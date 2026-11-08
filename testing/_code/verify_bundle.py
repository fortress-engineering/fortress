"""Offline public-bundle consumer. Standard library only; no Fortress imports.

Integrity and replay check the supplied record, not producer identity, execution,
semantic correctness, approval, or freshness against an unspecified repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

sys.dont_write_bytecode = True
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_ITEMS = 100_000
SAFE_INTEGER = 9007199254740991
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MEMBER = re.compile(r"(?:manifest|statement)\.json\Z|artifacts/[0-9a-f]{64}\.(?:json|bin)\Z")


class Invalid(ValueError):
    """Explicit non-favorable protocol failure."""
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def require(condition, code, detail):
    if not condition:
        raise Invalid(code, detail)


def closed(value, fields):
    require(isinstance(value, dict) and set(value) == set(fields.split()), "INVALID_RECORD", "unknown or missing public fields")


def edition(value, versions, field="schema_version"):
    """JSON booleans and floats cannot stand in for integer schema editions."""
    return isinstance(value, dict) and type(value.get(field)) is int and value[field] in versions


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def number(value):
    """ECMAScript decimal presentation of shortest round-trip finite binary64."""
    require(math.isfinite(value), "INVALID_JSON", "non-finite number")
    if value == 0:
        return "0"
    negative = value < 0
    source = repr(abs(value)).lower()
    coefficient, _, exponent = source.partition("e")
    exponent = int(exponent or "0")
    whole, _, fraction = coefficient.partition(".")
    digits = (whole + fraction).lstrip("0").rstrip("0") or "0"
    decimal = len(whole) + exponent
    if whole == "0":
        decimal = exponent - (len(fraction) - len(fraction.lstrip("0")))
    if 0 < decimal <= 21:
        result = digits[:decimal] + ("." + digits[decimal:] if decimal < len(digits) else "0" * (decimal - len(digits)))
    elif -6 < decimal <= 0:
        result = "0." + "0" * -decimal + digits
    else:
        exp = decimal - 1
        result = digits[0] + ("." + digits[1:] if len(digits) > 1 else "") + "e" + ("+" if exp >= 0 else "") + str(exp)
    return ("-" if negative else "") + result


def canonical(value):
    """RFC 8785 public bytes; unsafe integer tokens use decimal-string fields."""
    def emit(item, depth=0):
        require(depth <= 64, "RESOURCE_LIMIT", "JSON depth exceeds 64")
        if item is None:
            return "null"
        if isinstance(item, bool):
            return "true" if item else "false"
        if isinstance(item, int):
            require(abs(item) <= SAFE_INTEGER, "INVALID_JSON", "integer exceeds exact public range")
            return str(item)
        if isinstance(item, float):
            return number(item)
        if isinstance(item, str):
            require(not any(0xD800 <= ord(c) <= 0xDFFF for c in item), "INVALID_JSON", "lone Unicode surrogate")
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            require(len(item) <= MAX_ITEMS, "RESOURCE_LIMIT", "array exceeds admission")
            return "[" + ",".join(emit(x, depth + 1) for x in item) + "]"
        require(isinstance(item, dict) and len(item) <= MAX_ITEMS, "INVALID_JSON", "object expected")
        keys = sorted(item, key=lambda s: s.encode("utf-16-be"))
        return "{" + ",".join(emit(k, depth + 1) + ":" + emit(item[k], depth + 1) for k in keys) + "}"
    try:
        return emit(value).encode("utf-8")
    except (UnicodeError, RecursionError) as error:
        raise Invalid("INVALID_JSON", "invalid Unicode or nesting") from error


def parse(data):
    require(len(data) <= MAX_FILE, "RESOURCE_LIMIT", "member exceeds 32 MiB")
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "DUPLICATE_KEY", "duplicate JSON member")
            value[key] = item
        return value
    def constant(_):
        raise Invalid("INVALID_JSON", "non-finite JSON number")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        canonical(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, Invalid):
            raise
        raise Invalid("INVALID_JSON", "malformed UTF-8 JSON") from error


def hashed(value):
    return sha(canonical(value))


def ordered(values, key=lambda x: x):
    keys = [key(x) for x in values]
    require(keys == sorted(set(keys)), "NONCANONICAL_INVENTORY", "identities must be unique and sorted")


def checked_member(name):
    require(isinstance(name, str) and MEMBER.fullmatch(name), "UNSAFE_PATH", "unregistered or unsafe bundle member")
    return name


def no_links(path):
    require(not str(path).startswith(("\\\\", "//")), "UNSAFE_PATH", "network and device roots are not offline bundle inputs")
    absolute = Path(os.path.abspath(path))
    for candidate in [*reversed(absolute.parents), absolute]:
        info = candidate.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "UNSAFE_PATH", "symlink or reparse point")
    return absolute


def archive_names(path):
    require(path.stat().st_size <= MAX_TOTAL, "RESOURCE_LIMIT", "archive exceeds 128 MiB")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) <= 130, "RESOURCE_LIMIT", "archive inventory exceeds 130")
        names, expanded = [], 0
        for entry in entries:
            checked_member(entry.filename)
            mode = entry.external_attr >> 16
            require(not stat.S_ISLNK(mode) and (not stat.S_IFMT(mode) or stat.S_ISREG(mode)), "UNSAFE_PATH", "special archive member")
            require(not entry.flag_bits & 1, "UNSUPPORTED_ARCHIVE", "encrypted archive")
            require(entry.file_size <= MAX_FILE and entry.file_size <= max(1, entry.compress_size) * 1000,
                    "RESOURCE_LIMIT", "archive member expansion exceeds admission")
            expanded += entry.file_size
            require(expanded <= MAX_TOTAL, "RESOURCE_LIMIT", "archive expansion exceeds 128 MiB")
            names.append(entry.filename)
        require(len(names) == len(set(n.casefold() for n in names)), "DUPLICATE_IDENTITY", "duplicate archive member")
        return set(names)


class Reader:
    """Bounded direct reads or ZIP reads; never extract or execute members."""
    def __init__(self, path):
        self.path = no_links(path)
        self.archive = None
        self.total = 0
        self.loaded = set()
        if self.path.is_dir():
            names = []
            for child in self.path.iterdir():
                require(len(names) < 130, "RESOURCE_LIMIT", "too many bundle members")
                no_links(child)
                if child.name == "artifacts" and child.is_dir():
                    for leaf in child.iterdir():
                        require(len(names) < 130, "RESOURCE_LIMIT", "too many bundle members")
                        no_links(leaf)
                        require(leaf.is_file(), "UNSAFE_PATH", "non-file artifact")
                        names.append("artifacts/" + leaf.name)
                else:
                    require(child.is_file(), "UNSAFE_PATH", "unregistered directory")
                    names.append(child.name)
            self.names = set(names)
        else:
            self.names = archive_names(self.path)
            self.archive = zipfile.ZipFile(self.path)
        for name in self.names:
            checked_member(name)

    def close(self):
        if self.archive:
            self.archive.close()

    def read(self, member):
        checked_member(member)
        require(member in self.names, "MISSING_ARTIFACT", "required member missing: " + member)
        require(member not in self.loaded, "DUPLICATE_IDENTITY", "member referenced multiple times")
        self.loaded.add(member)
        if self.archive:
            with self.archive.open(member) as stream:
                data = stream.read(MAX_FILE + 1)
        else:
            path = no_links(self.path / PurePosixPath(member))
            before = path.stat()
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE, "RESOURCE_LIMIT", "invalid member size/type")
            with path.open("rb") as stream:
                require(os.fstat(stream.fileno()).st_ino == before.st_ino, "UNSAFE_PATH", "member changed during admission")
                data = stream.read(MAX_FILE + 1)
                after = os.fstat(stream.fileno())
            require(before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns,
                    "INTEGRITY_ERROR", "member changed during read")
        self.total += len(data)
        require(len(data) <= MAX_FILE and self.total <= MAX_TOTAL, "RESOURCE_LIMIT", "bundle bytes exceed admission")
        return data


def legacy_json(value):
    """Historical serde_json Value ordering, independent of new JCS identities."""
    if isinstance(value, dict):
        return {k: legacy_json(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [legacy_json(x) for x in value]
    return value


def graph_check(graph, certification, graph_bytes, binding):
    closed(graph, "$schema schema_version subject standard profile nodes root_obligations coverage provenance")
    require(graph["schema_version"] == 2 and graph["$schema"] == "urn:fortress:schema:v2:evidence-graph", "UNSUPPORTED_VERSION", "unsupported Evidence DAG edition")
    require(graph["subject"] == binding["subject_ref"], "BINDING_MISMATCH", "graph subject differs")
    if certification is not None:
        require(graph["subject"] == certification["subject"] and graph["profile"] == certification["profile"], "BINDING_MISMATCH", "certification binding differs")
        require(sha(graph_bytes) == certification["evidence_graph_digest"], "DIGEST_MISMATCH", "original graph bytes differ")
    nodes = graph["nodes"]
    ordered(nodes, lambda n: n["id"])
    by_id = {n["id"]: n for n in nodes}
    dependencies = {}
    semantic = set()
    for node in nodes:
        closed(node, "id kind subject result inputs producer producer_semantic_version evidence_class payload")
        require(node["evidence_class"] in ["AUTHORITY", "OBSERVATION", "STATIC_PROOF", "EXECUTED_TEST", "EXECUTED_SCENARIO", "TRUSTED_ASSERTION", "DEFEATER", "AGGREGATE"]
                and node["result"] in ["PASS", "FAIL", "UNSUPPORTED", "INVALID", "OBSERVED", "ASSERTED"], "UNSUPPORTED_VERSION", "unsupported evidence semantics")
        ordered(node["inputs"])
        pair = (node["kind"], node["subject"])
        require(pair not in semantic, "DUPLICATE_IDENTITY", "conflicting semantic node")
        semantic.add(pair)
        body = {k: legacy_json(node[k]) for k in ["kind", "subject", "result", "inputs", "producer", "producer_semantic_version", "evidence_class", "payload"]}
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        require(sha(encoded) == node["id"], "DIGEST_MISMATCH", "original Evidence DAG node differs")
        require(all(i in by_id for i in node["inputs"]), "MISSING_REFERENCE", "dangling Evidence DAG reference")
        dependencies[node["id"]] = node["inputs"]
    topological(dependencies)
    ordered(graph["root_obligations"])
    require(all(i in by_id for i in graph["root_obligations"]), "MISSING_REFERENCE", "missing graph root")
    counts = {k: sum(n["evidence_class"].lower() == k for n in nodes) for k in graph["coverage"]}
    require(counts == graph["coverage"], "INCONSISTENT_RESULT", "graph coverage differs")
    if certification is None:
        require(not graph["root_obligations"] and all(n["kind"] == "assessment_replay" and n["evidence_class"] == "OBSERVATION" for n in nodes),
                "INVALID_GRAPH", "application reporting cannot masquerade as implementation certification")
        return by_id
    require(edition(certification, [1]) and certification["certification_digest"] in graph["root_obligations"], "INVALID_CERTIFICATION", "certification root absent")
    root = by_id[certification["certification_digest"]]
    require(root["kind"] == "certification_root" and root["payload"]["certification_source_digest"] == binding["subject_ref"], "BINDING_MISMATCH", "root context differs")
    states = []
    obligation_ids=set()
    for obligation in certification["obligations"]:
        require(obligation["kind"] in ["STANDARD_RULE","FEATURE_REQUIREMENT","BEHAVIORAL_REALIZATION","BEHAVIORAL_VERIFICATION","ENVIRONMENTAL_VERIFICATION","ARTIFACT_FRESHNESS","ASSURANCE_EVIDENCE"],
                "UNSUPPORTED_VERSION","unsupported certification obligation")
        identity=(obligation["kind"],obligation["subject"])
        require(identity not in obligation_ids,"DUPLICATE_IDENTITY","duplicate certification obligation")
        obligation_ids.add(identity)
        require(obligation["evidence_refs"] and all(i in by_id for i in obligation["evidence_refs"]), "MISSING_REFERENCE", "certification support absent")
        require(obligation["status"] in ["INVALID", "FAIL", "STALE", "MISSING", "PASS"], "UNSUPPORTED_VERSION", "unknown certification status")
        states.append(obligation["status"])
    aggregate = next((s for s in ["INVALID", "FAIL", "STALE", "MISSING"] if s in states), "PASS")
    require(aggregate == certification["status"], "INCONSISTENT_RESULT", "certification status does not match obligations")
    result_for={"PASS":"PASS","FAIL":"FAIL","INVALID":"INVALID","STALE":"UNSUPPORTED","MISSING":"UNSUPPORTED"}
    require(root["result"] == result_for[aggregate],"INCONSISTENT_RESULT","certification root verdict differs")
    wrappers=[n for n in nodes if n["kind"].startswith("certification_obligation:")]
    require(sorted(hashed(n["payload"]) for n in wrappers) == sorted(hashed(o) for o in certification["obligations"]),
            "MISSING_REFERENCE","original certification obligations differ from the DAG")
    require(graph["root_obligations"] == sorted([root["id"],*[n["id"] for n in wrappers]])
            and {n["id"] for n in wrappers} <= set(root["inputs"]),"MISSING_REFERENCE","certification root support differs")
    require(all(n["result"] == result_for[n["payload"]["status"]] for n in wrappers),"INCONSISTENT_RESULT","obligation node verdict differs")
    return by_id


def topological(dependencies):
    parents = {key: [] for key in dependencies}
    counts = {key: len(refs) for key, refs in dependencies.items()}
    for key, refs in dependencies.items():
        for ref in refs:
            require(ref in parents, "MISSING_REFERENCE", "dangling dependency")
            parents[ref].append(key)
    ready = sorted(key for key, count in counts.items() if not count)
    order = []
    while ready:
        key = ready.pop()
        order.append(key)
        for parent in parents[key]:
            counts[parent] -= 1
            if not counts[parent]:
                ready.append(parent)
    require(len(order) == len(dependencies), "INVALID_GRAPH", "cyclic dependency graph")
    return order


def conjunction(values):
    values = list(values)
    return "F" if "F" in values else "U" if "U" in values else "T"


def proof_check(proof, known):
    require(edition(proof, [1]), "INVALID_PROOF", "unsupported proof edition")
    closed(proof, "schema_version root_node_id nodes")
    ordered(proof["nodes"], lambda n: n["node_id"])
    nodes = {n["node_id"]: n for n in proof["nodes"]}
    require(proof["root_node_id"] in nodes, "INVALID_PROOF", "missing proof root")
    for node in nodes.values():
        closed(node, "node_id operator required_refs children")
        ordered(node["required_refs"])
        ordered(node["children"])
        require(set(node["required_refs"]) <= known, "INVALID_PROOF", "unknown proof leaf")
        op = node["operator"]
        require(op in ["LEAF", "ALL", "ANY"], "INVALID_PROOF", "unknown proof operator")
        require((op != "LEAF" or not node["children"]) and (op != "ANY" or node["children"])
                and (op != "LEAF" or node["required_refs"]) and (node["required_refs"] or node["children"]),
                "INVALID_PROOF", "empty or unsupported proof expression")
    return nodes, topological({k: n["children"] for k, n in nodes.items()})


def proof_value(proof, nodes, order, states):
    values = {}
    for key in order:
        node = nodes[key]
        child = [values[c] for c in node["children"]]
        choice = ("T" if "T" in child else "U" if "U" in child else "F") if node["operator"] == "ANY" else conjunction(child)
        values[key] = conjunction([choice, *[states.get(r, "U") for r in node["required_refs"]]])
    return values[proof["root_node_id"]]


def assess_obligation(obligation, declaration, expected, evidence, policy, prepared=None):
    def result(state, blocker=None):
        return {"id": obligation["id"], "decision": state, "blockers": [blocker] if blocker else []}
    proof = obligation["proof"]
    if proof is None:
        return result("NOT_EVALUABLE", "REQUIRED_EVIDENCE_MISSING")
    try:
        nodes, order = proof_check(proof, prepared["known"] if prepared is not None else {e["id"] for e in evidence})
    except Invalid:
        return result("INVALID", "INVALID_PROOF")
    claims = prepared["claims"].get(obligation["scope_ref"], []) if prepared is not None else [c for c in declaration["claims"] if c["scope_ref"] == obligation["scope_ref"]]
    contradiction = any(c["truth"] == "SUPPORTED_VIOLATION" for c in claims)
    predicate = obligation["predicate"]
    require(predicate in ["RULE_CHECK", "CONFORMANCE", "EVALUABILITY", "SUCCESSFUL_EXECUTION"], "UNSUPPORTED_VERSION", "unsupported profile predicate")
    kind = "RULE_CHECK" if predicate == "RULE_CHECK" else "SEMANTIC_POLICY" if predicate in ["CONFORMANCE", "EVALUABILITY"] else None
    if kind and (not claims or any(c["kind"] != kind for c in claims)):
        return result("NOT_EVALUABLE", "INCOMPATIBLE_EVIDENCE")
    raw = (all(c["truth"] == "NO_SUPPORTED_VIOLATION" and (predicate != "RULE_CHECK" or c.get("semantic_claim") is None) for c in claims) and not contradiction
           if predicate in ["RULE_CHECK", "CONFORMANCE"] else all(c["truth"] in ["NO_SUPPORTED_VIOLATION", "SUPPORTED_VIOLATION"] for c in claims) if predicate == "EVALUABILITY" else True)
    if not raw and not contradiction:
        return result("NOT_EVALUABLE", "REQUIRED_EVIDENCE_MISSING")
    required = {r for n in nodes.values() for r in n["required_refs"]}
    states, rejection = {}, "REQUIRED_EVIDENCE_MISSING"
    admitted_candidates = [prepared["evidence"][key] for key in sorted(required) if key in prepared["evidence"]] if prepared is not None else evidence
    for leaf in admitted_candidates:
        if leaf["id"] not in required:
            continue
        proposition = leaf["proposition"]
        accepted = (proposition == ("SUPPORTED_VIOLATION" if contradiction else "NO_SUPPORTED_VIOLATION") if predicate in ["RULE_CHECK", "CONFORMANCE"]
                    else proposition in ["NO_SUPPORTED_VIOLATION", "SUPPORTED_VIOLATION"] if predicate == "EVALUABILITY"
                    else proposition in ["EXECUTION_SUCCEEDED", "EXECUTION_FAILED"])
        reason = None
        if leaf["binding"]["context_ref"] != expected["binding"]["context_ref"]:
            reason = "INCOMPATIBLE_CONTEXT"
        elif leaf["binding"] != expected["binding"]:
            reason = "STALE_EVIDENCE"
        elif leaf["scope_ref"] != obligation["scope_ref"]:
            reason = "INCOMPATIBLE_EVIDENCE"
        elif proposition == "UNAVAILABLE":
            reason = "REQUIRED_EVIDENCE_MISSING"
        elif leaf["evidence_class"] != obligation["evidence_class"] or not accepted or (predicate != "SUCCESSFUL_EXECUTION" and not any(leaf["source_ref"] in c["proof_refs"] for c in claims)):
            reason = "INCOMPATIBLE_EVIDENCE"
        elif policy["verified_payloads"].get(leaf["id"]) != leaf["payload_digest"]:
            reason = "UNTRUSTED_EVIDENCE"
        elif obligation["authenticated_producer_required"] and leaf["id"] not in policy["authenticated_evidence"]:
            reason = "PRODUCER_NOT_AUTHENTICATED"
        elif not set(leaf["assumptions"]) <= set(policy["accepted_assumptions"]):
            reason = "ASSUMPTION_NOT_ACCEPTED"
        elif leaf["valid_until"] is not None and (policy["assessment_time"] is None or policy["assessment_time"] > leaf["valid_until"]):
            reason = "EVIDENCE_EXPIRED_OR_TIME_MISSING"
        elif policy["verified_metadata"].get(leaf["id"]) != hashed(leaf):
            reason = "UNTRUSTED_EVIDENCE"
        if reason:
            rejection = reason
        else:
            states[leaf["id"]] = "F" if proposition == "EXECUTION_FAILED" else "T"
    state = proof_value(proof, nodes, order, states)
    if state == "F":
        return result("NOT_SATISFIED", "EXECUTION_FAILED")
    if state == "U":
        return result("NOT_EVALUABLE", rejection)
    return result("NOT_SATISFIED", "SUPPORTED_VIOLATION") if predicate in ["RULE_CHECK", "CONFORMANCE"] and contradiction else result("SATISFIED")


def replay_check(declaration, assessment, replay):
    require(edition(replay, [1]), "UNSUPPORTED_VERSION", "unsupported replay edition")
    expected, evidence, policy = replay["expected"], replay["evidence"], replay["acceptance"]
    for claim in declaration["claims"]:
        require(claim["truth"] in ["SUPPORTED_VIOLATION", "NO_SUPPORTED_VIOLATION", "NOT_EVALUABLE", "NOT_APPLICABLE", "AUTHORIZATION"]
                and claim["kind"] in ["RULE_CHECK", "SEMANTIC_POLICY"], "UNSUPPORTED_VERSION", "unsupported claim semantics")
    ordered(expected["obligations"], lambda o: o["id"])
    ordered(evidence, lambda e: e["id"])
    require(expected["binding"] == declaration["binding"] == assessment["binding"], "BINDING_MISMATCH", "replay binding differs")
    require(expected["profile_digest"] == assessment["profile_digest"] and hashed(expected["obligations"]) == assessment["obligation_manifest_digest"], "BINDING_MISMATCH", "profile or obligation manifest differs")
    require(hashed(policy) == assessment["acceptance_policy_digest"], "DIGEST_MISMATCH", "acceptance policy differs")
    require(hashed(declaration) == assessment["declaration_digest"], "DIGEST_MISMATCH", "declaration differs")
    if assessment["schema_version"] == 2:
        inputs = replay.get("evidence_inputs")
        selected = [] if inputs is None else inputs["selected"]
        require(inputs is None or inputs["binding"] == expected["binding"], "BINDING_MISMATCH", "provider input binding differs")
        require(hashed(["provider-evidence-input-set-v1", expected["binding"], selected]) == assessment["evidence_input_digest"], "DIGEST_MISMATCH", "provider input set differs")
    mismatch = expected["artifacts"] != declaration["proof_manifest"] or expected["dimensions"] != declaration["required_dimension_manifest"]
    claims_by_scope = {}
    for claim in declaration["claims"]:
        claims_by_scope.setdefault(claim["scope_ref"], []).append(claim)
    prepared = {"known": {e["id"] for e in evidence}, "evidence": {e["id"]: e for e in evidence}, "claims": claims_by_scope}
    outcomes = ([{"id": o["id"], "decision": "INVALID", "blockers": ["TRUSTED_MANIFEST_MISMATCH"]} for o in expected["obligations"]] if mismatch
                else [assess_obligation(o, declaration, expected, evidence, policy, prepared) for o in expected["obligations"]])
    decision = next((s for s in ["INVALID", "NOT_SATISFIED", "NOT_EVALUABLE"] if any(o["decision"] == s for o in outcomes)), "INVALID" if mismatch else "SATISFIED")
    require(outcomes == assessment["obligations"] and decision == assessment["decision"] and assessment["blockers"] == (["TRUSTED_MANIFEST_MISMATCH"] if mismatch else []),
            "INCONSISTENT_RESULT", "independent profile replay disagrees")
    return decision


def authority_check(authority, replay, declaration, assessment):
    """Validate public authority definitions and the retained binding preimage."""
    preimage = replay["authority_preimage"]
    context_bytes = replay["program_context_utf8"].encode()
    context = parse(context_bytes)
    require(edition(context, [1], "version") and sha(context_bytes) == declaration["binding"]["context_ref"], "BINDING_MISMATCH", "original ProgramContext differs")
    require(len(preimage) == 7 and preimage[0] == "application-authority-v1" and hashed(preimage) == declaration["binding"]["authority_ref"],
            "BINDING_MISMATCH", "authority preimage differs")
    governance = authority["finding_governance_utf8"]
    require((governance is None and preimage[6] is None) or (isinstance(governance,str) and sha(governance.encode()) == preimage[6]),
            "BINDING_MISMATCH", "original finding governance differs")
    external = {"external-verification:" + identity for identity in authority["external_requirements"]}
    require(external == {o["id"] for o in replay["expected"]["obligations"] if o["id"].startswith("external-verification:")},
            "MISSING_REFERENCE", "required external obligation manifest differs")
    layout_bytes = authority["control_layout_utf8"].encode()
    policy_bytes = authority["assessment_policy_utf8"].encode()
    require(sha(layout_bytes) == preimage[1] and sha(policy_bytes) == preimage[2], "DIGEST_MISMATCH", "layout/policy authority differs")
    layout, policy = parse(layout_bytes), parse(policy_bytes)
    require(edition(layout, [5]) and edition(policy, [1]) and policy["id"] == "application-assessment-policy"
            and policy["version"] == "1.0.0", "UNSUPPORTED_VERSION", "unsupported authority semantics")
    manifest_bytes = authority["manifest_utf8"].encode()
    manifest = parse(manifest_bytes)
    require(edition(manifest, [1]) and manifest["$schema"] == "urn:fortress:schema:v1:standard-manifest",
            "UNSUPPORTED_VERSION","unsupported Standard manifest")
    rules = sorted(authority["rules"], key=lambda r: r["path"])
    require(len(rules) == len({r["path"] for r in rules}), "DUPLICATE_IDENTITY", "duplicate authority asset path")
    require(sorted(manifest["rules"]) == [r["path"] for r in rules], "MISSING_REFERENCE", "Standard rule inventory differs")
    digest = hashlib.sha256()
    for data in [b"standard_manifest", manifest_bytes, *[part for r in rules for part in [r["path"].encode(), r["utf8"].encode()]]]:
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    require("sha256:" + digest.hexdigest() == authority["standard_digest"] == preimage[3], "DIGEST_MISMATCH", "Standard authority differs")
    catalog = parse(authority["profile_catalog_utf8"].encode())
    require(edition(catalog, [1]), "UNSUPPORTED_VERSION", "unsupported profile definitions")
    profiles = {}
    body_keys = ["id", "version", "kind", "layout_id", "active_rules", "semantic_scopes", "required_evidence", "conflicts"]
    for profile in catalog["profiles"]:
        key = (profile["id"], profile["version"])
        require(key not in profiles and hashed({k: profile[k] for k in body_keys}) == profile["digest"], "DIGEST_MISMATCH", "profile definition differs")
        profiles[key] = profile
    references = []
    associations = [[None, p] for p in authority["selected_profiles"]]
    associations.extend([module, p] for module in sorted(authority["module_profiles"]) for p in authority["module_profiles"][module])
    require(associations == preimage[4], "BINDING_MISMATCH", "scoped profile authority differs")
    for module, reference in associations:
        profile = profiles.get((reference["id"], reference["version"]))
        require(profile is not None and reference["digest"] == profile["digest"], "BINDING_MISMATCH", "selected profile digest differs")
        references.append({"module": module, **reference})
    references.sort(key=lambda p: (p["module"] is not None, p["module"] or "", p["id"], p["version"], p["digest"]))
    require(references == declaration["required_dimension_manifest"]["profiles"], "BINDING_MISMATCH", "declaration profile selection differs")
    require(replay["profile_override_modules"] == sorted(authority["module_profiles"]), "BINDING_MISMATCH", "override scopes differ")
    composite = ["application-assessment-policy-v1", preimage[2], replay["profile_layout_id"], references, replay["profile_override_modules"]]
    require(hashed(composite) == assessment["profile_digest"], "BINDING_MISMATCH", "profile composition digest differs")




# Independent public provider-v1 replay. Reused from the qualified standard-library
# reference consumer; no Rust producer, analyzer or project code is imported.
"""Independent bounded XML reference consumer; no Fortress producer imports.

Standard-library parser deliberately shares no code with the Rust adapter.
Its normalized facts must be compared with retained envelope observations.
Parsing does not authenticate a manifest, execute code, or establish completeness.
"""
import io
import json
import math
import re
import xml.etree.ElementTree as ET
_provider_xml_MAX_BYTES = 32 * 1024 * 1024
_provider_xml_MAX_NORMALIZED = 64 * 1024 * 1024
_provider_xml_MAX_ROWS = 100000
_provider_xml_MAX_EXACT = 2 ** 53 - 1

def _provider_xml_require(value, message):
    if not value:
        raise ValueError(message)

def _provider_xml_unique_json(payload):
    _provider_xml_require(len(payload) <= _provider_xml_MAX_BYTES, 'payload byte bound')
    depth = tokens = 0
    quoted = escaped = False
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            _provider_xml_require(depth <= 64, 'JSON depth bound')
        elif byte in (93, 125):
            depth -= 1
        elif byte in (44, 58):
            tokens += 1
            _provider_xml_require(tokens <= 1000000, 'JSON token bound')

    def pairs(items):
        result = {}
        for key, value in items:
            _provider_xml_require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def integer(value):
        parsed = int(value)
        _provider_xml_require(abs(parsed) <= _provider_xml_MAX_EXACT, 'inexact public integer')
        return parsed

    def constant(_):
        raise ValueError('nonfinite number')

    def floating(value):
        parsed = float(value)
        _provider_xml_require(math.isfinite(parsed), 'nonfinite number')
        return parsed
    value = json.loads(payload.decode('utf-8'), object_pairs_hook=pairs, parse_int=integer, parse_float=floating, parse_constant=constant)
    json.dumps(value, ensure_ascii=False).encode('utf-8')
    return value

def _provider_xml_parse_junit(payload, inventory):
    """Independent XML facts; companion inventory only resolves package ambiguity."""
    _provider_xml_require(len(payload) <= _provider_xml_MAX_BYTES, 'payload byte bound')
    source = payload.decode('utf-8')
    _provider_xml_require(not re.search('<!\\s*(?:DOCTYPE|ENTITY)\\b', source, re.I), 'DTD/entity forbidden')
    _provider_xml_require(all((c in '\t\n\r' or 32 <= ord(c) <= 55295 or 57344 <= ord(c) <= 65533 or (65536 <= ord(c) <= 1114111) for c in source)), 'XML1.0 character')
    declaration = re.match('\\ufeff?<\\?xml\\s+([^?]+)\\?>', source)
    if declaration:
        text = declaration[1]
        _provider_xml_require(re.search('version\\s*=\\s*[\\\'"]1\\.0[\\\'"]', text), 'XML version')
        encoding = re.search('encoding\\s*=\\s*[\\\'"]([^\\\'"]+)[\\\'"]', text)
        _provider_xml_require(not encoding or encoding[1].lower() == 'utf-8', 'XML encoding')
    _provider_xml_require(len(inventory) <= _provider_xml_MAX_ROWS, 'inventory count bound')
    _provider_xml_require(sum((sum((len((item['key'][name] or '').encode('utf-8')) for name in ('package', 'target', 'qualified_name'))) + 128 for item in inventory)) <= _provider_xml_MAX_NORMALIZED, 'inventory normalized bound')
    packages = {}
    for item in inventory:
        native = item['key']
        partial = (native['target'], native['qualified_name'])
        candidate = native['package']
        if partial not in packages:
            packages[partial] = candidate
        elif packages[partial] != candidate:
            packages[partial] = None
    stack, suites, rows, limits = ([], [], {}, set())
    pending = None
    root_seen = False
    charge = events = 0
    for event, elem in ET.iterparse(io.BytesIO(payload), events=('start', 'end', 'pi', 'start-ns')):
        events += 1
        _provider_xml_require(events <= 1000000, 'XML event bound')
        if event == 'start-ns':
            raise ValueError('XML namespace declaration unsupported')
        if event == 'pi':
            limits.add('JUNIT_PROCESSING_INSTRUCTION_UNINTERPRETED')
            continue
        tag = elem.tag
        _provider_xml_require(type(tag) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]*', tag), 'XML namespace')
        if event == 'start':
            _provider_xml_require(len(stack) < 64 and len(elem.attrib) <= 256, 'XML depth/attribute bound')
            _provider_xml_require(all((re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]*', k) and k != 'xmlns' and (len(v.encode('utf-8')) <= 65536) for k, v in elem.attrib.items())), 'XML attribute')
            attrs = elem.attrib
            if not stack:
                _provider_xml_require(not root_seen and tag in ('testsuite', 'testsuites'), 'JUnit root')
                root_seen = True
            if tag in ('testsuite', 'testsuites'):
                _provider_xml_require(pending is None and (not stack or stack[-1] in ('testsuite', 'testsuites')), 'suite location')
                _provider_xml_require(tag != 'testsuites' or not stack, 'nested testsuites')
                expected = {}
                for name in ('tests', 'failures', 'errors', 'skipped'):
                    if name in attrs:
                        _provider_xml_require(re.fullmatch('[0-9]+', attrs[name]), 'suite count')
                        expected[name] = int(attrs[name])
                        _provider_xml_require(expected[name] <= _provider_xml_MAX_EXACT, 'suite count bound')
                if attrs.get('disabled') not in (None, '0'):
                    limits.add('JUNIT_DISABLED_MEMBERS')
                suites.append(dict(tag=tag, name=attrs.get('name') or None, package=attrs.get('package'), expected=expected, counts=dict.fromkeys(('tests', 'failures', 'errors', 'skipped'), 0)))
                if tag == 'testsuite' and (not attrs.get('name')):
                    limits.add('JUNIT_SUITE_TARGET_UNSPECIFIED')
            elif tag == 'testcase':
                _provider_xml_require(stack and stack[-1] == 'testsuite' and (pending is None) and (len(rows) < _provider_xml_MAX_ROWS), 'case location/count')
                _provider_xml_require(bool(attrs.get('name')), 'native case name')
                name = attrs['name']
                if attrs.get('classname'):
                    name = attrs['classname'] + '::' + name
                _provider_xml_require(len(name.encode('utf-8')) <= 65536, 'native name bound')
                suite = suites[-1]
                package = suite['package'] or packages.get((suite['name'], name))
                if not package:
                    limits.add('JUNIT_PACKAGE_UNRESOLVED')
                native = (package, suite['name'], name)
                charge += sum((len((x or '').encode('utf-8')) for x in native)) + 256
                _provider_xml_require(charge <= _provider_xml_MAX_NORMALIZED, 'normalized output budget')
                _provider_xml_require(native not in rows, 'duplicate/retried native case')
                outcome = 'PASSED'
                if attrs.get('status') in ('notrun', 'skipped'):
                    outcome = 'SKIPPED'
                elif 'status' in attrs and attrs['status'] not in ('run', 'completed'):
                    outcome = 'UNKNOWN'
                    limits.add('JUNIT_STATUS_UNINTERPRETED')
                retry_metadata = any((word in k.lower() for k in attrs for word in ('retry', 'flaky', 'rerun')))
                if retry_metadata:
                    limits.add('JUNIT_RETRY_METADATA')
                pending = dict(key=native, outcome=outcome, terminal=set(), retry_metadata_present=retry_metadata, unknown=False)
            elif tag in ('failure', 'error', 'skipped'):
                if not stack or stack[-1] != 'testcase' or pending is None:
                    limits.add('JUNIT_NONCASE_TERMINAL_STATE')
                else:
                    _provider_xml_require(not pending['terminal'], 'duplicate/conflicting terminal state')
                    pending['terminal'].add(tag)
            elif tag not in ('system-out', 'system-err', 'properties', 'property'):
                limits.add('JUNIT_UNINTERPRETED_ELEMENT')
                if pending:
                    pending['unknown'] = True
                if pending and any((x in tag.lower() for x in ('retry', 'flaky', 'rerun'))):
                    pending['retry_metadata_present'] = True
            stack.append(tag)
        else:
            _provider_xml_require(stack and stack.pop() == tag, 'XML closure')
            if tag == 'testcase':
                terminal = pending['terminal']
                if 'failure' in terminal or 'error' in terminal:
                    pending['outcome'] = 'FAILED'
                elif 'skipped' in terminal:
                    pending['outcome'] = 'SKIPPED'
                if pending['outcome'] == 'SKIPPED' and ('failure' in terminal or 'error' in terminal):
                    limits.add('JUNIT_CONFLICTING_TERMINAL_STATES')
                if pending['outcome'] == 'PASSED' and pending['unknown']:
                    pending['outcome'] = 'UNKNOWN'
                for suite in suites:
                    suite['counts']['tests'] += 1
                    suite['counts']['failures'] += 'failure' in terminal
                    suite['counts']['errors'] += 'error' in terminal
                    suite['counts']['skipped'] += pending['outcome'] == 'SKIPPED' or 'skipped' in terminal
                rows[pending['key']] = dict(outcome=pending['outcome'], retry_metadata_present=pending['retry_metadata_present'])
                pending = None
            elif tag in ('testsuite', 'testsuites'):
                suite = suites.pop()
                for name, count in suite['expected'].items():
                    if count != suite['counts'][name]:
                        limits.add('JUNIT_DECLARED_COUNT_MISMATCH:' + name)
            elem.clear()
    _provider_xml_require(root_seen and (not stack) and (not suites) and (pending is None), 'complete XML syntax')
    return (rows, sorted(limits))

"""Independent SARIF2.1 subset reference; standard JSON parser, no Fortress imports.

Expected fixtures come from SARIF run/invocation/rule/result semantics. Tool
execution success, inventory completeness and findings are separate propositions.
"""
import unicodedata
_provider_sarif_SCOPE = 'run:0/invocation:0'

def _provider_sarif_text(value):
    _provider_xml_require(type(value) is str and 0 < len(value.encode('utf-8')) <= 65536 and (not any((unicodedata.category(c) == 'Cc' for c in value))), 'SARIF text')
    return value

def _provider_sarif_sequence(value, limit=_provider_xml_MAX_ROWS):
    _provider_xml_require(type(value) is list and len(value) <= limit, 'SARIF sequence bound')
    return value

def _provider_sarif_boolean(value):
    _provider_xml_require(value is None or type(value) is bool, 'SARIF boolean')
    return value

def _provider_sarif_parse(payload, manifest):
    document = _provider_xml_unique_json(payload)
    _provider_xml_require(type(document) is dict and document.get('version') == '2.1.0', 'SARIF version')
    runs = _provider_sarif_sequence(document.get('runs'), 1)
    if not runs:
        _provider_xml_require(manifest is None, 'unavailable declared run')
        return ([], ['SARIF_RUN_UNAVAILABLE'], dict(succeeded=None, exit_code=None), None, None)
    run = runs[0]
    _provider_xml_require(type(run) is dict, 'SARIF run')
    tool = run['tool']
    driver = tool['driver']
    name = _provider_sarif_text(driver['name'])
    version = driver.get('semanticVersion')
    if version is None:
        version = driver.get('version')
    if version is not None:
        _provider_sarif_text(version)
    limitations = set()
    if version is None:
        limitations.add('SARIF_TOOL_VERSION_UNAVAILABLE')
    if run.get('externalPropertyFileReferences'):
        limitations.add('SARIF_EXTERNAL_PROPERTIES_UNRESOLVED')
    if tool.get('extensions'):
        limitations.add('SARIF_TOOL_EXTENSIONS_UNINTERPRETED')
    invocations = run.get('invocations')
    invocation = _provider_sarif_sequence(invocations, 1)[0] if invocations else None
    outcome = dict(succeeded=None, exit_code=None)
    if invocation is None:
        limitations.add('SARIF_INVOCATION_SCOPE_UNRESOLVED')
    else:
        _provider_xml_require(type(invocation) is dict, 'SARIF invocation')
        outcome['succeeded'] = _provider_sarif_boolean(invocation.get('executionSuccessful'))
        code = invocation.get('exitCode')
        _provider_xml_require(code is None or (type(code) is int and -2 ** 31 <= code < 2 ** 31), 'SARIF exit code')
        outcome['exit_code'] = code
        for category in ('toolExecutionNotifications', 'toolConfigurationNotifications'):
            for notice in _provider_sarif_sequence(invocation.get(category) or []):
                _provider_xml_require(type(notice) is dict, 'SARIF notification')
                if notice.get('level') == 'error':
                    outcome['succeeded'] = False
        if invocation.get('ruleConfigurationOverrides'):
            limitations.add('SARIF_RULE_OVERRIDES_UNINTERPRETED')
    if outcome['succeeded'] is None:
        limitations.add('SARIF_INVOCATION_STATUS_UNAVAILABLE')
    rules = driver.get('rules')
    if rules is None:
        limitations.add('SARIF_RULE_CATALOG_UNAVAILABLE')
        rules = []
    rules = _provider_sarif_sequence(rules)
    names = []
    known = set()
    for rule in rules:
        rule_id = _provider_sarif_text(rule['id'])
        _provider_xml_require(rule_id not in known, 'duplicate SARIF rule')
        names.append(rule_id)
        known.add(rule_id)
        configuration = rule.get('defaultConfiguration') or {}
        if _provider_sarif_boolean(configuration.get('enabled')) is False or configuration.get('level') == 'none':
            limitations.add('SARIF_DISABLED_RULE')
    results = run.get('results')
    if results is None:
        limitations.add('SARIF_RESULTS_UNAVAILABLE')
        results = []
    results = _provider_sarif_sequence(results)
    facts = {}
    guids = set()
    for result in results:
        _provider_xml_require(type(result) is dict, 'SARIF result')
        guid = result.get('guid')
        if guid is not None:
            _provider_sarif_text(guid)
            _provider_xml_require(guid not in guids, 'duplicate SARIF result GUID')
            guids.add(guid)
        reference = result.get('rule') or {}
        if reference.get('toolComponent'):
            limitations.add('SARIF_EXTERNAL_RULE_COMPONENT_UNINTERPRETED')
            continue
        rule_id = result.get('ruleId')
        index = result.get('ruleIndex')
        if reference.get('id') is not None:
            _provider_xml_require(rule_id is None or rule_id == reference['id'], 'SARIF rule reference conflict')
            rule_id = reference['id']
        if reference.get('index') is not None:
            _provider_xml_require(index is None or index == reference['index'], 'SARIF index reference conflict')
            index = reference['index']
        if index is not None:
            _provider_xml_require(type(index) is int and 0 <= index < len(names), 'SARIF rule index')
            _provider_xml_require(rule_id is None or rule_id == names[index], 'SARIF rule ID/index conflict')
            rule_id = names[index]
        if rule_id is None:
            limitations.add('SARIF_RESULT_RULE_UNRESOLVED')
            continue
        _provider_sarif_text(rule_id)
        if driver.get('rules') is not None and rule_id not in known:
            limitations.add('SARIF_RESULT_RULE_UNREGISTERED')
        fact = facts.setdefault(rule_id, dict(failures=0, unknown=False, not_applicable=False))
        if result.get('suppressions'):
            _provider_sarif_sequence(result['suppressions'])
            limitations.add('SARIF_SUPPRESSED_RESULTS')
            fact['unknown'] = True
        if result.get('baselineState') == 'absent':
            limitations.add('SARIF_NONCURRENT_BASELINE_RESULT')
            fact['unknown'] = True
            continue
        kind = result.get('kind')
        kind = 'fail' if kind is None else kind
        if kind == 'fail':
            fact['failures'] += 1
        elif kind == 'notApplicable':
            fact['not_applicable'] = True
        elif kind != 'pass':
            fact['unknown'] = True
            limitations.add('SARIF_RESULT_REQUIRES_INTERPRETATION')
    complete = outcome['succeeded'] is True and run.get('results') is not None and (not limitations)
    observations = []
    charge = 0
    if manifest is not None:
        _provider_xml_require(manifest['invocation_scope'] == _provider_sarif_SCOPE and manifest['provider'] == name, 'SARIF selected scope')
        _provider_xml_require(version is None or manifest['provider_version'] == version, 'SARIF producer version')
        inventory = _provider_sarif_sequence(manifest['inventory'])
        for member in inventory:
            key = member['key']
            _provider_xml_require(key['namespace'] == 'NATIVE_QUALIFIED' and key['package'] == name and (key['target'] == _provider_sarif_SCOPE), 'SARIF native scope')
            rule = key['qualified_name']
            _provider_xml_require(driver.get('rules') is None or rule in known, 'unregistered SARIF inventory')
            fact = facts.get(rule, {})
            count = fact.get('failures', 0)
            result = 'FAILED' if count else 'UNKNOWN' if fact.get('unknown') else 'NOT_APPLICABLE' if fact.get('not_applicable') else 'PASSED' if complete else 'UNKNOWN'
            observations.append(dict(key=key.copy(), outcome=result, attempts=None, retry_metadata_present=False, finding_count=count if run.get('results') is not None else None))
        if version is None:
            version = manifest['provider_version']
    else:
        for rule, fact in sorted(facts.items()):
            if fact['failures']:
                observations.append(dict(key=dict(namespace='NATIVE_QUALIFIED', package=name, target=_provider_sarif_SCOPE if invocation is not None else None, qualified_name=rule), outcome='FAILED', attempts=None, retry_metadata_present=False, finding_count=fact['failures']))
    for observation in observations:
        charge += 256 + sum((len((value or '').encode('utf-8')) for value in observation['key'].values()))
        _provider_xml_require(charge <= _provider_xml_MAX_NORMALIZED, 'normalized SARIF output budget')
    return (observations, sorted(limitations), outcome, name, version)

"""Independent retained-provider replay and conservative requirement assessment.

No Fortress producer or evaluator is imported. Raw XML/JSON is parsed with the
Python standard library. The caller supplies trusted expected bindings, selected
requirements and current execution descriptors. This consumer cannot receive a
fresh capability through serialized reporting and never authenticates a name.
"""
import hashlib
import json
import re
_provider_reference_DIGEST = re.compile('sha256:[0-9a-f]{64}\\Z')
_provider_reference_UNKNOWN = dict(succeeded=None, exit_code=None)

def _provider_reference_canonical(value):

    def check(value):
        if type(value) is dict:
            _provider_xml_require(all((type(k) is str and k.isascii() for k in value)), 'closed DTO keys')
            for child in value.values():
                check(child)
        elif type(value) is list:
            for child in value:
                check(child)
        elif type(value) is int:
            _provider_xml_require(abs(value) <= 2 ** 53 - 1, 'exact public integer')
        else:
            _provider_xml_require(value is None or type(value) in (str, bool), 'closed DTO value')
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')

def _provider_reference_digest(payload):
    return 'sha256:' + hashlib.sha256(payload).hexdigest()

def _provider_reference_shape(value, fields):
    _provider_xml_require(type(value) is dict and set(value) == set(fields.split()), 'closed record shape')

def _provider_reference_execution(value):
    _provider_reference_shape(value, 'binary_digest tool_digest arguments working_directory inputs environment_dependencies dependencies_complete')
    for field in ('binary_digest', 'tool_digest'):
        _provider_xml_require(value[field] is None or (type(value[field]) is str and _provider_reference_DIGEST.fullmatch(value[field])), 'execution identity')
    _provider_xml_require(value['arguments'] is None or (type(value['arguments']) is list and len(value['arguments']) <= _provider_xml_MAX_ROWS and all((type(a) is str for a in value['arguments']))), 'argv')
    _provider_xml_require(value['working_directory'] in (None, 'SUBJECT_ROOT'), 'execution directory')
    _provider_xml_require(type(value['dependencies_complete']) is bool, 'execution closure status')
    if value['dependencies_complete']:
        _provider_xml_require(all((value[f] is not None for f in ('binary_digest', 'tool_digest', 'arguments', 'working_directory'))), 'incomplete descriptor claiming closure')
    for field in ('inputs', 'environment_dependencies'):
        entries = value[field]
        _provider_xml_require(type(entries) is list and len(entries) <= _provider_xml_MAX_ROWS, 'execution dependency bound')
        names = []
        for entry in entries:
            _provider_reference_shape(entry, 'name digest')
            _provider_xml_require(type(entry['name']) is str and entry['name'], 'execution dependency name')
            _provider_xml_require(type(entry['digest']) is str and _provider_reference_DIGEST.fullmatch(entry['digest']), 'execution dependency identity')
            names.append(entry['name'])
        _provider_xml_require(names == sorted(set(names)), 'execution dependency ambiguity')

def _provider_reference_check_invocation(value):
    _provider_reference_shape(value, 'succeeded exit_code')
    _provider_xml_require(value['succeeded'] is None or type(value['succeeded']) is bool, 'process success')
    _provider_xml_require(value['exit_code'] is None or (type(value['exit_code']) is int and -2 ** 31 <= value['exit_code'] < 2 ** 31), 'process exit')

def _provider_reference_key(value):
    _provider_reference_shape(value, 'namespace package target qualified_name')
    _provider_xml_require(value['namespace'] in ('NATIVE_QUALIFIED', 'GOVERNED_TEST_ID'), 'identity namespace')
    _provider_xml_require(type(value['qualified_name']) is str and value['qualified_name'], 'qualified name')
    for field in ('package', 'target'):
        _provider_xml_require(value[field] is None or (type(value[field]) is str and value[field]), 'native qualifier')
    if value['namespace'] == 'GOVERNED_TEST_ID':
        _provider_xml_require(value['package'] is None and value['target'] is None and value['qualified_name'].startswith('T-'), 'governed namespace')
    return tuple((value[name] for name in ('namespace', 'package', 'target', 'qualified_name')))

def _provider_reference_order(identity):
    ns, package, target, name = identity
    return (0 if ns == 'NATIVE_QUALIFIED' else 1, package is not None, package or '', target is not None, target or '', name)

def _provider_reference_ordered(values, identity):
    keys = [identity(value) for value in values]
    _provider_xml_require(keys == sorted(set(keys), key=_provider_reference_order), 'duplicate/unordered native records')
    return keys

def _provider_reference_verify(envelope, raw):
    _provider_reference_shape(envelope, '$schema schema_version normalizer_semantic_version format provider provider_version media_type payload_digest run_manifest observations invocation invocation_basis limitations authenticity')
    _provider_xml_require(envelope['$schema'] == 'urn:fortress:derived:v1:provider-evidence' and type(envelope['schema_version']) is int and (envelope['schema_version'] == 1), 'provider edition')
    _provider_xml_require(envelope['normalizer_semantic_version'] == '1.0.0' and envelope['authenticity'] == 'UNVERIFIED', 'normalizer/authenticity')
    _provider_xml_require(len(raw) <= _provider_xml_MAX_BYTES and envelope['payload_digest'] == _provider_reference_digest(raw), 'raw payload binding')
    _provider_xml_require(type(envelope['observations']) is list and len(envelope['observations']) <= _provider_xml_MAX_ROWS, 'row bound')
    observed = _provider_reference_ordered(envelope['observations'], lambda row: _provider_reference_key(row['key']))
    _provider_reference_check_invocation(envelope['invocation'])
    manifest = envelope['run_manifest']
    inventory = []
    attempts = {}
    if manifest is not None:
        _provider_reference_shape(manifest, 'binding provider provider_version invocation_scope execution inventory inventory_complete filters filtering_known attempts_complete attempts invocation payload_digest assumptions')
        for field in ('provider', 'provider_version', 'payload_digest'):
            _provider_xml_require(manifest[field] == envelope[field], 'manifest metadata binding')
        _provider_reference_shape(manifest['binding'], 'subject_ref context_ref authority_ref')
        _provider_reference_execution(manifest['execution'])
        _provider_reference_check_invocation(manifest['invocation'])
        for field in ('inventory_complete', 'filtering_known', 'attempts_complete'):
            _provider_xml_require(type(manifest[field]) is bool, 'manifest completeness flag')
        _provider_xml_require(type(manifest['filters']) is list and all((type(v) is str for v in manifest['filters'])), 'manifest filters')
        _provider_xml_require(type(manifest['assumptions']) is list and manifest['assumptions'] == sorted(set(manifest['assumptions'])), 'manifest assumptions')
        _provider_xml_require(all((type(v) is str and _provider_reference_DIGEST.fullmatch(v) for v in manifest['binding'].values())), 'manifest binding')
        inventory = manifest['inventory']
        _provider_xml_require(type(inventory) is list and len(inventory) <= _provider_xml_MAX_ROWS, 'inventory bound')
        inventory_keys = _provider_reference_ordered(inventory, lambda row: _provider_reference_key(row['key']))
        for member in inventory:
            _provider_reference_shape(member, 'key enabled')
            _provider_xml_require(type(member['enabled']) is bool, 'inventory eligibility')
        inventory_set = set(inventory_keys)
        attempt_keys = _provider_reference_ordered(manifest['attempts'], lambda row: _provider_reference_key(row['key']))
        for row in manifest['attempts']:
            count = row['count']
            _provider_xml_require(type(count) is int and 0 <= count <= 2 ** 53 - 1, 'exact attempt count')
            _provider_xml_require(_provider_reference_key(row['key']) in inventory_set, 'attempt outside inventory')
            attempts[_provider_reference_key(row['key'])] = count
        if manifest['attempts_complete']:
            _provider_xml_require(attempt_keys == inventory_keys, 'attempt accounting')
    kind = envelope['format']
    limits = []
    invocation = _provider_reference_UNKNOWN.copy()
    provider = envelope['provider']
    version = envelope['provider_version']
    basis = 'UNKNOWN'
    if kind == 'JUNIT_XML':
        _provider_xml_require(envelope['media_type'] == 'application/xml', 'media type')
        native, limits = _provider_xml_parse_junit(raw, inventory)
        rows = [dict(key=dict(namespace='NATIVE_QUALIFIED', package=k[0], target=k[1], qualified_name=k[2]), outcome=v['outcome'], attempts=None, retry_metadata_present=v['retry_metadata_present'], finding_count=None) for k, v in native.items()]
        if manifest is not None:
            invocation = manifest['invocation']
            basis = 'COMPANION_MANIFEST'
    elif kind == 'SARIF210':
        _provider_xml_require(envelope['media_type'] == 'application/sarif+json', 'media type')
        rows, limits, invocation, provider, version = _provider_sarif_parse(raw, manifest)
        basis = 'UNKNOWN' if invocation == _provider_reference_UNKNOWN else 'PAYLOAD'
    elif kind == 'CARGO_SUITE':
        _provider_xml_require(envelope['media_type'] == 'application/vnd.fortress.cargo-suite+json', 'media type')
        suite = _provider_xml_unique_json(raw)
        _provider_xml_require(manifest is not None, 'controlled Cargo manifest')
        complete = suite['passed'] is True and suite['canonical_unfiltered'] is True
        rows = []
        for enabled, ids in ((True, suite['eligible_test_ids']), (False, suite['ignored_test_ids'])):
            for test in ids:
                rows.append(dict(key=dict(namespace='GOVERNED_TEST_ID', package=None, target=None, qualified_name=test), outcome=('PASSED' if enabled else 'SKIPPED') if complete else 'UNKNOWN', attempts=None, retry_metadata_present=False, finding_count=None))
        invocation = dict(succeeded=suite['passed'], exit_code=None)
        basis = 'PAYLOAD'
        provider = suite['executor']
        version = suite['executor_version']
    else:
        raise ValueError('unsupported format')
    for row in rows:
        count = attempts.get(_provider_reference_key(row['key']))
        row['attempts'] = None if row['retry_metadata_present'] and count is not None and (count <= 1) else count
    rows.sort(key=lambda row: _provider_reference_order(_provider_reference_key(row['key'])))
    _provider_xml_require(_provider_reference_canonical(rows) == _provider_reference_canonical(envelope['observations']), 'raw payload does not reproduce normalized rows')
    _provider_xml_require(sorted(limits) == envelope['limitations'], 'raw payload limitation mismatch')
    _provider_xml_require(invocation == envelope['invocation'] and basis == envelope['invocation_basis'], 'raw invocation mismatch')
    _provider_xml_require(provider == envelope['provider'] and version == envelope['provider_version'], 'raw producer mismatch')
    if manifest is not None and invocation['succeeded'] is not None and (manifest['invocation']['succeeded'] is not None):
        _provider_xml_require(invocation['succeeded'] is manifest['invocation']['succeeded'], 'raw/companion invocation conflict')
    accounted = manifest is not None and bool(inventory) and (manifest['inventory_complete'] is True) and (manifest['filtering_known'] is True) and (not manifest['filters']) and (not limits) and (_provider_reference_ordered(inventory, lambda row: _provider_reference_key(row['key'])) == observed) and all((member['enabled'] is True and row['outcome'] in ('PASSED', 'FAILED') and (row['attempts'] == 1) and (not row['retry_metadata_present']) for member, row in zip(inventory, rows)))
    return (rows, accounted)

def _provider_reference_resolve(envelope, raw, expected, requirement, host):
    rows, accounted = _provider_reference_verify(envelope, raw)
    manifest = envelope['run_manifest']
    identity = _provider_reference_digest(_provider_reference_canonical(envelope))
    if envelope['format'] == 'SARIF210' or manifest is None:
        return 'NOT_EVALUABLE'
    if manifest['binding'] != expected or manifest['provider'] != requirement['provider'] or manifest['invocation_scope'] != requirement['invocation_scope']:
        return 'NOT_EVALUABLE'
    if identity not in host.get('admitted_envelopes', []):
        return 'NOT_EVALUABLE'
    if requirement['authenticated_producer_required']:
        return 'NOT_EVALUABLE'
    if any((a not in host.get('accepted_assumptions', []) for a in manifest['assumptions'])):
        return 'NOT_EVALUABLE'
    descriptor = manifest['execution']
    current = host.get('current_executions', {}).get(identity)
    if current is not None:
        _provider_reference_execution(current)
    if descriptor.get('dependencies_complete') is not True or current != descriptor:
        return 'NOT_EVALUABLE'
    if any((descriptor.get(field) is None for field in ('binary_digest', 'tool_digest', 'arguments', 'working_directory'))):
        return 'NOT_EVALUABLE'
    if manifest['inventory_complete'] is not True or not manifest['inventory']:
        return 'NOT_EVALUABLE'
    selected = []
    for selector in requirement['selectors']:
        matches = [member['key'] for member in manifest['inventory'] if member['key']['namespace'] == selector['namespace'] and member['key']['qualified_name'] == selector['qualified_name'] and all((selector[field] is None or member['key'][field] == selector[field] for field in ('package', 'target')))]
        if len(matches) != 1 or _provider_reference_key(matches[0]) in selected:
            return 'NOT_EVALUABLE'
        selected.append(_provider_reference_key(matches[0]))
    if not selected:
        return 'NOT_EVALUABLE'
    by_key = {_provider_reference_key(row['key']): row for row in rows}
    values = [True if accounted else None, envelope['invocation']['succeeded']]
    for identity in selected:
        row = by_key.get(identity)
        if row is None or row['attempts'] != 1 or row['retry_metadata_present'] or (row['outcome'] not in ('PASSED', 'FAILED')):
            values.append(None)
        else:
            values.append(row['outcome'] == 'PASSED')
    return 'NOT_SATISFIED' if False in values else 'SATISFIED' if all((v is True for v in values)) else 'NOT_EVALUABLE'

def provider_check(artifacts, raw, replay, graph):
    """Verify original provider reports and their normalized public facts."""
    envelopes = {}
    inputs = replay.get("evidence_inputs")
    if inputs is not None:
        require(inputs["binding"] == replay["expected"]["binding"], "BINDING_MISMATCH", "provider input context differs")
        ordered(inputs["selected"], lambda s: (s["envelope_digest"], s["payload_digest"], s["inventory_digest"] or ""))
        for selected in inputs["selected"]:
            role = "provider-envelope:" + selected["envelope_digest"]
            payload = "provider-payload:" + selected["payload_digest"]
            if role in artifacts and payload in raw:
                envelope = artifacts[role]
                require(hashed(envelope) == selected["envelope_digest"] and sha(raw[payload]) == selected["payload_digest"] == envelope["payload_digest"],
                        "DIGEST_MISMATCH", "selected provider report identity differs")
                rows, accounted = _provider_reference_verify(envelope, raw[payload])
                require(selected["inventory_digest"] == (hashed(envelope["run_manifest"]["inventory"]) if envelope["run_manifest"] else None),
                        "BINDING_MISMATCH", "selected provider inventory differs")
                envelopes[selected["envelope_digest"]] = (envelope, rows, accounted)
    if graph:
        for node in graph["nodes"]:
            if node["kind"] == "controlled_cargo_provider_envelope":
                envelope = node["payload"]["envelope"]
                record = canonical(node["payload"]["raw_execution_record"])
                rows, accounted = _provider_reference_verify(envelope, record)
                require(envelope["run_manifest"]["binding"] == replay["expected"]["binding"], "BINDING_MISMATCH", "controlled execution context differs")
                envelopes[hashed(envelope)] = (envelope, rows, accounted)
    return envelopes


def payload_check(declaration, replay, providers):
    """Reproduce static metadata/payload bindings, never Rust semantic analysis."""
    unresolved = []
    claims = {}
    for claim in declaration["claims"]:
        claims.setdefault(claim["scope_ref"], []).append(claim)
    provider_facts = {}
    for identity, (envelope, rows, accounted) in providers.items():
        manifest = envelope["run_manifest"]
        if not manifest:
            continue
        facts = {"inventory": "EXECUTION_SUCCEEDED" if accounted else "UNAVAILABLE",
                 "invocation": "EXECUTION_SUCCEEDED" if envelope["invocation"]["succeeded"] is True else "EXECUTION_FAILED" if envelope["invocation"]["succeeded"] is False else "UNAVAILABLE"}
        for row in rows:
            facts["member:" + hashed(row["key"])] = ("EXECUTION_SUCCEEDED" if row["outcome"] == "PASSED" else "EXECUTION_FAILED" if row["outcome"] == "FAILED" else "UNAVAILABLE") if row["attempts"] == 1 and not row["retry_metadata_present"] else "UNAVAILABLE"
        assumptions = sorted({"provider-assumption:" + hashed([identity, a]) for a in manifest["assumptions"]})
        for fact, proposition in facts.items():
            reference = "provider-premise:" + hashed([identity, fact])
            provider_facts[(envelope["payload_digest"], reference)] = (manifest["binding"], proposition, assumptions)
    for leaf in replay["evidence"]:
        require(DIGEST.fullmatch(leaf["payload_digest"]), "INVALID_IDENTITY", "invalid leaf payload digest")
        matching = [claim for claim in claims.get(leaf["scope_ref"], []) if leaf["source_ref"] in claim["proof_refs"]]
        if leaf["evidence_class"] in ["STATIC_PROOF", "OBSERVATION"] and matching:
            require(any(hashed(["static-claim-premise-v1", leaf["binding"], hashed(claim), leaf["source_ref"]]) == leaf["payload_digest"] for claim in matching),
                    "DIGEST_MISMATCH", "static premise payload differs")
            require(leaf["id"] == "assessment-leaf:" + hashed([leaf["scope_ref"], leaf["source_ref"]]), "INVALID_IDENTITY", "scoped static leaf identity differs")
        elif leaf["proposition"] != "UNAVAILABLE" or leaf["id"].startswith("provider-leaf:"):
            fact = provider_facts.get((leaf["payload_digest"], leaf["source_ref"]))
            if fact is None:
                unresolved.append("payload bytes or normalized premise not retained for " + leaf["id"])
            else:
                binding, proposition, assumptions = fact
                require(leaf["binding"] == binding and leaf["id"] == "provider-leaf:" + hashed([binding, leaf["scope_ref"], leaf["source_ref"]])
                        and proposition == leaf["proposition"] and leaf["assumptions"] == assumptions,
                        "INCONSISTENT_PROVIDER", "provider fact, scope, assumptions or proposition differs")
    return unresolved


def verify(path, predicate_type, expected_binding=None, expected_profile=None):
    authority = predicate_type.removeprefix("https://").split("/",1)[0]
    require(predicate_type.startswith("https://") and predicate_type.endswith("/v1") and predicate_type.isascii()
            and len(predicate_type) <= 2048 and authority and "@" not in authority and not any(c.isspace() for c in predicate_type),
            "UNSUPPORTED_VERSION", "expected owner predicate must be a bounded explicit HTTPS v1 URI without credentials")
    reader = Reader(path)
    try:
        manifest_bytes = reader.read("manifest.json")
        manifest = parse(manifest_bytes)
        require(isinstance(manifest,dict) and manifest.get("$schema") == "urn:fortress:schema:v1:portable-bundle" and type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1,
                "UNSUPPORTED_VERSION", "unsupported bundle edition")
        closed(manifest, "$schema schema_version binding generation_ref declaration_digest assessment_digest profile_digest certification_result_availability artifacts authority_assets required_nodes required_payloads optional_projection_refs materialization_dependencies unavailable projection_losses")
        require(canonical(manifest) == manifest_bytes, "NONCANONICAL_JSON", "manifest is not JCS")
        statement_bytes = reader.read("statement.json")
        statement = parse(statement_bytes)
        binding = manifest["binding"]
        require(set(binding) == {"subject_ref", "context_ref", "authority_ref"} and all(DIGEST.fullmatch(v) for v in binding.values()), "INVALID_IDENTITY", "invalid exact binding")
        require(statement["_type"] == "https://in-toto.io/Statement/v1" and statement["predicateType"] == predicate_type, "UNSUPPORTED_VERSION", "unsupported statement or predicate")
        require(statement["subject"] == [{"name": "fortress-source", "digest": {"sha256": binding["subject_ref"][7:]}}], "BINDING_MISMATCH", "statement subject differs")
        predicate = statement["predicate"]
        closed(predicate,"schema_version manifest_digest binding profile_digest authenticity")
        require(edition(predicate, [1]) and predicate["manifest_digest"] == sha(manifest_bytes) and predicate["binding"] == binding
                and predicate["profile_digest"] == manifest["profile_digest"] and predicate["authenticity"] == "UNVERIFIED", "BINDING_MISMATCH", "predicate differs")
        require(canonical(statement) == statement_bytes, "NONCANONICAL_JSON", "statement is not JCS")
        artifacts, raw = {}, {}
        ordered(manifest["artifacts"], lambda a: a["id"])
        require(len(manifest["artifacts"]) <= 128, "RESOURCE_LIMIT", "too many artifacts")
        for artifact in manifest["artifacts"]:
            closed(artifact, "id member wire_digest jcs_digest media_type byte_count schema required")
            require(artifact["required"] is True, "UNSUPPORTED_VERSION", "optional artifact descriptor not supported")
            data = reader.read(artifact["member"])
            require(artifact["byte_count"] == len(data) and artifact["wire_digest"] == sha(data), "DIGEST_MISMATCH", "artifact bytes differ")
            binary = artifact["id"].startswith("provider-payload:")
            extension = "bin" if binary else "json"
            require(artifact["member"] == "artifacts/" + sha(data)[7:] + "." + extension, "INVALID_IDENTITY", "artifact media locator differs")
            if binary:
                require(artifact["jcs_digest"] is None and artifact["media_type"] == "application/octet-stream" and artifact["schema"] == "urn:fortress:portable:v1:raw-provider-payload",
                        "UNSUPPORTED_VERSION", "binary report representation differs")
                value = None
            else:
                value = parse(data)
                require(artifact["media_type"] == "application/json" and hashed(value) == artifact["jcs_digest"], "DIGEST_MISMATCH", "artifact JCS identity differs")
                require(artifact["schema"] == value.get("$schema", "urn:fortress:portable:v1:retained-input"), "BINDING_MISMATCH", "artifact schema differs")
            artifacts[artifact["id"]], raw[artifact["id"]] = value, data
        require(reader.loaded == reader.names, "UNREGISTERED_ARTIFACT", "bundle contains unreferenced members")
        require(manifest["authority_assets"] == (["authority-assets"] if "authority-assets" in artifacts else []), "MISSING_REFERENCE", "required authority inventory differs")
        require(all(r in artifacts for r in ["conformance-declaration", "profile-assessment"]), "MISSING_ARTIFACT", "declaration/assessment required")
        declaration, assessment = artifacts["conformance-declaration"], artifacts["profile-assessment"]
        if manifest["generation_ref"] is not None:
            require("control-generation" in artifacts and hashed(artifacts["control-generation"]) == manifest["generation_ref"], "DIGEST_MISMATCH", "original CONTROL generation differs")
            control = artifacts["control-generation"]
            require(edition(control, [1, 2, 3, 4, 5]), "UNSUPPORTED_VERSION", "unsupported CONTROL generation edition")
            require(control["$schema"] == "urn:fortress:derived:v" + str(control["schema_version"]) + ":assessment-generation-manifest", "UNSUPPORTED_VERSION", "CONTROL schema differs")
            original = {a["id"]: a for a in control["artifacts"]}
            for role in ["conformance-declaration", "profile-assessment", "evidence-graph", "certification", "quality-certificate", "verified-bfg"]:
                if role in artifacts:
                    require(role in original and sha(raw[role]) == original[role]["content_digest"] and len(raw[role]) == original[role]["byte_count"], "BINDING_MISMATCH", "CONTROL member differs")
        require(edition(declaration, [1]) and declaration["$schema"] == "urn:fortress:derived:v1:conformance-declaration"
                and edition(assessment, [1, 2]) and assessment["$schema"] == "urn:fortress:derived:v" + str(assessment["schema_version"]) + ":profile-assessment", "UNSUPPORTED_VERSION", "unsupported declaration or assessment")
        require(binding == declaration["binding"] == assessment["binding"], "BINDING_MISMATCH", "artifact binding differs")
        require(hashed(declaration) == manifest["declaration_digest"] == assessment["declaration_digest"] and hashed(assessment) == manifest["assessment_digest"], "DIGEST_MISMATCH", "declaration or assessment identity differs")
        require(manifest["profile_digest"] == assessment["profile_digest"], "BINDING_MISMATCH", "assessment profile differs")
        require(manifest["optional_projection_refs"] == declaration["proof_manifest"], "MISSING_REFERENCE", "projection manifest differs")
        omitted = {a["id"]: a for a in declaration["proof_manifest"] if a["id"] not in artifacts}
        if "control-generation" in artifacts:
            for artifact in artifacts["control-generation"]["artifacts"]:
                if artifact["id"] in artifacts:
                    continue
                product = {k: artifact[k] for k in ["id", "content_digest", "byte_count"]}
                require(product["id"] not in omitted or omitted[product["id"]] == product, "BINDING_MISMATCH", "materialization identities conflict")
                omitted[product["id"]] = product
        require([omitted[k] for k in sorted(omitted)] == manifest["materialization_dependencies"], "MISSING_REFERENCE", "omitted product requirements differ")
        unavailable = list(manifest["unavailable"])
        ordered(unavailable)
        certification_availability = manifest["certification_result_availability"]
        require(certification_availability in ["INCLUDED", "NOT_APPLICABLE_APPLICATION", "UNAVAILABLE"], "UNSUPPORTED_VERSION", "unsupported certification availability")
        if certification_availability == "INCLUDED":
            require("certification" in artifacts, "MISSING_ARTIFACT", "required certification missing")
        elif certification_availability == "NOT_APPLICABLE_APPLICATION":
            require((("control-generation" in artifacts and artifacts["control-generation"]["generation_kind"] == "APPLICATION") or
                    ("state-view" in artifacts and artifacts["state-view"]["$schema"] == "urn:fortress:derived:v3:state-view")) and "certification" not in artifacts,
                    "BINDING_MISMATCH", "application reporting scope differs")
        else:
            unavailable.append("implementation certification unavailable")
        if "evidence-graph" in artifacts:
            by_id = graph_check(artifacts["evidence-graph"], artifacts.get("certification"), raw["evidence-graph"], binding)
            require(sorted(by_id) == manifest["required_nodes"], "MISSING_REFERENCE", "required node inventory differs")
            replays = [n for n in by_id.values() if n["kind"] == "assessment_replay"]
            if replays:
                require(len(replays) == 1, "DUPLICATE_IDENTITY", "multiple replay observations")
                for role, key in [("assessment-replay", "replay"), ("authority-assets", "authority"), ("audit", "audit")]:
                    require(role in artifacts and artifacts[role] == replays[0]["payload"][key], "MISSING_REFERENCE", "replay observation binding differs")
            if "state-view" in artifacts:
                view = artifacts["state-view"]
                require(view["schema_version"] == 3 and view["source_ref"] == binding["subject_ref"]
                        and view["portable_evidence_graph"] == artifacts["evidence-graph"]
                        and view["application"]["declaration"] == declaration and view["application"]["assessment"] == assessment,
                        "BINDING_MISMATCH", "captured endpoint differs from portable products")
        else:
            unavailable.append("Evidence DAG unavailable")
        replayed = "UNAVAILABLE"
        if "assessment-replay" in artifacts:
            replay = artifacts["assessment-replay"]
            require(manifest["required_payloads"] == {e["id"]: e["payload_digest"] for e in replay["evidence"]}, "MISSING_REFERENCE", "leaf inventory differs")
            replayed = replay_check(declaration, assessment, replay)
            providers = provider_check(artifacts, raw, replay, artifacts.get("evidence-graph"))
            unavailable.extend(payload_check(declaration, replay, providers))
            unavailable.extend("required evidence unavailable for " + leaf["id"] for leaf in replay["evidence"] if leaf["proposition"] == "UNAVAILABLE")
            if replay.get("evidence_inputs"):
                for selected in replay["evidence_inputs"]["selected"]:
                    for role, identity in [("provider-envelope",selected["envelope_digest"]),("provider-payload",selected["payload_digest"])]:
                        if role + ":" + identity not in raw:
                            unavailable.append("required " + role + ":" + identity)
        else:
            unavailable.append("original assessment replay inputs unavailable")
        if "authority-assets" not in artifacts:
            unavailable.append("original authority assets unavailable")
        elif "assessment-replay" in artifacts:
            authority_check(artifacts["authority-assets"], artifacts["assessment-replay"], declaration, assessment)
        freshness = "UNKNOWN"
        if expected_binding or expected_profile:
            supplied = expected_binding or {}
            mismatch = any(binding.get(k) != v for k, v in supplied.items()) or bool(expected_profile and expected_profile != manifest["profile_digest"])
            freshness = "STALE" if mismatch else "MATCHES_SUPPLIED_REFERENCES" if set(supplied) == set(binding) and expected_profile else "PARTIAL_REFERENCE_MATCH"
        return {"schema_version": 1, "integrity": "INCOMPLETE" if unavailable else "VERIFIED", "authenticity": "UNVERIFIED",
                "assessment_replay": replayed, "assurance": "UNVERIFIED", "freshness": freshness,
                "binding": binding, "profile_digest": manifest["profile_digest"], "manifest_digest": sha(manifest_bytes),
                "verification_scope": "PUBLIC_BYTES_REFERENCES_AND_DECLARED_PROOF_ALGEBRA",
                "certification_result_availability": certification_availability,
                "materialization_dependencies": manifest["materialization_dependencies"],
                "unavailable": sorted(set(unavailable)), "limitations": manifest["projection_losses"],
                "unproven": ["PRODUCER_IDENTITY", "ACTUAL_EXECUTION", "SEMANTIC_CORRECTNESS", "EXTERNAL_AUTHORIZATION", "LEAF_TRUST_ADMISSION", "AUTHORED_MANIFEST_DERIVATION"],
                "errors": []}
    finally:
        reader.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle")
    parser.add_argument("--predicate-type", required=True)
    for part in ["subject", "context", "authority", "profile"]:
        parser.add_argument("--expected-" + part)
    parser.add_argument("--current-state", help="Explicit independently supplied StateView reference; never captured implicitly")
    args = parser.parse_args(argv)
    try:
        binding = {part + "_ref": getattr(args, "expected_" + part) for part in ["subject", "context", "authority"] if getattr(args, "expected_" + part)}
        profile = args.expected_profile
        reference = None
        require(not args.current_state or not (binding or profile), "INVALID_PARAMETERS", "current-state and explicit expected references are exclusive")
        if args.current_state:
            path = no_links(args.current_state)
            with path.open("rb") as stream:
                view = parse(stream.read(MAX_FILE + 1))
            require(type(view["schema_version"]) is int and view["schema_version"] in [1, 2, 3]
                    and view["$schema"] == "urn:fortress:derived:v" + str(view["schema_version"]) + ":state-view", "UNSUPPORTED_VERSION", "unsupported reference endpoint")
            reference = hashed(view)
            binding = {"subject_ref": view["source_ref"]}
            if view.get("application") is not None:
                app = view["application"]
                require(app["declaration"]["binding"] == app["assessment"]["binding"]
                        and app["declaration"]["binding"]["subject_ref"] == view["source_ref"], "BINDING_MISMATCH", "reference endpoint differs")
                binding = app["declaration"]["binding"]
                profile = app["assessment"]["profile_digest"]
        require(all(isinstance(v,str) and DIGEST.fullmatch(v) for v in binding.values()) and (profile is None or DIGEST.fullmatch(profile)),
                "INVALID_PARAMETERS", "invalid independently supplied identity")
        result = verify(args.bundle, args.predicate_type, binding, profile)
        if reference is not None:
            result["reference_state_digest"] = reference
        code = 0 if result["integrity"] == "VERIFIED" and result["freshness"] != "STALE" else 1
    except (Invalid, OSError, KeyError, TypeError, AttributeError, ValueError, zipfile.BadZipFile, RuntimeError, OverflowError, RecursionError) as error:
        result = {"schema_version": 1, "integrity": "INVALID", "assurance": "UNVERIFIED", "authenticity": "UNVERIFIED", "freshness": "UNKNOWN",
                  "errors": [{"code": getattr(error, "code", "INVALID_BUNDLE"), "message": str(error)[:1024]}]}
        code = 2
    print(canonical(result).decode())
    return code


if __name__ == "__main__":
    raise SystemExit(main())
