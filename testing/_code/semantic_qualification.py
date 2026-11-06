#!/usr/bin/env python3
"""Test-owned independent scoring of a preregistered automated semantic envelope.

No candidate conclusion constructs an expected answer. Every completed initial
observation is durably retained before a mismatch can fail qualification. Replays
consume already exposed holdouts; they are never new human or population evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unittest

MAX_BYTES = 64 * 1024 * 1024
SCOPE = "rust-primitive-effects-automated-v1"
ROOT_ID = "PF-SEMANTIC-QUALIFICATION"
OWNER = "AF-SAMPLE-0001"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def jcs(value: object) -> bytes:
    # This closed protocol has ASCII member keys and exact unsigned integer
    # counts; arbitrary floating-point and Unicode-key canonicalization is not
    # delegated to this restricted encoder.
    def check(value):
        if type(value) is dict:
            if any(type(k) is not str or not k.isascii() for k in value):
                raise ValueError("qualification DTO member keys must be ASCII")
            for child in value.values(): check(child)
        elif type(value) is list:
            for child in value: check(child)
        elif type(value) is int:
            if not 0<=value<=2**53-1: raise ValueError("qualification integer outside exact range")
        elif value is not None and type(value) not in (str,bool):
            raise ValueError("qualification DTO has unsupported values")
    check(value)
    return canonical(value)[:-1]


def bundle(root:Path,paths:list[str])->str:
    if paths!=sorted(set(paths)):
        raise ValueError("qualification dependency paths are not sorted and unique")
    return digest(jcs([dict(path=p,digest=digest((root/p).read_bytes())) for p in paths]))


def exclusive(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


RETAINED_MEMBERS={"candidate_inputs.json","preregistered_cases.json","binding_premises.json",
    "reference_inputs.json","reference_outputs.jsonl","observations.jsonl","scored_outcomes.json","manifest.json","validation_inputs.json"}


def retained_directory(root:Path,destination:Path)->None:
    """Validate the external reservation delivered by the active OPS owner."""
    root=root.resolve(strict=True)
    destination=destination.absolute()
    if destination.is_relative_to(root) or not re.fullmatch('[0-9a-f]{64}',destination.name):
        raise ValueError("raw qualification observations require external owned retention")
    current=destination
    for _ in range(64):
        metadata=current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or getattr(metadata,'st_file_attributes',0)&0x400:
            raise ValueError("qualification retention ancestor is not a plain directory")
        if current.parent==current: break
        current=current.parent
    else: raise ValueError("qualification retention path depth exceeds bound")
    owner=load(destination/"owner.json")
    if set(owner)!={"namespace","repository","root_identity","run_nonce","category","maximum_bytes"} or (
        owner["namespace"]!="python-retained-evidence-v1" or owner["repository"]!=str(root)
        or owner["root_identity"]!=hashlib.sha256(os.fsencode(root)).hexdigest()
        or owner["category"]!="semantic-qualification-v1" or type(owner["maximum_bytes"]) is not int
        or owner["maximum_bytes"]!=80*1024*1024):
        raise ValueError("retention reservation does not match independently supplied repository scope")
    if {p.name for p in destination.iterdir()}!={"owner.json"}:
        raise ValueError("retained observation preimage already exists; never overwrite an earlier run")


def load(path: Path) -> object:
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise ValueError("qualification input exceeds 64 MiB")
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError("duplicate qualification JSON member")
            result[key]=value
        return result
    return json.loads(data,object_pairs_hook=unique)


def contract(identifier: str) -> dict:
    return {"$schema": "urn:fortress:schema:v2:module-contract", "schema_version": 2,
            "id": identifier, "display_name": identifier, "provides": [], "requires": [],
            "relationships": [], "constraints": [], "guarantees": [], "features": [], "behavior": []}


def contract_text(value:dict)->str:
    """Render the existing Module Contract wire order, without changing intent."""
    fields=["$schema","schema_version","id","display_name","ecosystem","provides","requires",
            "relationships","constraints","guarantees","features","behavior","semantic_policy"]
    if set(value)-set(fields):
        raise ValueError("unexpected qualification wrapper contract member")
    return json.dumps({key:value[key] for key in fields if key in value},ensure_ascii=False,indent=2)+"\n"


def native_case(case: dict) -> dict:
    root = contract(ROOT_ID)
    root["ecosystem"] = {"repository_grammar": 1, "standard": {"id": "STD-FORTRESS-ENGINEERING", "edition": "1.0.0-draft.1"}}
    owner = contract(OWNER)
    if case["disposition"] != "UNDECLARED":
        owner.update({"$schema": "urn:fortress:schema:v3:module-contract", "schema_version": 3,
                      "semantic_policy": {"default": "UNDECLARED", "capabilities": {"allow": [], "deny": []},
                                          "effects": {"allow": [case["effect"]] if case["disposition"] == "ALLOW" else [],
                                                      "deny": [case["effect"]] if case["disposition"] == "DENY" else []}}})
    logical = "repository" in case
    source_path = case.get("path", "sample/_code/lib.rs") if case.get("source") is not None else None
    contract_path = "_data/logical_modules/sample/contract.json" if logical else "sample/contract.json"
    files = {"contract.json": contract_text(root), contract_path: contract_text(owner)}
    if source_path is not None:
        source = case["source"]
        if digest(source.encode()).removeprefix("sha256:") != case["source_sha256"]:
            raise ValueError("frozen source digest differs: " + case["case_id"])
        files[source_path] = source
        lib_path = "../../" + source_path if logical else "../_code/lib.rs"
        files["sample/_data/Cargo.toml"] = "[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath=" + repr(lib_path) + "\n"
    for row in case.get("data_files", []):
        if hashlib.sha256(row["bytes"].encode()).hexdigest() != row["sha256"]:
            raise ValueError("frozen data digest differs")
        files[row["path"]] = row["bytes"]
    if logical:
        files["__fortress/.fsconfig"] = canonical({"$schema": "urn:fortress:schema:v3:project-configuration", "schema_version": 3,
            "observation_exclusions": [".git"], "logical_modules": [{"module": OWNER, "contract": contract_path,
            "parent": ROOT_ID, "bindings": [{"kind": "file", "path": source_path}]}]}).decode()
    return {"case_id": case["case_id"], "files": files, "source_path": source_path, "logical": logical,
            "context_selected": case["provenance"] != "UNKNOWN_CONFIGURATION", "test_context": case["provenance"] == "TEST_ONLY",
            "primitive_source": "sha256:"+case["source_sha256"] if case.get("opcodes") is not None else None,
            "target": "sample/library:sample"}


def corpus(data: Path) -> list[dict]:
    protocol=load(data / "semantic_qualification_protocol.json")
    for frozen in protocol["freeze_files"]:
        if hashlib.sha256((data/frozen["path"]).read_bytes()).hexdigest()!=frozen["sha256"]:
            raise ValueError("pre-evaluation fixture freeze changed: "+frozen["path"])
    synthetic = load(data / "synthetic_scopes_freeze.json")
    na = load(data / "na_scopes_addendum.json")
    public = load(data / "public_scopes_freeze.json")
    cases = synthetic["cases"] + na["cases"]
    for original in public["cases"]:
        row = dict(original)
        row.update(source=original["content"], source_sha256=hashlib.sha256(original["content"].encode()).hexdigest(),
                   effect=original["policy"]["effect"], disposition=original["policy"]["disposition"],
                   provenance="PRODUCTION", expected_reporting=[original["expected"]],
                   expected_blocking=None, required_supported_control=original["required"],
                   holdout="PUBLIC_SOURCE_REFERENCE", stratum="PUBLIC_FILE_SCOPE")
        cases.append(row)
    ids = [c["case_id"] for c in cases]
    if len(ids) != 86 or len(ids) != len(set(ids)):
        raise ValueError("preregistered corpus denominator changed")
    return sorted(cases, key=lambda c: c["case_id"])


def local_inputs(root:Path,cases:list[dict],executable:Path,cli:Path)->dict[str,str]:
    def paths(prefix):
        return sorted(p.relative_to(root).as_posix() for p in (root/prefix).rglob('*') if p.is_file())
    analyzer=sorted(p for owner in ["program_semantics","semantic_analysis","state_effect_analysis","architecture_evaluation","implementation_observation"]
        for p in paths("engine/"+owner+"/_code"))
    registry=paths("engine/standard_registry/_data")
    catalog=sorted(paths("engine/state_effect_analysis/_data") + paths("__fortress/governance/effect_summaries"))
    profiles=sorted(p for p in registry if "profile" in p or "cert_full_snapshot" in p)+["__fortress/.fsconfig","testing/_data/primitive_profile_inputs.json"]
    schemas=load(root/"engine/standard_registry/_data/schema_manifest.json")["schemas"]
    scope=load(root/"testing/_data/supported_scope_manifest.json")
    return dict(analyzer=bundle(root,analyzer),registry=bundle(root,registry),catalog=bundle(root,catalog),
        profiles=bundle(root,sorted(profiles)),schemas=bundle(root,sorted(schemas)),
        protocol=digest((root/"testing/_data/semantic_qualification_protocol.json").read_bytes()),
        corpus=bundle(root,sorted("testing/_data/"+p for p in ["synthetic_scopes_freeze.json","na_scopes_addendum.json","public_scopes_freeze.json","source_mutation_relations.json"])),
        contexts=digest(jcs([native_case(c) for c in cases])),
        oracle=bundle(root,["testing/_data/semantic_oracle_provenance.json","testing/semantic_oracle/_code/oracle.rs"]),
        heldout_selection=digest(jcs([dict(case_id=c["case_id"],holdout=c["holdout"]) for c in cases])),
        supported_scope=digest(jcs(scope)),
        harness=digest(jcs(dict(native_executable=digest(executable.read_bytes()),scorer=digest(Path(__file__).read_bytes()),
            harness_controls=digest(Path(__file__).with_name("qualification_controls.py").read_bytes())))),
        staged_cli=digest(cli.read_bytes()))


def manifest(evaluated:dict,inputs:dict[str,str],cases:list[dict])->dict:
    scored=evaluated["scored"]
    counts=Counter(c["raw_observed"] for c in scored if c["status"]=="COMPLETED")
    required=[c for c in scored if c.get("required")]
    matches=[c for c in required if c["match"]]
    mutations=evaluated["mutation_results"]
    return {"$schema":"urn:fortress:derived:v1:semantic-qualification","schema_version":1,
        "scope_id":SCOPE,"status":"PASS" if evaluated.get("native_exit_code")==0 and len(scored)==len(cases) and all(c["match"] for c in scored) and all(e["match"] for e in mutations) else "FAIL",
        "inputs":{"identities":dict(inputs,outcomes=digest(canonical(evaluated)))},
        "counts":dict(declared_cases=len(cases),completed_cases=sum(c["status"]=="COMPLETED" for c in scored),
            required_cases=len(required),required_passed=len(matches),mismatches=sum(not c["match"] for c in scored),
            positive=counts["SUPPORTED_VIOLATION"],negative=counts["NO_SUPPORTED_VIOLATION"],unknown=counts["NOT_EVALUABLE"],
            conditional_negative=sum(c.get("raw_observed")=="NO_SUPPORTED_VIOLATION" and bool(c.get("assumption_refs")) for c in scored),
            not_applicable=counts["NOT_APPLICABLE"],invalid=counts["INVALID_DIAGNOSTIC"],authorization=counts["AUTHORIZATION"],
            execution_failures=sum(counts[k] for k in ["DRIVER_FAILURE","WRONG_CLAIM_UNIVERSE"]),
            undeclared=counts["NO_DECLARED_CLAIM"],distinct_source_sites=evaluated["distinct_source_sites"],
            claims=evaluated["claims"],causal_paths=evaluated["causal_paths"],declared_mutations=len(mutations),
            exercised_mutations=sum(e["match"] for e in mutations),equal_differentials=evaluated["equal_differentials"],
            equal_metadata_controls=evaluated["equal_metadata_controls"],invalid_port_equivalences=evaluated["invalid_port_equivalences"],external_positive_scopes=evaluated["external_positive_scopes"]),
        "limitations":dict(independent_human_adjudication=False,population_precision=None,real_world_false_positive_rate=None,
            statistical_confidence=None,independent_external_assurance=False,
            reasons=sorted(load(Path(__file__).resolve().parents[1]/"_data/supported_scope_manifest.json")["exclusions"]))}


def independent_truth(case: dict) -> str | None:
    """Primitive language interpreter, independent of the candidate implementation."""
    ops = case.get("opcodes")
    if ops is None or case["stratum"] not in {"RESTRICTED_SUPPORTED_OPCODE_LANGUAGE", "AUTHORIZATION", "NO_POLICY"}:
        return None
    if case["disposition"] == "UNDECLARED":
        return "NO_DECLARED_CLAIM"
    if case["disposition"] == "ALLOW":
        return "AUTHORIZATION"
    denied = 1 if case["effect"] == "filesystem.write" else 2
    effects = 0
    for op in ops:
        effects |= [0, 1, 2, 4][op]
    if effects & denied:
        return "SUPPORTED_VIOLATION"
    if effects & 4:
        return "NOT_EVALUABLE"
    return "NO_SUPPORTED_VIOLATION"


def reference_cases(cases:list[dict])->list[dict]:
    rows=[]
    for case in cases:
        if not case["required_supported_control"] or "repository" in case:
            continue
        ops=case.get("opcodes",[0])
        rows.append(dict(case_id=case["case_id"],first=ops[0],second=ops[1] if len(ops)>1 else 0,
            second_reachable=len(ops)>1,disposition={"UNDECLARED":0,"ALLOW":1,"DENY":2}[case["disposition"]],
            denied_effect=1 if case["effect"]=="filesystem.write" else 2,
            source=dict(has_subject=case["source"] is not None,
                has_support=case["source"] is not None and case["stratum"]!="ZERO_EXECUTABLE_COVERAGE",complete=True),
            production=case["provenance"]=="PRODUCTION"))
    if len(rows)!=74:
        raise ValueError("independent primitive control denominator changed")
    return rows


def verify_reference(cases:list[dict],rows:list[dict])->None:
    cases={c["case_id"]:c for c in cases}
    names=[r["case_id"] for r in rows]
    required={c["case_id"] for c in cases.values() if c["required_supported_control"] and "repository" not in c}
    if len(names)!=len(set(names)) or set(names)!=required:
        raise ValueError("independent primitive oracle omitted or duplicated controls")
    labels=["AUTHORIZATION","SUPPORTED_VIOLATION","NO_SUPPORTED_VIOLATION","NOT_EVALUABLE",
            "NOT_APPLICABLE","INVALID_POLICY","NO_DECLARED_CLAIM"]
    for row in rows:
        case=cases[row["case_id"]]
        if type(row["truth"]) is not int or not 0<=row["truth"]<len(labels):
            raise ValueError("invalid primitive oracle output")
        if labels[row["truth"]] not in case["expected_reporting"] or row["blocking"]!=case["expected_blocking"]:
            raise ValueError("independent reference helper disagrees with pre-evaluation expected answer: "+row["case_id"])


def observed_endpoint(row: dict) -> tuple[str, bool]:
    if row["status"] == "INVALID_DIAGNOSTIC":
        return "INVALID_DIAGNOSTIC", False
    if row["status"] != "OBSERVED":
        return "DRIVER_FAILURE", False
    claims = row["module"]["conclusions"]
    if not claims:
        return "NO_DECLARED_CLAIM", False
    if len(claims) != 1:
        return "WRONG_CLAIM_UNIVERSE", False
    evaluation = claims[0]
    if evaluation.get("authorization") is not None:
        return "AUTHORIZATION", False
    verdict = evaluation["verdict"]
    blocking = evaluation.get("blocking_eligibility") == "BLOCK_SUPPORTED"
    if verdict == "SUPPORTED_VIOLATION" and not blocking:
        return "SUPPORTED_VIOLATION_ADVISORY", False
    return verdict, blocking


def score(cases: list[dict], rows: list[dict], mutations: dict) -> dict:
    index = {r["case_id"]: r for r in rows}
    if len(index) != len(rows) or set(index) - {c["case_id"] for c in cases}:
        raise ValueError("duplicate or foreign candidate observations")
    scored, sites, witness_sites = [], set(), set()
    claims = paths = differentials = metadata_controls = invalid_equivalences = external_positive = 0
    for case in cases:
        row = index.get(case["case_id"])
        if row is None:
            scored.append({"case_id": case["case_id"], "status": "INCOMPLETE", "match": False, "required":case["required_supported_control"], "holdout":case["holdout"], "stratum":case["stratum"], "ground_truth":case.get("ground_truth","PUBLIC_REFERENCE")})
            continue
        endpoint, blocking = observed_endpoint(row)
        expected = case["expected_reporting"]
        reference = independent_truth(case)
        # Advisory support retains the same raw positive while withholding enforcement.
        raw_endpoint = "SUPPORTED_VIOLATION" if endpoint == "SUPPORTED_VIOLATION_ADVISORY" else endpoint
        endpoint_match = endpoint in expected or (raw_endpoint in expected and "SUPPORTED_VIOLATION_ADVISORY" not in expected)
        if reference is not None and reference not in expected:
            raise ValueError("frozen expected answers disagree with independent primitive interpreter: " + case["case_id"])
        equal = row.get("equal_differentials", row.get("invalid_port_equivalence", False))
        match = endpoint_match and equal and row.get("equal_metadata_control", row["status"]=="INVALID_DIAGNOSTIC") and (case["expected_blocking"] is None or case["expected_blocking"] == blocking)
        witness_count = 0
        if row["status"] == "OBSERVED":
            module = row["module"]
            assumptions=sorted(set(reason for claim in module["conclusions"] for reason in claim.get("reason_codes",[])
                if reason.startswith(("operation_summary_assumption:","accepted_profile:"))))
            if raw_endpoint=="NO_SUPPORTED_VIOLATION" and any(op in (1,2) for op in case.get("opcodes",[])):
                unconfigured=json.loads(row["authoritative_products"]["unconfigured_conformance"])
                original=next(m for m in unconfigured["modules"] if m["module"]==OWNER)
                match &= bool(assumptions) and original["conclusions"][0]["verdict"]=="NOT_EVALUABLE"
            claims += len(module["conclusions"])
            paths += len(module["observations"])
            differentials += int(equal)
            metadata_controls += int(row.get("equal_metadata_control",False))
            for operation in row["operation_inventory"]:
                provenance=operation["provenance"]
                if provenance["path"] == case.get("path", "sample/_code/lib.rs"):
                    location=provenance["location"]
                    sites.add((case["source_sha256"],provenance["path"],location["line"],location["column"],operation["reference"]))
            for observation in module["observations"]:
                if observation["effect"] == case["effect"] and observation["path"] == case.get("path", "sample/_code/lib.rs"):
                    site = (case["source_sha256"], observation["path"], observation["line"], observation["column"], observation["operation"])
                    witness_sites.add(site)
                    witness_count += 1
            if raw_endpoint=="SUPPORTED_VIOLATION":
                conclusion=module["conclusions"][0]
                source_sites={op.get("semantic_operation_site_id") for op in row["operation_inventory"] if op["provenance"]["path"]==case.get("path","sample/_code/lib.rs")}
                linked=any(obs["effect"]==case["effect"] and obs["path"]==case.get("path","sample/_code/lib.rs")
                    and obs["operation_site_id"] in source_sites and obs["operation_site_id"] is not None for obs in module["observations"])
                evaluation=conclusion
                match &= witness_count>0 and linked and bool(evaluation.get("proof_refs")) and evaluation.get("proof_graph") is not None
            if "repository" in case and case["expected_reporting"] == ["SUPPORTED_VIOLATION"]:
                match &= raw_endpoint == "SUPPORTED_VIOLATION" and witness_count >= case["oracle"]["minimum_distinct_sites"]
                external_positive += int(match)
        else:
            invalid_equivalences += int(equal)
        scored.append({"case_id": case["case_id"], "status": "COMPLETED", "observed": endpoint,
                       "raw_observed": raw_endpoint, "blocking": blocking, "match": bool(match),
                       "required": case["required_supported_control"], "holdout": case["holdout"],
                       "stratum": case["stratum"], "ground_truth": case.get("ground_truth", "PUBLIC_REFERENCE"),
                       "independent_primitive_truth": reference, "witnesses": witness_count,
                       "assumption_refs":assumptions if row["status"]=="OBSERVED" else [],
                       "observation_digest": digest(canonical(row))})
    scored_index={c["case_id"]:c for c in scored}
    checked=[]
    for edge in mutations["relations"]:
        left,right=scored_index[edge["from"]],scored_index[edge["to"]]
        match=left["match"] and right["match"] and (
            (left.get("raw_observed") != right.get("raw_observed")) == edge["expected_reporting_changes"]
            and (left.get("blocking") != right.get("blocking")) == edge["expected_blocking_changes"])
        checked.append({"from":edge["from"],"to":edge["to"],"match":match})
    if len(checked)!=mutations["directed_relations"] or mutations["extra_independent_samples"]!=0:
        raise ValueError("preregistered mutation denominator differs")
    return {"scored": scored, "distinct_source_sites": len(sites), "source_site_identities": sorted(sites),
            "distinct_supported_effect_sites":len(witness_sites),"supported_effect_site_identities":sorted(witness_sites),
            "claims": claims, "causal_paths": paths, "equal_differentials": differentials,
            "invalid_port_equivalences":invalid_equivalences,"equal_metadata_controls":metadata_controls,
            "external_positive_scopes": external_positive,
            "mutation_results":checked,"mutation_protocol": mutations}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--staged-cli", type=Path, required=True)
    parser.add_argument("--retained-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    args = parser.parse_args()
    from qualification_controls import QualificationHarnessControls
    controls=unittest.TextTestRunner(stream=sys.stderr).run(unittest.defaultTestLoader.loadTestsFromTestCase(QualificationHarnessControls))
    if not controls.wasSuccessful():
        raise RuntimeError("independent harness countermodels failed before candidate evaluation")
    data = args.root / "testing/_data"
    cases = corpus(data)
    premises=load(args.bindings)
    if set(premises)!={"candidate_source","native_source","toolchain"} or any(type(value) is not str or not re.fullmatch('sha256:[0-9a-f]{64}',value) for value in premises.values()):
        raise ValueError("exact caller-supplied source and toolchain premises are required; unknown standalone bindings cannot qualify")
    actual=local_inputs(args.root,cases,args.executable,args.staged_cli)
    # Construct every other current identity before candidate evaluation. The
    # issuer invokes this test-owned process; production code imports no oracle.
    bindings=dict(premises,**actual)
    # OPS supplies a fresh external reservation that compiler/staging cleanup preserves.
    retained_directory(args.root,args.retained_run)
    inputs = canonical([native_case(case) for case in cases])
    if len(inputs)>4*1024*1024 or len(canonical(cases))>4*1024*1024 or args.bindings.stat().st_size>1024*1024:
        raise ValueError("qualification retained inputs exceed their reserved byte bounds")
    exclusive(args.retained_run / "candidate_inputs.json", inputs)
    exclusive(args.retained_run / "preregistered_cases.json", canonical(cases))
    exclusive(args.retained_run / "binding_premises.json", jcs(bindings))
    references=args.retained_run / "reference_inputs.json"
    exclusive(references,canonical(reference_cases(cases)))
    reference_output=args.retained_run / "reference_outputs.jsonl"
    subprocess.run([str(args.executable),"--reference",str(references),str(reference_output)],check=True)
    reference_rows=[json.loads(line) for line in reference_output.read_bytes().splitlines()]
    verify_reference(cases,reference_rows)
    observations = args.retained_run / "observations.jsonl"
    result = subprocess.run([str(args.executable), str(args.retained_run / "candidate_inputs.json"), str(observations)], check=False)
    raw = observations.read_bytes() if observations.is_file() else b""
    if len(raw) > MAX_BYTES:
        raise ValueError("retained native observations exceed bound")
    rows = [json.loads(line) for line in raw.splitlines()]
    evaluated = score(cases, rows, load(data / "source_mutation_relations.json"))
    evaluated["native_exit_code"]=result.returncode
    evaluated["harness_countermodels_passed"]=controls.testsRun
    evaluated["independent_reference_outputs_digest"]=digest(reference_output.read_bytes())
    # The first result is immutable even when the candidate fails.
    exclusive(args.retained_run / "scored_outcomes.json", canonical(evaluated))
    report=manifest(evaluated,bindings,cases)
    exclusive(args.retained_run / "manifest.json",jcs(report))
    if result.returncode or len(rows) != len(cases) or any(not c["match"] for c in evaluated["scored"]) or any(not e["match"] for e in evaluated["mutation_results"]):
        raise RuntimeError("semantic qualification failed; every available first observation and mismatch was retained")
    if actual!=local_inputs(args.root,cases,args.executable,args.staged_cli):
        raise RuntimeError("qualification executable or authored dependencies changed during scoring")
    validation=args.retained_run/"validation_inputs.json"
    # Reconstruct from independently supplied premises and retained outcome bytes;
    # never use the report's own input claims as their validation oracle.
    exclusive(validation,jcs(dict(identities=dict(bindings,outcomes=digest((args.retained_run/"scored_outcomes.json").read_bytes())))))
    subprocess.run([str(args.executable),"--validate-metadata",str(args.retained_run/"manifest.json"),str(validation),
                    str(data/"supported_scope_manifest.json")],check=True)
    exclusive(args.output, jcs(report))


if __name__ == "__main__":
    main()
