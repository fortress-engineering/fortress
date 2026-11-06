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

MAX_BYTES = 32 * 1024 * 1024
MAX_NORMALIZED = 64 * 1024 * 1024
MAX_ROWS = 100_000
MAX_EXACT = 2**53 - 1


def require(value, message):
    if not value:
        raise ValueError(message)


def unique_json(payload):
    require(len(payload) <= MAX_BYTES, "payload byte bound")
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
            require(depth <= 64, "JSON depth bound")
        elif byte in (93, 125):
            depth -= 1
        elif byte in (44, 58):
            tokens += 1
            require(tokens <= 1_000_000, "JSON token bound")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def integer(value):
        parsed = int(value)
        require(abs(parsed) <= MAX_EXACT, "inexact public integer")
        return parsed
    def constant(_):
        raise ValueError("nonfinite number")
    def floating(value):
        parsed = float(value)
        require(math.isfinite(parsed), "nonfinite number")
        return parsed
    value = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs,
                       parse_int=integer, parse_float=floating, parse_constant=constant)
    json.dumps(value, ensure_ascii=False).encode("utf-8")
    return value


def parse_junit(payload, inventory):
    """Independent XML facts; companion inventory only resolves package ambiguity."""
    require(len(payload) <= MAX_BYTES, "payload byte bound")
    source = payload.decode("utf-8")
    require(not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", source, re.I), "DTD/entity forbidden")
    require(all(c in "\t\n\r" or 0x20 <= ord(c) <= 0xD7FF or
                0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF
                for c in source), "XML1.0 character")
    declaration = re.match(r"\ufeff?<\?xml\s+([^?]+)\?>", source)
    if declaration:
        text = declaration[1]
        require(re.search(r'version\s*=\s*[\'"]1\.0[\'"]', text), "XML version")
        encoding = re.search(r'encoding\s*=\s*[\'"]([^\'"]+)[\'"]', text)
        require(not encoding or encoding[1].lower() == "utf-8", "XML encoding")
    require(len(inventory) <= MAX_ROWS, "inventory count bound")
    require(sum(sum(len((item["key"][name] or "").encode("utf-8")) for name in
                        ("package", "target", "qualified_name")) + 128 for item in inventory)
            <= MAX_NORMALIZED, "inventory normalized bound")
    packages = {}
    for item in inventory:
        native = item["key"]
        partial = (native["target"], native["qualified_name"])
        candidate = native["package"]
        if partial not in packages:
            packages[partial] = candidate
        elif packages[partial] != candidate:
            packages[partial] = None
    stack, suites, rows, limits = [], [], {}, set()
    pending = None
    root_seen = False
    charge = events = 0
    # iterparse and immediate clear avoid retaining the entire XML tree.
    for event, elem in ET.iterparse(io.BytesIO(payload), events=("start", "end", "pi", "start-ns")):
        events += 1
        require(events <= 1_000_000, "XML event bound")
        if event == "start-ns":
            raise ValueError("XML namespace declaration unsupported")
        if event == "pi":
            limits.add("JUNIT_PROCESSING_INSTRUCTION_UNINTERPRETED")
            continue
        tag = elem.tag
        require(type(tag) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*",tag), "XML namespace")
        if event == "start":
            require(len(stack) < 64 and len(elem.attrib) <= 256, "XML depth/attribute bound")
            require(all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*",k) and k != "xmlns" and
                        len(v.encode("utf-8")) <= 65536 for k, v in elem.attrib.items()),
                    "XML attribute")
            attrs = elem.attrib
            if not stack:
                require(not root_seen and tag in ("testsuite", "testsuites"), "JUnit root")
                root_seen = True
            if tag in ("testsuite", "testsuites"):
                require(pending is None and (not stack or stack[-1] in ("testsuite", "testsuites")), "suite location")
                require(tag != "testsuites" or not stack, "nested testsuites")
                expected = {}
                for name in ("tests", "failures", "errors", "skipped"):
                    if name in attrs:
                        require(re.fullmatch(r"[0-9]+", attrs[name]), "suite count")
                        expected[name] = int(attrs[name])
                        require(expected[name] <= MAX_EXACT, "suite count bound")
                if attrs.get("disabled") not in (None,"0"): limits.add("JUNIT_DISABLED_MEMBERS")
                suites.append(dict(tag=tag, name=attrs.get("name") or None, package=attrs.get("package"),
                                   expected=expected, counts=dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)))
                if tag == "testsuite" and not attrs.get("name"):
                    limits.add("JUNIT_SUITE_TARGET_UNSPECIFIED")
            elif tag == "testcase":
                require(stack and stack[-1] == "testsuite" and pending is None and len(rows) < MAX_ROWS, "case location/count")
                require(bool(attrs.get("name")), "native case name")
                name = attrs["name"]
                if attrs.get("classname"):
                    name = attrs["classname"] + "::" + name
                require(len(name.encode("utf-8")) <= 65536,"native name bound")
                suite = suites[-1]
                package = suite["package"] or packages.get((suite["name"], name))
                if not package:
                    limits.add("JUNIT_PACKAGE_UNRESOLVED")
                native = (package, suite["name"], name)
                charge += sum(len((x or "").encode("utf-8")) for x in native) + 256
                require(charge <= MAX_NORMALIZED, "normalized output budget")
                require(native not in rows, "duplicate/retried native case")
                outcome = "PASSED"
                if attrs.get("status") in ("notrun", "skipped"):
                    outcome = "SKIPPED"
                elif "status" in attrs and attrs["status"] not in ("run", "completed"):
                    outcome = "UNKNOWN"
                    limits.add("JUNIT_STATUS_UNINTERPRETED")
                retry_metadata = any(word in k.lower() for k in attrs for word in ("retry", "flaky", "rerun"))
                if retry_metadata:
                    limits.add("JUNIT_RETRY_METADATA")
                pending = dict(key=native, outcome=outcome, terminal=set(), retry_metadata_present=retry_metadata, unknown=False)
            elif tag in ("failure", "error", "skipped"):
                if not stack or stack[-1] != "testcase" or pending is None:
                    limits.add("JUNIT_NONCASE_TERMINAL_STATE")
                else:
                    require(not pending["terminal"], "duplicate/conflicting terminal state")
                    pending["terminal"].add(tag)
            elif tag not in ("system-out", "system-err", "properties", "property"):
                limits.add("JUNIT_UNINTERPRETED_ELEMENT")
                if pending: pending["unknown"] = True
                if pending and any(x in tag.lower() for x in ("retry", "flaky", "rerun")):
                    pending["retry_metadata_present"] = True
            stack.append(tag)
        else:
            require(stack and stack.pop() == tag, "XML closure")
            if tag == "testcase":
                terminal = pending["terminal"]
                if "failure" in terminal or "error" in terminal:
                    pending["outcome"] = "FAILED"
                elif "skipped" in terminal:
                    pending["outcome"] = "SKIPPED"
                if pending["outcome"]=="SKIPPED" and ("failure" in terminal or "error" in terminal):
                    limits.add("JUNIT_CONFLICTING_TERMINAL_STATES")
                if pending["outcome"]=="PASSED" and pending["unknown"]: pending["outcome"]="UNKNOWN"
                for suite in suites:
                    suite["counts"]["tests"] += 1
                    suite["counts"]["failures"] += "failure" in terminal
                    suite["counts"]["errors"] += "error" in terminal
                    suite["counts"]["skipped"] += pending["outcome"] == "SKIPPED" or "skipped" in terminal
                rows[pending["key"]] = dict(outcome=pending["outcome"], retry_metadata_present=pending["retry_metadata_present"])
                pending = None
            elif tag in ("testsuite", "testsuites"):
                suite = suites.pop()
                for name, count in suite["expected"].items():
                    if count != suite["counts"][name]:
                        limits.add("JUNIT_DECLARED_COUNT_MISMATCH:" + name)
            elem.clear()
    require(root_seen and not stack and not suites and pending is None, "complete XML syntax")
    return rows, sorted(limits)
