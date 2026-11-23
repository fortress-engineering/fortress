"""Observe bounded compile-only CPython syntax and lexical facts from stdin.

The subject is never imported, executed, or read from disk. This worker
requires a trusted interpreter, installation and supervising host.
"""
from __future__ import annotations

import sys


if (sys.implementation.name != "cpython" or sys.version_info[:2] not in ((3, 12), (3, 13))
        or not sys.flags.isolated or not sys.flags.no_site
        or not sys.dont_write_bytecode or sys.flags.optimize):
    sys.stdout.buffer.write(b'{"reason":"UNSUPPORTED_INTERPRETER_FLAGS",'
                            b'"schema":"fortress-host/python-lexical-ready/1",'
                            b'"status":"UNAVAILABLE"}\n')
    raise SystemExit(3)

import ast
import base64
import binascii
from hashlib import file_digest, sha256
import io
import json
from pathlib import Path
import re
import symtable
import tokenize
import warnings


REQUEST = "fortress-research/python-lexical-request/1"
RESPONSE = "fortress-research/python-lexical-response/1"
SOURCE_MAX = 128 * 1024
INPUT_MAX = 192 * 1024
OUTPUT_MAX = 1024 * 1024
TOKEN_MAX = 10_000
NODE_MAX = 6000
DEPTH_MAX = 72
BINDING_MAX = 4000
SCOPE_MAX = 256
SHAPE_MAX = 5000
KEYS = {"schema", "id", "mode", "source", "source_ref", "byte_count", "runtime_ref", "worker_ref"}
FLAGS = ("assigned", "declared_global", "free", "global", "imported",
         "local", "namespace", "nonlocal", "parameter", "referenced")
FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
REGIONS = (ast.AsyncFor, ast.AsyncWith, ast.Await, ast.ExceptHandler, ast.Try,
           ast.TryStar, ast.With, ast.Raise, ast.Return)
OPAQUE_BLOCKS = (ast.ClassDef, ast.Lambda, ast.ListComp, ast.SetComp,
                 ast.DictComp, ast.GeneratorExp, ast.TypeAlias)
PHASES = ("SYNTAX", "LEXICAL_SCOPE", "MODULE_VALIDITY")
ENCODING = re.compile(br"^[ \t\f]*#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+)")
BLANK_OR_COMMENT = re.compile(br"^[ \t\f]*(?:[#\r\n]|$)")
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class Refuse(Exception):
    """Typed refusal; the string is a fixed non-secret reason code."""


def stamp(data):
    return "sha256:" + sha256(data).hexdigest()


def exact_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def bounded_encoded(value):
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, allow_nan=False,
                               separators=(",", ":"))
    output = bytearray()
    for chunk in encoder.iterencode(value):
        raw = chunk.encode("ascii")
        if len(output) + len(raw) >= OUTPUT_MAX:
            raise Refuse("OUTPUT_LIMIT")
        output.extend(raw)
    output.append(10)
    return output


def hash_file(path):
    with path.open("rb") as stream:
        return "sha256:" + file_digest(stream, "sha256").hexdigest()


def runtime():
    executable = Path(sys.executable).resolve(strict=True)
    pieces = {"executable": executable, "ast": Path(ast.__file__),
              "symtable": Path(symtable.__file__), "tokenize": Path(tokenize.__file__)}
    if sys.platform == "win32":
        import ctypes
        get_module = ctypes.WinDLL("kernel32", use_last_error=True).GetModuleFileNameW
        get_module.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint)
        get_module.restype = ctypes.c_uint
        buf = ctypes.create_unicode_buffer(32768)
        length = get_module(sys.dllhandle, buf, len(buf))
        if not 0 < length < len(buf):
            raise Refuse("RUNTIME_BUILD_UNAVAILABLE")
        pieces["compiler_dll"] = Path(buf.value).resolve(strict=True)
    return {
        "implementation": sys.implementation.name,
        "version": sys.version.replace("\n", " "),
        "platform": sys.platform,
        "tool_files": {key: hash_file(path) for key, path in pieces.items()},
        "flags": ["-I", "-S", "-B"],
    }


READY = "fortress-host/python-lexical-ready/1"
READY_MAX = 4096
MEMORY_BYTES = 96 * 1024 * 1024
CPU_SECONDS = 1


def linux_gate():
    import resource

    caps = ((resource.RLIMIT_AS, MEMORY_BYTES),
            (resource.RLIMIT_CPU, CPU_SECONDS),
            (resource.RLIMIT_CORE, 0))
    for resource_id, maximum in caps:
        if any(value != resource.RLIM_INFINITY and value < maximum
               for value in resource.getrlimit(resource_id)):
            raise Refuse("LINUX_LIMIT_PROFILE_UNAVAILABLE")
        resource.setrlimit(resource_id, (maximum, maximum))
        if resource.getrlimit(resource_id) != (maximum, maximum):
            raise Refuse("LINUX_LIMIT_PROFILE_UNAVAILABLE")
    return "LINUX_AS_CPU_V1", {
        "address_space_bytes": MEMORY_BYTES,
        "cpu_seconds": CPU_SECONDS,
        "core_bytes": 0,
    }


def windows_gate():
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_int64),
            ("job_time", ctypes.c_int64),
            ("flags", wintypes.DWORD),
            ("min_working_set", ctypes.c_size_t),
            ("max_working_set", ctypes.c_size_t),
            ("active_processes", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority", wintypes.DWORD),
            ("schedule", wintypes.DWORD),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("basic", BasicLimits),
            ("io_counters", ctypes.c_uint64 * 6),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t),
            ("peak_job_memory", ctypes.c_size_t),
        ]

    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    handle_t, dword = wintypes.HANDLE, wintypes.DWORD
    pointer = ctypes.c_void_p

    def api(name, result, *args):
        call = getattr(dll, name)
        call.restype = result
        call.argtypes = args
        return call

    make_job = api("CreateJobObjectW", handle_t, pointer, wintypes.LPCWSTR)
    current_process = api("GetCurrentProcess", handle_t)
    assign = api("AssignProcessToJobObject", wintypes.BOOL, handle_t, handle_t)
    membership = api("IsProcessInJob", wintypes.BOOL, handle_t, handle_t,
                     ctypes.POINTER(wintypes.BOOL))
    set_limits = api("SetInformationJobObject", wintypes.BOOL, handle_t, ctypes.c_int,
                     pointer, dword)
    query = api("QueryInformationJobObject", wintypes.BOOL, handle_t, ctypes.c_int,
                pointer, dword, ctypes.POINTER(dword))
    close_handle = api("CloseHandle", wintypes.BOOL, handle_t)

    def require(success):
        if not success:
            raise Refuse("WINDOWS_JOB_PROFILE_UNAVAILABLE")

    job = make_job(None, None)
    require(job)
    assigned = False
    try:
        # ACTIVE_PROCESS | PROCESS_MEMORY | JOB_MEMORY | KILL_ON_JOB_CLOSE.
        # This unnamed private job never enables silent or requested breakaway.
        expected_flags = 0x8 | 0x100 | 0x200 | 0x2000
        information_class = 9  # JobObjectExtendedLimitInformation
        wanted = ExtendedLimits()
        wanted.basic.flags = expected_flags
        wanted.basic.active_processes = 1
        wanted.process_memory = wanted.job_memory = MEMORY_BYTES
        require(set_limits(job, information_class, ctypes.byref(wanted), ctypes.sizeof(wanted)))
        process = current_process()
        require(assign(job, process))
        assigned = True
        in_job = wintypes.BOOL()
        require(membership(process, job, ctypes.byref(in_job)) and in_job.value)
        verified = ExtendedLimits()
        require(query(job, information_class, ctypes.byref(verified), ctypes.sizeof(verified), None))
        require(verified.basic.flags == expected_flags
                and verified.basic.active_processes == 1
                and verified.process_memory == verified.job_memory == MEMORY_BYTES)
    finally:
        if not assigned:
            close_handle(job)
        # After self-assignment the process owns the non-inheritable handle until exit.
        # Closing the last reference here would terminate the active worker.
    return "WINDOWS_JOB_WALL_V1", {
        "commit_bytes": MEMORY_BYTES,
        "active_processes": 1,
        "kill_on_close": True,
    }


def source_gate():
    if sys.platform == "linux":
        return linux_gate()
    if sys.platform == "win32":
        return windows_gate()
    raise Refuse("UNSUPPORTED_WORKER_PLATFORM")


def publish_ready(status, **fields):
    raw = exact_json({"schema": READY, "status": status, **fields}) + b"\n"
    if len(raw) > READY_MAX:
        raise Refuse("READY_OUTPUT_LIMIT")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def prepare(args):
    if (len(args) != 5 or args[:2] != ["--serve", "--worker-ref"]
            or args[3] != "--runtime-ref"
            or not DIGEST.fullmatch(args[2]) or not DIGEST.fullmatch(args[4])):
        raise Refuse("UNSUPPORTED_WORKER_INVOCATION")
    profile, limits = source_gate()
    worker_ref, runtime_ref = args[2], args[4]
    if hash_file(Path(__file__)) != worker_ref:
        raise Refuse("WORKER_BINDING_MISMATCH")
    if stamp(exact_json(runtime())) != runtime_ref:
        raise Refuse("RUNTIME_BINDING_MISMATCH")
    publish_ready("READY", worker_ref=worker_ref, runtime_ref=runtime_ref,
                  grammar=f"cpython{sys.version_info.major}.{sys.version_info.minor}",
                  profile=profile, limits=limits)
    return worker_ref, runtime_ref


def duplicate_free(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise Refuse("DUPLICATE_JSON_KEY")
        values[key] = value
    return values


def no_constant(raw):
    raise Refuse("UNSUPPORTED_JSON_CONSTANT")


def load_input():
    payload = sys.stdin.buffer.read(INPUT_MAX + 1)
    if len(payload) > INPUT_MAX:
        raise Refuse("INPUT_LIMIT")
    try:
        request = json.loads(payload.decode("utf-8"), object_pairs_hook=duplicate_free,
                             parse_constant=no_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise Refuse("INVALID_REQUEST_JSON") from None
    if not isinstance(request, dict) or set(request) != KEYS:
        raise Refuse("UNKNOWN_OR_MISSING_REQUEST_FIELDS")
    if request["schema"] != REQUEST or request["mode"] not in ("SYNTAX", "LEXICAL"):
        raise Refuse("UNSUPPORTED_REQUEST_MODE")
    if not isinstance(request["id"], str) or not ID.fullmatch(request["id"]):
        raise Refuse("INVALID_REQUEST_ID")
    if any(not isinstance(request[key], str) or not DIGEST.fullmatch(request[key])
           for key in ("source_ref", "runtime_ref", "worker_ref")):
        raise Refuse("INVALID_DIGEST")
    count = request["byte_count"]
    if type(count) is not int or not 0 <= count <= SOURCE_MAX:
        raise Refuse("SOURCE_LIMIT_OR_INVALID_LENGTH")
    try:
        encoded = request["source"].encode("ascii")
        raw = base64.b64decode(encoded, validate=True)
    except (AttributeError, UnicodeError, ValueError, binascii.Error):
        raise Refuse("INVALID_SOURCE_ENCODING") from None
    if base64.b64encode(raw) != encoded or len(raw) != count or stamp(raw) != request["source_ref"]:
        raise Refuse("SOURCE_BINDING_MISMATCH")
    return request, raw


def source_text(raw):
    if raw.startswith(b"\xef\xbb\xbf"):
        raise Refuse("UNSUPPORTED_UTF8_BOM")
    if b"\r" in raw.replace(b"\r\n", b""):
        raise Refuse("UNSUPPORTED_LINE_ENDING")
    # Examine allowed cookie lines without looking up any source-selected codec.
    first = raw.split(b"\n", 2)
    for line in first[:2] if BLANK_OR_COMMENT.match(first[0]) else first[:1]:
        match = ENCODING.match(line)
        if match and match[1].lower() not in (b"utf-8", b"utf_8"):
            raise Refuse("UNSUPPORTED_ENCODING_COOKIE")
    return raw.decode("utf-8")


def check_tokens(source):
    """Pre-admit bounded token count and nesting. AST and compile have separate limits."""
    indent = 0
    brackets = 0
    try:
        items = tokenize.generate_tokens(io.StringIO(source).readline)
        for total, item in enumerate(items, 1):
            if item.type == tokenize.INDENT:
                indent += 1
            elif item.type == tokenize.DEDENT:
                indent -= 1
            elif item.type == tokenize.OP:
                if item.string in ("(", "[", "{"):
                    brackets += 1
                elif item.string in (")", "]", "}"):
                    brackets -= 1
            if total > TOKEN_MAX or indent + max(brackets, 0) > DEPTH_MAX:
                raise Refuse("TOKEN_OR_NESTING_LIMIT")
    except (SyntaxError, tokenize.TokenError):
        # The AST stage has authority over syntax and provides a typed outcome.
        return


def check_ast(tree):
    work = [(tree, 0)]
    count = 0
    while work:
        node, depth = work.pop()
        count += 1
        if count > NODE_MAX or depth > DEPTH_MAX:
            raise Refuse("AST_NODE_OR_DEPTH_LIMIT")
        work.extend((child, depth + 1) for child in ast.iter_child_nodes(node))


def span(node, lines):
    start, end = node.lineno, node.end_lineno
    first, last = node.col_offset, node.end_col_offset
    if not (1 <= start <= end <= len(lines)
            and 0 <= first <= len(lines[start - 1]) and 0 <= last <= len(lines[end - 1])
            and (start != end or first <= last)):
        raise Refuse("INVALID_COMPILER_COORDINATE")
    try:
        lines[start - 1][:first].decode("utf-8")
        lines[end - 1][:last].decode("utf-8")
    except UnicodeError:
        raise Refuse("INVALID_COMPILER_COORDINATE") from None
    return [start, first, end, last]


def shape(node):
    if isinstance(node, ast.Name):
        return f"Name:{node.id}"
    if isinstance(node, ast.Attribute):
        return f"Attribute:{node.attr}"
    return type(node).__name__


def project(tree, table, raw):
    rows = {"scopes": [], "imports": [], "constructs": [], "limitations": []}
    lines = raw.replace(b"\r\n", b"\n").split(b"\n")
    counters = {"binding": 0, "shape": 0}

    def add(key, row):
        counters["shape"] += 1
        if counters["shape"] > SHAPE_MAX:
            raise Refuse("FACT_LIMIT")
        rows[key].append(row)

    def visit_scope(syntax, scope_table, parent):
        scope = f"s{len(rows['scopes'])}"
        if len(rows["scopes"]) >= SCOPE_MAX:
            raise Refuse("SCOPE_LIMIT")
        bindings = []
        for name in sorted(scope_table.get_identifiers()):
            counters["binding"] += 1
            if counters["binding"] > BINDING_MAX:
                raise Refuse("BINDING_LIMIT")
            symbol = scope_table.lookup(name)
            bindings.append({"name": name, "flags": [flag for flag in FLAGS
                                                       if getattr(symbol, f"is_{flag}")()]})
        is_module = isinstance(syntax, ast.Module)
        rows["scopes"].append({"id": scope, "parent": parent, "kind": type(syntax).__name__,
                               "name": scope_table.get_name(), "span": None if is_module else span(syntax, lines),
                               "bindings": bindings})
        children = sorted(scope_table.get_children(), key=lambda row: (row.get_lineno(), row.get_name()))
        work = list(reversed(syntax.body))
        while work:
            node = work.pop()
            if isinstance(node, FUNCTIONS):
                matches = [child for child in children if child.get_name() == node.name
                           and child.get_lineno() == node.lineno and child.get_type() == "function"]
                if (len(matches) != 1 or node.decorator_list or node.type_params or node.returns
                        or node.args.defaults or any(v is not None for v in node.args.kw_defaults)
                        or any(arg.annotation for arg in ast.walk(node.args) if isinstance(arg, ast.arg))):
                    add("limitations", {"scope": scope, "code": "UNMODELED_FUNCTION_SCOPE_OR_HEADER",
                                        "span": span(node, lines)})
                    continue
                visit_scope(node, matches[0], scope)
                continue
            if isinstance(node, OPAQUE_BLOCKS):
                add("limitations", {"scope": scope, "code": "UNMODELED_SCOPE_FORM",
                                    "kind": type(node).__name__, "span": span(node, lines)})
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                form = "from" if isinstance(node, ast.ImportFrom) else "import"
                add("imports", {"scope": scope, "form": form, "level": getattr(node, "level", None),
                                "module": getattr(node, "module", None),
                                "names": [[alias.name, alias.asname] for alias in node.names],
                                "target": "UNRESOLVED", "span": span(node, lines)})
            if isinstance(node, ast.Call):
                add("constructs", {"scope": scope, "kind": "Call", "spelling": shape(node.func),
                                   "target": "UNRESOLVED", "span": span(node, lines)})
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                add("constructs", {"scope": scope, "kind": "NameStore", "spelling": node.id,
                                   "span": span(node, lines)})
            elif isinstance(node, REGIONS):
                add("constructs", {"scope": scope, "kind": type(node).__name__, "span": span(node, lines)})
            work.extend(reversed(list(ast.iter_child_nodes(node))))

    visit_scope(tree, table, None)
    return rows


def syntax_diagnostic(error):
    # SyntaxError offset conventions differ from AST UTF-8 coordinates.
    # Report line only rather than guessing an offset conversion.
    return {"reason": type(error).__name__, "line": error.lineno}


def phases():
    return {name: {"status": "NOT_RUN"} for name in PHASES}


def observe(request, raw, reply):
    stage = reply["stages"]
    try:
        source = source_text(raw)
    except UnicodeError:
        stage["SYNTAX"] = {"status": "INVALID", "reason": "INVALID_UTF8"}
        reply["outcome"] = "INVALID_SOURCE"
        return
    except Refuse as error:
        reply.update(outcome="UNSUPPORTED", reason=str(error))
        return
    check_tokens(source)
    for key, operation in (
        ("SYNTAX", lambda: ast.parse(source, filename="<fortress-source>", mode="exec")),
        ("LEXICAL_SCOPE", lambda: symtable.symtable(source, "<fortress-source>", "exec")),
        ("MODULE_VALIDITY", lambda: compile(source, "<fortress-source>", "exec",
                                            dont_inherit=True, optimize=0)),
    ):
        stage[key] = {"status": "INCOMPLETE"}
        try:
            result = operation()
        except SyntaxError as error:
            stage[key] = {"status": "INVALID", **syntax_diagnostic(error)}
            reply.update(outcome="INVALID_SOURCE")
            return
        stage[key] = {"status": "COMPLETE"}
        if key == "SYNTAX":
            tree = result
            check_ast(tree)
            if request["mode"] == "SYNTAX":
                reply.update(outcome="SYNTAX_ONLY", reason="LEXICAL_AND_MODULE_VALIDITY_NOT_ADMITTED")
                return
        elif key == "LEXICAL_SCOPE":
            table = result
    records = project(tree, table, raw)
    reply.update(outcome="PARTIAL" if records["limitations"] else "LEXICAL", observations=records)


def make_reply(worker_ref, runtime_ref):
    request, raw = load_input()
    reply = {
        "schema": RESPONSE, "id": request["id"], "mode": request["mode"],
        "source_ref": request["source_ref"], "byte_count": request["byte_count"],
        "runtime_ref": request["runtime_ref"], "worker_ref": request["worker_ref"],
        "stages": phases(), "observations": None, "target_execution": "NOT_RUN",
        "runtime_limitations": ["IMPORT_TARGETS", "RUNTIME_CALL_TARGETS", "EFFECTS", "EXECUTION"],
    }
    try:
        if worker_ref != request["worker_ref"]:
            raise Refuse("WORKER_BINDING_MISMATCH")
        if runtime_ref != request["runtime_ref"]:
            raise Refuse("RUNTIME_BINDING_MISMATCH")
        with warnings.catch_warnings():
            # Some compiler warnings include subject spellings. Observation
            # emits only the bounded protocol diagnostics.
            warnings.simplefilter("ignore")
            observe(request, raw, reply)
    except (Refuse, RecursionError, MemoryError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, Refuse) else type(error).__name__
        reply.update(outcome="UNAVAILABLE", reason=reason, observations=None)
    try:
        return bounded_encoded(reply)
    except Refuse as error:
        reply.update(outcome="UNAVAILABLE", reason=str(error), observations=None)
        return bounded_encoded(reply)


def main():
    if sys.argv[1:] == ["--describe-runtime"]:
        try:
            sys.stdout.buffer.write(exact_json(runtime()) + b"\n")
            return 0
        except (Refuse, ImportError, OSError, ValueError):
            return 3

    try:
        worker_ref, runtime_ref = prepare(sys.argv[1:])
    except (Refuse, ImportError, OSError, ValueError, MemoryError) as error:
        reason = str(error) if isinstance(error, Refuse) else type(error).__name__
        publish_ready("UNAVAILABLE", reason=reason)
        return 3

    try:
        raw = make_reply(worker_ref, runtime_ref)
    except Refuse as error:
        raw = bounded_encoded({"schema": RESPONSE, "outcome": "REJECTED",
                               "reason": str(error), "observations": None})
        sys.stdout.buffer.write(raw)
        return 2
    sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
