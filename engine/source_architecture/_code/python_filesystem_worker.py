"""Observe a bounded Python call shape and a separately qualified installed receiver.

Repository bytes are compiled as data. No repository module is imported or
executed. The source classification does not establish run-time imports or
admit a filesystem effect.
"""

from __future__ import annotations

import sys

if (sys.implementation.name != "cpython" or sys.version_info[:2] not in ((3, 12), (3, 13))
        or not sys.flags.isolated or not sys.flags.no_site
        or not sys.flags.safe_path or not sys.dont_write_bytecode or sys.flags.optimize):
    raise SystemExit(3)

import ast
import base64
from hashlib import sha256
import inspect
import json
import os
import pathlib
import re
import stat
import symtable
from types import CodeType
import warnings


REQUEST = "fortress:python:filesystem-calls-request:1"
RESPONSE = "fortress:python:filesystem-calls-response:1"
READY = "fortress-host/python-filesystem-calls-ready/1"
BOOTSTRAP = "sha256:19ca652a6ed8908d128ac231da47b45d0b0a86a9baffaff9626fb2d1609c9836"
MAX_SOURCE = 32 * 1024
MAX_REQUEST = 64 * 1024
MAX_BOOTSTRAP = 64 * 1024
MAX_MEMBER = 256 * 1024
MAX_FRAME = 4096
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
PATH_PART = re.compile(r"[A-Za-z_0-9][A-Za-z_0-9.-]{0,63}\Z")
REF = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMPORT = re.compile(rb"from[ \t]+pathlib[ \t]+import[ \t]+Path(?:[ \t]+as[ \t]+[A-Za-z_][A-Za-z0-9_]*)?")
PINS = ("worker_ref", "bootstrap_ref", "runtime_ref")
FIELDS = {"schema", "id", "source", "source_ref", "source_path", "byte_count", "function", *PINS}
PLATFORMS = {
    ("linux", (3, 12, 3)): {
        "target": "linux/amd64",
        "receiver": "pathlib.PosixPath",
        "method": "Path.write_bytes",
        "members": (
            ("definition", "pathlib.py", "sha256:b43e134bf7479759838b4ecec3d78e0e67fdfde2d671c5c2d7886a47da93885d"),
            ("receiver", "pathlib.py", "sha256:b43e134bf7479759838b4ecec3d78e0e67fdfde2d671c5c2d7886a47da93885d"),
        ),
        "entry": ("pathlib.py", "sha256:b43e134bf7479759838b4ecec3d78e0e67fdfde2d671c5c2d7886a47da93885d"),
        "context": "sha256:e8f5edbfdbb267a48b402ac87b416b6f574a07f3ec163c8ea74e927c5c35a85b",
    },
    ("win32", (3, 13, 5)): {
        "target": "windows/amd64",
        "receiver": "pathlib._local.WindowsPath",
        "method": "PathBase.write_bytes",
        "members": (
            ("definition", "pathlib/_abc.py", "sha256:e37c70955985422905b5ea77572f2e89b5bd45465f5d83a13e35bbc409f603c2"),
            ("receiver", "pathlib/_local.py", "sha256:f50e14b22650d169b2a4a33d71f8cee5546a306ddc38a5179aa3ec5a41bb1983"),
        ),
        "entry": ("pathlib/__init__.py", "sha256:62b3b842bda77ca6245f8c8657b8c72540e383fb9aa70e4c3a705947cc8611fd"),
        "context": "sha256:e7fd36144d77040e4b15d5804817c959d91e5864426eb1a87083b5f346f37fb2",
    },
}


class Refuse(Exception):
    """A fixed reason code. No repository or host path is emitted."""


def stamp(data):
    return "sha256:" + sha256(data).hexdigest()


def exact(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def publish(record):
    raw = exact(record) + b"\n"
    if len(raw) > MAX_FRAME:
        raise Refuse("FRAME_LIMIT")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def plain(path):
    found = path.lstat()
    reparse = getattr(found, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    if stat.S_ISLNK(found.st_mode) or reparse:
        raise Refuse("LINKED_HOST_ASSET")
    return found


def identity(found):
    # CPython on Windows reports different ctime semantics for the open
    # handle and the named entry. Both expose the same native birth time.
    changed = found.st_birthtime_ns if sys.platform == "win32" else found.st_ctime_ns
    return found.st_dev, found.st_ino, found.st_mode, found.st_size, found.st_mtime_ns, changed


def ordinary_bytes(path, maximum):
    if not path.is_absolute():
        raise Refuse("UNBOUND_HOST_PATH")
    for parent in path.parents:
        if not stat.S_ISDIR(plain(parent).st_mode):
            raise Refuse("INVALID_HOST_DIRECTORY")
    before = plain(path)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise Refuse("INVALID_HOST_MEMBER")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise Refuse("HOST_MEMBER_CHANGED")
        raw = stream.read(maximum + 1)
        if (len(raw) != before.st_size or identity(os.fstat(stream.fileno())) != identity(before)
                or identity(plain(path)) != identity(before)):
            raise Refuse("HOST_MEMBER_CHANGED")
    return raw


def host_member(path, pin, maximum=MAX_MEMBER):
    raw = ordinary_bytes(path, maximum)
    if stamp(raw) != pin:
        raise Refuse("HOST_MEMBER_BINDING_MISMATCH")
    return raw


def loaded_path(path, expected):
    if not path or pathlib.Path(path) != expected:
        raise Refuse("STDLIB_ORIGIN_MISMATCH")


def nested_code(code, qualname):
    pending = [code]
    matches = []
    while pending:
        current = pending.pop()
        if current.co_qualname == qualname:
            matches.append(current)
        pending.extend(value for value in current.co_consts if isinstance(value, CodeType))
    if len(matches) != 1:
        raise Refuse("STDLIB_DEFINITION_UNESTABLISHED")
    return matches[0]


def installed_receiver():
    # The isolated host is independently selected. Neither request fields nor
    # a project path can select an installed file, module, or import route.
    profile = PLATFORMS.get((sys.platform, sys.version_info[:3]))
    if profile is None or sys.maxsize != 9223372036854775807:
        raise Refuse("STDLIB_CONTEXT_UNAVAILABLE")
    amd64 = (os.uname().machine == "x86_64" if sys.platform == "linux"
             else sys.version.endswith("64 bit (AMD64)]"))
    if not amd64:
        raise Refuse("STDLIB_CONTEXT_UNAVAILABLE")

    stdlib = pathlib.Path(ast.__file__).parent
    entry_path, entry_ref = profile["entry"]
    loaded_path(pathlib.__file__, stdlib / entry_path)
    host_member(stdlib / entry_path, entry_ref)
    method = pathlib.Path.write_bytes
    concrete = type(pathlib.Path("."))
    if (concrete.__module__ + "." + concrete.__qualname__ != profile["receiver"]
            or concrete.write_bytes is not method or method.__qualname__ != profile["method"]):
        raise Refuse("STDLIB_RECEIVER_UNESTABLISHED")

    (definition_role, definition_path, definition_ref), (receiver_role, receiver_path, receiver_ref) = profile["members"]
    loaded_path(inspect.getsourcefile(method), stdlib / definition_path)
    loaded_path(inspect.getsourcefile(pathlib.Path), stdlib / receiver_path)
    source = host_member(stdlib / definition_path, definition_ref)
    host_member(stdlib / receiver_path, receiver_ref)
    compiled = compile(source, method.__code__.co_filename, "exec", dont_inherit=True, optimize=0)
    # Existing compiled method identity must match the independently pinned
    # source. A same-named method or an unrelated cached code object cannot bind.
    if nested_code(compiled, profile["method"]) != method.__code__:
        raise Refuse("STDLIB_COMPILED_DEFINITION_MISMATCH")

    members = [[definition_role, definition_path, definition_ref],
               [receiver_role, receiver_path, receiver_ref]]
    context = stamp(exact(members))
    if context != profile["context"]:
        raise Refuse("STDLIB_CONTEXT_BINDING_MISMATCH")
    return {
        "context_ref": context,
        "version": ".".join(map(str, sys.version_info[:3])),
        "target": profile["target"],
        "features": ["isolated", "no-site"],
        "receiver": profile["receiver"],
        "definition_symbol": profile["method"],
        "members": members,
        "entry_ref": entry_ref,
    }


def prepare(args):
    expected = ["--worker-ref", "--bootstrap-ref", "--runtime-ref"]
    if (len(args) != 7 or args[0] != "--serve" or args[1::2] != expected
            or not all(REF.fullmatch(value) for value in args[2::2])):
        raise Refuse("UNSUPPORTED_INVOCATION")
    pins = dict(zip(PINS, args[2::2], strict=True))
    if pins["bootstrap_ref"] != BOOTSTRAP:
        raise Refuse("BOOTSTRAP_BINDING_MISMATCH")
    worker = pathlib.Path(__file__)
    bootstrap = worker.with_name("python_lexical_worker.py")
    support = host_member(bootstrap, BOOTSTRAP, MAX_BOOTSTRAP)
    host_member(worker, pins["worker_ref"], MAX_BOOTSTRAP)
    tool = {"__name__": "_fortress_pinned_filesystem_bootstrap", "__file__": str(bootstrap)}
    exec(compile(support, "<fortress-pinned-bootstrap>", "exec", dont_inherit=True, optimize=0), tool)
    try:
        profile, limits = tool["source_gate"]()
        if stamp(tool["exact_json"](tool["runtime"]())) != pins["runtime_ref"]:
            raise Refuse("RUNTIME_BINDING_MISMATCH")
    except tool["Refuse"] as error:
        raise Refuse("RESOURCE_PROFILE_UNAVAILABLE") from error
    receiver = installed_receiver()
    publish({
        "schema": READY, "status": "READY", "profile": profile, "limits": limits,
        "grammar": f"cpython{sys.version_info.major}.{sys.version_info.minor}",
        "stdlib_receiver": receiver, **pins,
    })
    return tool, pins, receiver


def load_request(tool, pins):
    frame = sys.stdin.buffer.read(MAX_REQUEST + 1)
    if len(frame) > MAX_REQUEST:
        raise Refuse("REQUEST_LIMIT")
    try:
        request = json.loads(frame, object_pairs_hook=tool["duplicate_free"], parse_constant=tool["no_constant"])
    except (ValueError, RecursionError, tool["Refuse"]) as error:
        raise Refuse("MALFORMED_REQUEST") from error
    if (not isinstance(request, dict) or set(request) != FIELDS
            or request["schema"] != REQUEST or not all(request[key] == pins[key] for key in PINS)
            or not isinstance(request["id"], str) or not tool["ID"].fullmatch(request["id"])
            or not isinstance(request["function"], str) or not IDENT.fullmatch(request["function"])):
        raise Refuse("MALFORMED_REQUEST")
    path = request["source_path"]
    if (not isinstance(path, str) or len(path) > 240 or not path.endswith(".py")
            or not all(PATH_PART.fullmatch(part) and not part.endswith(".") for part in path.split("/"))
            or path.split("/")[0].lower() in (".git", "__fortress")):
        raise Refuse("INVALID_SOURCE_PATH")
    size = request["byte_count"]
    if type(size) is not int or not 0 < size <= MAX_SOURCE:
        raise Refuse("SOURCE_LIMIT")
    try:
        source = base64.b64decode(request["source"], validate=True)
    except (TypeError, ValueError) as error:
        raise Refuse("MALFORMED_REQUEST") from error
    if (len(source) != size or stamp(source) != request["source_ref"]
            or base64.b64encode(source).decode("ascii") != request["source"]):
        raise Refuse("SOURCE_BINDING_MISMATCH")
    return request, source


def location(node, raw, tool):
    physical = raw.split(b"\n")
    lines = [line.removesuffix(b"\r") for line in physical]
    line, start, end_line, end = tool["span"](node, lines)
    first = sum(len(value) + 1 for value in physical[:line - 1])
    last = sum(len(value) + 1 for value in physical[:end_line - 1])
    return [first + start, last + end]


def classify(tree, root_scope, function, raw, tool):
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == function]
    if len(functions) != 1:
        reason = "MISSING_FUNCTION" if not functions else "AMBIGUOUS_FUNCTION"
        return "UNAVAILABLE", reason, None
    selected = functions[0]
    calls = [
        node.value for node in selected.body
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "write_bytes"
    ]
    if len(calls) != 1:
        return "UNAVAILABLE", "DIRECT_RETURN_CALL_UNESTABLISHED", None
    target = calls[0]
    site = location(target, raw, tool)
    receiver = target.func.value
    if not isinstance(receiver, ast.Call) or not isinstance(receiver.func, ast.Name):
        return "UNRESOLVED", "INDIRECT_RECEIVER", site

    local_name = receiver.func.id
    scopes = [scope for scope in root_scope.get_children()
              if scope.get_name() == function and scope.get_lineno() == selected.lineno]
    if len(scopes) != 1:
        return "UNRESOLVED", "LEXICAL_SCOPE_UNESTABLISHED", site
    binding = scopes[0].lookup(local_name)
    if binding.is_local():
        return "LOCAL_OR_SHADOWED", None, site
    if len(tree.body) != 2 or tree.body[1] is not selected:
        return "UNRESOLVED", "MODULE_FORM_UNSUPPORTED", site
    imported = tree.body[0]
    if (not isinstance(imported, ast.ImportFrom) or imported.level != 0 or imported.module != "pathlib"
            or len(imported.names) != 1 or imported.names[0].name != "Path"
            or (imported.names[0].asname or "Path") != local_name
            or not root_scope.lookup(local_name).is_imported() or not binding.is_global()):
        return "UNRESOLVED", "IMPORT_BINDING_UNESTABLISHED", site
    left, right = location(receiver.func, raw, tool)
    member_left, member_right = location(target.func, raw, tool)
    import_left, import_right = location(imported, raw, tool)
    declaration_left, declaration_right = location(selected, raw, tool)
    declaration = raw[declaration_left:declaration_right]
    exact_function = rb"(?:async[ \t]+)?def[ \t]+" + function.encode("ascii") + rb"[ \t]*\("
    if (raw[left:right] != local_name.encode("ascii", "replace")
            or not raw[member_left:member_right].endswith(b".write_bytes")
            or not IMPORT.fullmatch(raw[import_left:import_right])
            or not re.match(exact_function, declaration)):
        return "UNRESOLVED", "NONCANONICAL_BINDING_SPELLING", site

    if (target.keywords or receiver.keywords or len(receiver.args) != 1 or len(target.args) != 1
            or not isinstance(receiver.args[0], ast.Constant) or type(receiver.args[0].value) is not str
            or not isinstance(target.args[0], ast.Constant) or type(target.args[0].value) is not bytes
            or not receiver.args[0].value or len(receiver.args[0].value) > 256
            or any(ord(char) < 32 for char in receiver.args[0].value)
            or len(target.args[0].value) > 512):
        return "UNRESOLVED", "DYNAMIC_ARGUMENT", site
    args = selected.args
    if (not isinstance(selected, ast.FunctionDef) or selected.decorator_list or selected.returns
            or selected.type_params or args.posonlyargs or args.args or args.kwonlyargs
            or args.vararg or args.kwarg or len(selected.body) != 1):
        return "UNRESOLVED", "FUNCTION_FORM_UNSUPPORTED", site
    return "CLOSED_LITERAL_SHAPE", None, site


def observe(request, source, tool):
    try:
        text = tool["source_text"](source)
        filename = "<fortress-python-filesystem-source>"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tool["check_tokens"](text)
            tree = ast.parse(text, filename=filename, mode="exec")
            tool["check_ast"](tree)
            compile(text, filename, "exec", dont_inherit=True, optimize=0)
            root_scope = symtable.symtable(text, filename, "exec")
        return classify(tree, root_scope, request["function"], source, tool)
    except (ValueError, SyntaxError, RecursionError, tool["Refuse"]):
        return "UNAVAILABLE", "INADMISSIBLE_SOURCE", None


def main():
    try:
        tool, pins, receiver = prepare(sys.argv[1:])
    except (Refuse, ImportError, OSError, ValueError, MemoryError) as error:
        reason = str(error) if isinstance(error, Refuse) else type(error).__name__
        publish({"schema": READY, "status": "UNAVAILABLE", "reason": reason})
        return 3

    try:
        request, source = load_request(tool, pins)
        status, reason, site = observe(request, source, tool)
        if installed_receiver() != receiver:
            raise Refuse("STDLIB_CONTEXT_CHANGED")
        keys = ("id", "source_ref", "source_path", "byte_count", "function", *PINS)
        publish({
            "schema": RESPONSE, "status": status, "reason": reason, "site": site,
            "installed_context_ref": receiver["context_ref"], "target_execution": "NOT_RUN",
            "project_runtime_import_binding": "UNESTABLISHED", "effect_projection": "NOT_PERFORMED",
            **{key: request[key] for key in keys},
        })
        return 0
    except (Refuse, ImportError, OSError, ValueError, MemoryError) as error:
        reason = str(error) if isinstance(error, Refuse) else type(error).__name__
        publish({"schema": RESPONSE, "status": "REFUSED", "reason": reason})
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
