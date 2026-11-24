"""Collect bounded compile-only Python scalar, control-flow and lexical call facts."""

import sys

if (sys.implementation.name != "cpython" or sys.version_info[:2] not in ((3, 12), (3, 13))
        or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
        or sys.flags.optimize):
    raise SystemExit(3)

import ast
import base64
import json
from pathlib import Path
import re
import warnings


REQUEST = "fortress:python:scalar-request:1"
RESPONSE = "fortress:python:scalar-response:1"
READY = "fortress-host/python-scalar-ready/1"
CALL_REQUEST = "fortress:python:lexical-call-request:1"
CALL_RESPONSE = "fortress:python:lexical-call-response:1"
CALL_READY = "fortress-host/python-lexical-call-ready/1"
BOOTSTRAP_REF = "sha256:19ca652a6ed8908d128ac231da47b45d0b0a86a9baffaff9626fb2d1609c9836"
MAX_BOOTSTRAP_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 32 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_UNITS = 256
MAX_DEPTH = 20
MAX_BOOLEAN_RETURN_OPERANDS = 4
MAX_PARAMS = 8
MAX_CALL_PARAMS = 4
MAX_HELPERS = 16
MAX_MODULE_DEFINITIONS = 16
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
PATH_PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
REF = re.compile(r"sha256:[0-9a-f]{64}\Z")
SOURCE_KEYS = {"schema", "id", "source", "byte_count", "source_ref", "source_path",
               "function", "parameter_domains", "worker_ref", "bootstrap_ref", "runtime_ref"}
PIN_KEYS = ["worker_ref", "bootstrap_ref", "runtime_ref"]
MODULE_VALUE_KINDS = (ast.List, ast.Dict, ast.Set, ast.Tuple, ast.Attribute, ast.Subscript,
                      ast.NamedExpr, ast.Lambda, ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)
COMPARISON_OPERATORS = {
    ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
}


class Refuse(Exception):
    def __init__(self, code, node=None):
        super().__init__(code)
        self.code = code
        self.node = node


def exact(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def publish(value):
    payload = exact(value) + b"\n"
    if len(payload) > MAX_RESPONSE_BYTES:
        raise Refuse("OUTPUT_LIMIT")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def chosen_pins(args):
    if len(args) != 7 or args[0] not in ("--serve", "--serve-calls"):
        raise Refuse("UNSUPPORTED_INVOCATION")
    expected_flags = ["--worker-ref", "--bootstrap-ref", "--runtime-ref"]
    if args[1::2] != expected_flags or not all(REF.fullmatch(value) for value in args[2::2]):
        raise Refuse("UNSUPPORTED_INVOCATION")
    return dict(zip(PIN_KEYS, args[2::2], strict=True))


def trusted_bootstrap(expected):
    # Open the reviewed sibling only, verify the complete bytes, then load those
    # in memory. No request bytes, request name or project path enter startup.
    from hashlib import sha256

    sibling = Path(__file__).with_name("python_lexical_worker.py")
    with sibling.open("rb") as stream:
        code = stream.read(MAX_BOOTSTRAP_BYTES + 1)
    if expected != BOOTSTRAP_REF or len(code) > MAX_BOOTSTRAP_BYTES or "sha256:" + sha256(code).hexdigest() != expected:
        raise Refuse("BOOTSTRAP_BINDING_MISMATCH")
    tool = {"__name__": "_fortress_pinned_scalar_bootstrap", "__file__": str(sibling)}
    exec(compile(code, "<fortress-pinned-bootstrap>", "exec", dont_inherit=True, optimize=0), tool)
    return tool


def prepare(args, with_calls):
    pins = chosen_pins(args)
    tool = trusted_bootstrap(pins["bootstrap_ref"])
    try:
        profile, limits = tool["source_gate"]()
    except tool["Refuse"] as error:
        raise Refuse("RESOURCE_PROFILE_UNAVAILABLE") from error
    if tool["hash_file"](Path(__file__)) != pins["worker_ref"]:
        raise Refuse("WORKER_BINDING_MISMATCH")
    if tool["stamp"](tool["exact_json"](tool["runtime"]())) != pins["runtime_ref"]:
        raise Refuse("RUNTIME_BINDING_MISMATCH")
    publish({"schema": CALL_READY if with_calls else READY, "status": "READY", "grammar": f"cpython{sys.version_info.major}.{sys.version_info.minor}",
             "profile": profile, "limits": limits, **pins})
    return tool, pins


def load_request(tool, pins, with_calls):
    payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(payload) > MAX_REQUEST_BYTES:
        raise Refuse("INPUT_LIMIT")
    try:
        record = json.loads(payload, object_pairs_hook=tool["duplicate_free"], parse_constant=tool["no_constant"])
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refuse("MALFORMED_INPUT") from error
    schema = CALL_REQUEST if with_calls else REQUEST
    if not isinstance(record, dict) or set(record) != SOURCE_KEYS or record["schema"] != schema:
        raise Refuse("MALFORMED_INPUT")
    if any(record[key] != pins[key] for key in PIN_KEYS):
        raise Refuse("INPUT_PIN_MISMATCH")
    if not isinstance(record["id"], str) or not tool["ID"].fullmatch(record["id"]):
        raise Refuse("MALFORMED_INPUT")
    if not isinstance(record["function"], str) or not IDENT.fullmatch(record["function"]):
        raise Refuse("INVALID_FUNCTION_SELECTOR")
    path = record["source_path"]
    if (not isinstance(path, str) or len(path) > 240 or not path.endswith(".py")
            or not all(PATH_PART.fullmatch(piece) and not piece.endswith(".") for piece in path.split("/"))
            or path.split("/")[0].lower() in ("__fortress", ".git")):
        raise Refuse("INVALID_SOURCE_PATH")
    if (not isinstance(record["parameter_domains"], list)
            or len(record["parameter_domains"]) > (MAX_CALL_PARAMS if with_calls else MAX_PARAMS)
            or any(item != "BOOL" for item in record["parameter_domains"])):
        raise Refuse("PARAMETER_DOMAIN_UNAVAILABLE")
    count = record["byte_count"]
    if type(count) is not int or not 0 < count <= MAX_SOURCE_BYTES:
        raise Refuse("INPUT_LIMIT")
    try:
        raw = base64.b64decode(record["source"], validate=True)
    except (TypeError, ValueError) as error:
        raise Refuse("MALFORMED_INPUT") from error
    if (len(raw) != count or tool["stamp"](raw) != record["source_ref"]
            or base64.b64encode(raw).decode("ascii") != record["source"]):
        raise Refuse("SOURCE_BINDING_MISMATCH")
    return record, raw


class Source:
    def __init__(self, path, raw, tool):
        self.path = path
        self.raw = raw
        self.lines = raw.split(b"\n")
        self.normal_lines = [line[:-1] if line.endswith(b"\r") else line for line in self.lines]
        self.starts = [0]
        for line in self.lines[:-1]:
            self.starts.append(self.starts[-1] + len(line) + 1)
        self.check_span = tool["span"]

    def location(self, line, col, end):
        return {"path": self.path, "start_byte": self.starts[line - 1] + col, "end_byte": end,
                "start_line": line, "start_byte_column": col + 1}

    def node(self, node):
        line, col, last, end = self.check_span(node, self.normal_lines)
        return self.location(line, col, self.starts[last - 1] + end)

    def symbol(self, node):
        if IDENT.fullmatch(node.name):
            line, col = node.lineno, node.col_offset
            text = self.normal_lines[line - 1]
            match = re.match(rb"def[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b", text[col:])
            if match and match.group(1).decode("ascii") == node.name:
                start = col + match.start(1)
                end = self.starts[line - 1] + col + match.end(1)
                return {"name": node.name, "span": self.location(line, start, end),
                        "declaration_span": self.node(node)}
        raise Refuse("IDENTIFIER_SPELLING_UNSUPPORTED", node)

    def name(self, identifier, node):
        span = self.node(node)
        literal = self.raw[span["start_byte"]:span["end_byte"]]
        if not IDENT.fullmatch(identifier) or literal != identifier.encode("ascii"):
            raise Refuse("IDENTIFIER_SPELLING_UNSUPPORTED", node)
        return span


class Lower:
    def __init__(self, source, parameters, callees=None):
        self.source = source
        self.callees = callees
        self.parameters = dict.fromkeys(parameters, "BOOL")
        self.locals = {}
        self.result = None
        self.units = 0

    def charge(self, node, depth):
        self.units += 1
        if self.units > MAX_UNITS or depth > MAX_DEPTH:
            raise Refuse("SCALAR_COMPLEXITY_LIMIT", node)

    def integer(self, value, node):
        if not -(2 ** 31) <= value < 2 ** 31:
            raise Refuse("INTEGER_RANGE_UNSUPPORTED", node)
        return "INTEGER_LITERAL", {"kind": "integer", "value": str(value)}

    def expression(self, node, initialized, depth):
        self.charge(node, depth)
        if isinstance(node, ast.Constant):
            if type(node.value) is bool:
                return "BOOL", {"kind": "boolean", "value": node.value}
            if type(node.value) is int:
                return self.integer(node.value, node)
            raise Refuse("EXPRESSION_UNSUPPORTED", node)
        if isinstance(node, ast.Name):
            self.source.name(node.id, node)
            if node.id in initialized:
                return initialized[node.id], {"kind": "binding", "name": node.id}
            raise Refuse("BINDING_UNAVAILABLE", node)
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                scalar, row = self.expression(node.operand, initialized, depth + 1)
                if scalar != "BOOL":
                    raise Refuse("TRUTH_CONVERSION_UNSUPPORTED", node)
                return scalar, {"kind": "unary", "operator": "!", "value": row}
            if isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) and type(node.operand.value) is int:
                return self.integer(-node.operand.value, node)
            raise Refuse("INTEGER_OPERATION_UNSUPPORTED", node)
        if isinstance(node, ast.Compare):
            return self.comparison(node, initialized, depth)
        if isinstance(node, ast.Call):
            return self.call(node, initialized, depth)
        if isinstance(node, ast.BinOp):
            raise Refuse("INTEGER_OPERATION_UNSUPPORTED", node)
        if isinstance(node, MODULE_VALUE_KINDS):
            raise Refuse("OBJECT_OR_ALIAS_UNSUPPORTED", node)
        raise Refuse("EXPRESSION_UNSUPPORTED", node)

    def call(self, node, initialized, depth):
        if self.callees is None:
            raise Refuse("CALL_UNSUPPORTED", node)
        if not isinstance(node.func, ast.Name) or node.func.id not in self.callees:
            raise Refuse("CALL_TARGET_UNESTABLISHED", node)
        self.source.name(node.func.id, node.func)
        target, count = self.callees[node.func.id]
        if node.keywords or len(node.args) != count:
            raise Refuse("CALL_ARGUMENTS_UNSUPPORTED", node)
        arguments = []
        for item in node.args:
            scalar, expression = self.expression(item, initialized, depth + 1)
            if scalar != "BOOL":
                raise Refuse("CALL_ARGUMENTS_UNSUPPORTED", item)
            arguments.append(expression)
        return "BOOL", {"kind": "call", "call": {
            "target": target, "span": self.source.node(node), "arguments": arguments,
        }}

    def comparison(self, node, initialized, depth):
        if len(node.ops) != 1:
            raise Refuse("COMPARISON_FORM_UNSUPPORTED", node)
        operator = COMPARISON_OPERATORS.get(type(node.ops[0]))
        if operator is None:
            raise Refuse("COMPARISON_FORM_UNSUPPORTED", node)
        left_type, left = self.expression(node.left, initialized, depth + 1)
        right_type, right = self.expression(node.comparators[0], initialized, depth + 1)
        if left_type != right_type or (left_type == "BOOL" and operator not in ("==", "!=")):
            raise Refuse("COMPARISON_TYPES_UNSUPPORTED", node)
        return "BOOL", {"kind": "binary", "operator": operator, "left": left, "right": right}

    def assign(self, node, init, depth):
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            raise Refuse("OBJECT_OR_ALIAS_UNSUPPORTED", node)
        target = node.targets[0]
        if target.id in self.parameters:
            raise Refuse("PARAMETER_REASSIGNMENT_UNSUPPORTED", target)
        scalar, value = self.expression(node.value, init, depth + 1)
        name = {"name": target.id, "scalar": scalar, "span": self.source.name(target.id, target)}
        known = self.locals.setdefault(target.id, name)
        if known["scalar"] != scalar:
            raise Refuse("SCALAR_KIND_CONFLICT", target)
        init[target.id] = scalar
        return {"kind": "assign", "target": target.id, "value": value}

    def boolean_return(self, node, init, depth):
        self.charge(node, depth)
        if len(node.values) > MAX_BOOLEAN_RETURN_OPERANDS:
            raise Refuse("SCALAR_COMPLEXITY_LIMIT", node)
        evaluated = []
        for operand in node.values:
            scalar, value = self.expression(operand, init, depth + 1)
            if scalar != "BOOL":
                raise Refuse("TRUTH_CONVERSION_UNSUPPORTED", operand)
            evaluated.append((operand, value))
        final, value = evaluated[-1]
        branch = {"kind": "return", "span": self.source.node(final), "value": value}
        short_value = isinstance(node.op, ast.Or)
        end_byte = self.source.node(node)["end_byte"]
        for operand, condition in reversed(evaluated[:-1]):
            left = self.source.node(operand)
            if not short_value:
                condition = {"kind": "unary", "operator": "!", "value": condition}
            short = {"kind": "return", "span": left, "value": {"kind": "boolean", "value": short_value}}
            branch = {"kind": "if", "span": {**left, "end_byte": end_byte},
                      "condition": condition, "then_branch": [short], "else_branch": [branch]}
        return branch

    def returned(self, node, init, depth):
        if node.value is None:
            raise Refuse("RETURN_REQUIRED_SCALAR", node)
        if isinstance(node.value, ast.BoolOp):
            scalar = "BOOL"
            row = self.boolean_return(node.value, init, depth + 1)
        else:
            scalar, value = self.expression(node.value, init, depth + 1)
            row = {"kind": "return", "value": value}
        if self.result is not None and self.result != scalar:
            raise Refuse("SCALAR_KIND_CONFLICT", node)
        self.result = scalar
        return row

    def branches(self, node, init, depth):
        scalar, condition = self.expression(node.test, init, depth + 1)
        if scalar != "BOOL":
            raise Refuse("TRUTH_CONVERSION_UNSUPPORTED", node.test)
        left, then_init = self.block(node.body, init.copy(), depth + 1)
        right, else_init = self.block(node.orelse, init.copy(), depth + 1)
        if then_init is None or else_init is None:
            joined = then_init if else_init is None else else_init
        else:
            joined = {name: kind for name, kind in then_init.items() if else_init.get(name) == kind}
        return {"kind": "if", "condition": condition, "then_branch": left, "else_branch": right}, joined

    def block(self, statements, init, depth=0):
        rows = []
        for node in statements:
            self.charge(node, depth)
            if init is None:
                raise Refuse("UNREACHABLE_FORM_UNSUPPORTED", node)
            if isinstance(node, ast.Assign):
                row = self.assign(node, init, depth)
            elif isinstance(node, ast.Return):
                row, init = self.returned(node, init, depth), None
            elif isinstance(node, ast.If):
                row, init = self.branches(node, init, depth)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                raise Refuse("CALL_UNSUPPORTED", node)
            else:
                raise Refuse("STATEMENT_UNSUPPORTED", node)
            rows.append({**row, "span": self.source.node(node)})
        return rows, init


def function_signature(function, source, name, report, expected_count=None):
    if not isinstance(function, ast.FunctionDef) or function.name != name:
        raise Refuse("FUNCTION_FORM_UNSUPPORTED", function)
    if function.decorator_list or function.returns or function.type_params:
        raise Refuse("FUNCTION_FORM_UNSUPPORTED", function)
    report["symbol"] = source.symbol(function)
    args = function.args
    params = args.posonlyargs + args.args
    if (args.vararg or args.kwarg or args.kwonlyargs or args.defaults
            or any(param.annotation or param.type_comment for param in params)):
        raise Refuse("FUNCTION_FORM_UNSUPPORTED", function)
    if expected_count is not None and len(params) != expected_count:
        raise Refuse("PARAMETER_DOMAIN_UNAVAILABLE", function)
    if not all(IDENT.fullmatch(param.arg) for param in params):
        raise Refuse("IDENTIFIER_SPELLING_UNSUPPORTED", function)
    return [{"name": param.arg, "scalar": "BOOL", "span": source.name(param.arg, param)}
            for param in params]


def lower_body(function, source, statements, parameters, report, callees=None):
    analysis = Lower(source, [row["name"] for row in parameters], callees)
    body, after = analysis.block(statements, analysis.parameters.copy())
    if after is not None or analysis.result is None:
        raise Refuse("FALLTHROUGH_UNSUPPORTED", function)
    report.update(status="LOWERABLE", result_scalar=analysis.result,
                  parameters=parameters, locals=list(analysis.locals.values()), body=body)


def describe_function(function, source, request, report):
    parameters = function_signature(function, source, request["function"], report,
                                    len(request["parameter_domains"]))
    lower_body(function, source, function.body, parameters, report)


def describe_lexical_calls(function, source, request, report, top_scope):
    parameters = function_signature(function, source, request["function"], report,
                                    len(request["parameter_domains"]))
    namespaces = top_scope.lookup(function.name).get_namespaces()
    if len(namespaces) != 1 or namespaces[0].get_lineno() != function.lineno:
        raise Refuse("LEXICAL_SCOPE_UNESTABLISHED", function)
    outer = namespaces[0]
    if outer.get_frees():
        raise Refuse("LEXICAL_SCOPE_UNESTABLISHED", function)
    helpers = []
    for node in function.body:
        if not isinstance(node, ast.FunctionDef):
            break
        helpers.append(node)
    if len(helpers) > MAX_HELPERS:
        raise Refuse("CALLABLE_COUNT_LIMIT", function)
    statements = function.body[len(helpers):]
    names = {node.name for node in helpers}
    if len(names) != len(helpers) or names.intersection(row["name"] for row in parameters):
        raise Refuse("CALL_TARGET_UNESTABLISHED", function)
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, ast.Name) and node.id in names and not isinstance(node.ctx, ast.Load):
                raise Refuse("CALL_TARGET_UNESTABLISHED", node)

    callees, declarations = {}, []
    for helper in helpers:
        symbol = outer.lookup(helper.name)
        definitions = symbol.get_namespaces()
        if (not symbol.is_local() or symbol.is_global() or symbol.is_nonlocal()
                or len(definitions) != 1 or definitions[0].get_lineno() != helper.lineno):
            raise Refuse("LEXICAL_SCOPE_UNESTABLISHED", helper)
        definition = definitions[0]
        free = definition.get_frees()
        if not names.issuperset(free) or any(definition.lookup(name).is_nonlocal() for name in free):
            raise Refuse("LEXICAL_SCOPE_UNESTABLISHED", helper)
        body = {}
        selected = function_signature(helper, source, helper.name, body)
        if len(selected) > MAX_CALL_PARAMS:
            raise Refuse("CALL_ARGUMENTS_UNSUPPORTED", helper)
        callees[helper.name] = (body["symbol"], len(selected))
        declarations.append((helper, selected, body, free))

    # The root calls only after all these ordinary definitions have bound their
    # cells. CPython's symbol table distinguishes captured names from shadows.
    bodies = []
    for helper, selected, body, free in declarations:
        targets = {name: callees[name] for name in free}
        lower_body(helper, source, helper.body, selected, body, targets)
        if body["result_scalar"] != "BOOL":
            raise Refuse("CALL_TARGET_SCALAR_UNSUPPORTED", helper)
        bodies.append(body)
    lower_body(function, source, statements, parameters, report, callees)
    report["helpers"] = bodies


def selected_module_function(statements, source, name):
    # Keep the single-statement diagnostic and source-span behavior.
    if len(statements) == 1:
        return statements[0]
    if not 2 <= len(statements) <= MAX_MODULE_DEFINITIONS:
        raise Refuse("MODULE_FORM_UNSUPPORTED")
    definitions = {}
    for statement in statements:
        if not isinstance(statement, ast.FunctionDef) or statement.name in definitions:
            raise Refuse("MODULE_FORM_UNSUPPORTED")
        # Definitions bind names when the module executes. Their bodies do
        # not run then, but defaults, decorators and annotations may run.
        function_signature(statement, source, statement.name, {})
        definitions[statement.name] = statement
    selected = definitions.get(name)
    if selected is None:
        raise Refuse("FUNCTION_FORM_UNSUPPORTED")
    return selected


def observe(tool, request, raw, report, with_calls):
    source = Source(request["source_path"], raw, tool)
    try:
        text = tool["source_text"](raw)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tool["check_tokens"](text)
            parsed = ast.parse(text, filename="<fortress-scalar-source>", mode="exec")
            tool["check_ast"](parsed)
            # Compile rejects contextual invalidity, without evaluating the resulting code.
            compile(text, "<fortress-scalar-source>", "exec", dont_inherit=True, optimize=0)
        function = selected_module_function(parsed.body, source, request["function"])
        if with_calls:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                scope = tool["symtable"].symtable(text, "<fortress-scalar-source>", "exec")
            describe_lexical_calls(function, source, request, report, scope)
        else:
            describe_function(function, source, request, report)
    except (SyntaxError, UnicodeError):
        report["diagnostic"] = {"code": "INVALID_SOURCE", "span": None}
    except Refuse as error:
        report["diagnostic"] = {
            "code": error.code, "span": source.node(error.node) if error.node else None,
        }
    except (tool["Refuse"], RecursionError, MemoryError):
        report["diagnostic"] = {"code": "CONTEXT_OR_RESOURCE_UNAVAILABLE", "span": None}


def main():
    with_calls = sys.argv[1:2] == ["--serve-calls"]
    ready_schema = CALL_READY if with_calls else READY
    response_schema = CALL_RESPONSE if with_calls else RESPONSE
    try:
        tool, pins = prepare(sys.argv[1:], with_calls)
    except (Refuse, OSError, ImportError, ValueError, MemoryError) as error:
        code = error.code if isinstance(error, Refuse) else "TRUST_OR_RESOURCE_UNAVAILABLE"
        publish({"schema": ready_schema, "status": "UNAVAILABLE", "reason": code})
        return 3
    try:
        request, raw = load_request(tool, pins, with_calls)
    except (Refuse, tool["Refuse"]) as error:
        code = error.code if isinstance(error, Refuse) else "MALFORMED_INPUT"
        publish({"schema": response_schema, "status": "UNAVAILABLE", "diagnostic": {"code": code, "span": None}})
        return 2
    bindings = {key: request[key] for key in (
        "id", "source_path", "source_ref", "byte_count", "function", "parameter_domains", *PIN_KEYS,
    )}
    report = {
        "schema": response_schema, **bindings, "target_execution": "NOT_RUN",
        "status": "UNAVAILABLE", "symbol": None, "parameters": [], "locals": [],
        "result_scalar": None, "body": [], "diagnostic": None,
    }
    if with_calls:
        report["helpers"] = []
    observe(tool, request, raw, report, with_calls)
    try:
        publish(report)
    except Refuse as error:
        report.update(status="UNAVAILABLE", parameters=[], locals=[], result_scalar=None, body=[],
                      diagnostic={"code": error.code, "span": None})
        if with_calls:
            report["helpers"] = []
        publish(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
