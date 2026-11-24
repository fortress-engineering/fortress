// Explicit native scalar-body projection for the existing closed Go collector.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"io"
	"os"
	"runtime"
	"strconv"
)

type statement struct {
	Kind       string          `json:"kind"`
	Span       sourceSpan      `json:"span"`
	Condition  *expression     `json:"condition,omitempty"`
	ThenBranch *[]statement    `json:"then_branch,omitempty"`
	ElseBranch *[]statement    `json:"else_branch,omitempty"`
	Target     string          `json:"target,omitempty"`
	Pattern    *bindingPattern `json:"pattern,omitempty"`
	Value      *expression     `json:"value,omitempty"`
}

type bindingPattern struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type expression struct {
	Kind     string      `json:"kind"`
	Name     string      `json:"name,omitempty"`
	Operator string      `json:"operator,omitempty"`
	Value    any         `json:"value,omitempty"`
	Left     *expression `json:"left,omitempty"`
	Right    *expression `json:"right,omitempty"`
}

type identifier struct {
	Name string     `json:"name"`
	Span sourceSpan `json:"span"`
}

type bodySymbol struct {
	identifier
	DeclarationSpan sourceSpan `json:"declaration_span"`
}

type scalarBinding struct {
	identifier
	Scalar string `json:"scalar"`
}

type bodyObservation struct {
	Symbol       *bodySymbol     `json:"symbol,omitempty"`
	Status       string          `json:"status"`
	Diagnostic   *diagnostic     `json:"diagnostic,omitempty"`
	Parameters   []scalarBinding `json:"parameters"`
	ResultScalar string          `json:"result_scalar,omitempty"`
	Locals       []scalarBinding `json:"locals"`
	Body         []statement     `json:"body"`
}

type firstOrderReceipt struct {
	Version    int               `json:"schema_version"`
	Producer   string            `json:"producer"`
	Toolchain  string            `json:"go_toolchain"`
	RequestSHA string            `json:"request_sha256"`
	Inventory  []identity        `json:"source_inventory"`
	Status     string            `json:"status"`
	Diagnostic *diagnostic       `json:"diagnostic,omitempty"`
	Functions  []bodyObservation `json:"functions"`
}

type observedBody struct {
	info         *types.Info
	positions    *token.FileSet
	resultScalar string
	names        map[string]bool
	objects      map[types.Object]scalarBinding
	locals       []scalarBinding
	depth        int
	nodes        int
}

const bodyProducer = "fortress.go-bodies@0.1.0"
const scalarBool = "BOOL"
const scalarInt64 = "SIGNED_I64"
const maxBodyBindings = 128
const maxBodyDepth = 10
const maxBodyNodes = 256
const maxBodyRows = 1024

func bodyIdentifier(name string) bool {
	if name == "" || name == "_" {
		return false
	}
	for index, byteValue := range []byte(name) {
		if !(byteValue == '_' || byteValue >= 'a' && byteValue <= 'z' ||
			byteValue >= 'A' && byteValue <= 'Z' || index > 0 && byteValue >= '0' && byteValue <= '9') {
			return false
		}
	}
	return true
}

func goScalar(typ types.Type) string {
	switch typ {
	case types.Typ[types.Bool]:
		return scalarBool
	case types.Typ[types.Int64]:
		return scalarInt64
	default:
		return ""
	}
}

func (state *observedBody) error(node ast.Node, code string) *diagnostic {
	location := span(state.positions, node.Pos(), node.End())
	return &diagnostic{Code: code, Span: &location}
}

func (state *observedBody) admitNode(node ast.Node) *diagnostic {
	state.nodes++
	if state.nodes > maxBodyNodes || state.depth >= maxBodyDepth {
		return state.error(node, "GO_SCALAR_BODY_LIMIT")
	}
	return nil
}

func (state *observedBody) add(obj types.Object, node ast.Node) (scalarBinding, *diagnostic) {
	if obj == nil {
		return scalarBinding{}, state.error(node, "UNBOUND_OR_NONLOCAL_VALUE")
	}
	name := obj.Name()
	if name == "" {
		return scalarBinding{}, state.error(node, "IDENTIFIER_OUTSIDE_ASCII_SCOPE")
	}
	if !bodyIdentifier(name) {
		location := span(state.positions, obj.Pos(), obj.Pos()+token.Pos(len(name)))
		return scalarBinding{}, &diagnostic{Code: "IDENTIFIER_OUTSIDE_ASCII_SCOPE", Span: &location}
	}
	if state.names[name] {
		return scalarBinding{}, state.error(node, "REPEATED_OR_SHADOWED_BINDING")
	}
	if len(state.objects) >= maxBodyBindings {
		return scalarBinding{}, state.error(node, "GO_SCALAR_BODY_LIMIT")
	}
	scalar := goScalar(obj.Type())
	if scalar == "" {
		return scalarBinding{}, state.error(node, "SCALAR_TYPE_UNAVAILABLE")
	}
	location := span(state.positions, obj.Pos(), obj.Pos()+token.Pos(len(name)))
	value := scalarBinding{identifier: identifier{name, location}, Scalar: scalar}
	state.names[name] = true
	state.objects[obj] = value
	return value, nil
}

func (state *observedBody) expr(node ast.Expr, expected string) (*expression, *diagnostic) {
	if refusal := state.admitNode(node); refusal != nil {
		return nil, refusal
	}
	state.depth++
	defer func() { state.depth-- }()

	info, present := state.info.Types[node]
	if !present || info.Type == nil {
		return nil, state.error(node, "TYPE_EVIDENCE_UNAVAILABLE")
	}
	if info.Value != nil {
		switch expected {
		case scalarBool:
			if info.Value.Kind() == constant.Bool && (info.Type == types.Typ[types.Bool] || info.Type == types.Typ[types.UntypedBool]) {
				return &expression{Kind: "boolean", Value: constant.BoolVal(info.Value)}, nil
			}
		case scalarInt64:
			if info.Value.Kind() == constant.Int && (info.Type == types.Typ[types.Int64] || info.Type == types.Typ[types.UntypedInt]) {
				if value, exact := constant.Int64Val(info.Value); exact {
					return &expression{Kind: "integer", Value: strconv.FormatInt(value, 10)}, nil
				}
			}
		}
		return nil, state.error(node, "EXACT_SCALAR_LITERAL_UNAVAILABLE")
	}
	if goScalar(info.Type) != expected && !(expected == scalarBool && info.Type == types.Typ[types.UntypedBool]) {
		return nil, state.error(node, "SCALAR_TYPE_UNAVAILABLE")
	}
	switch item := node.(type) {
	case *ast.Ident:
		binding, ok := state.objects[state.info.Uses[item]]
		if !ok || binding.Scalar != expected {
			return nil, state.error(node, "UNBOUND_OR_NONLOCAL_VALUE")
		}
		return &expression{Kind: "binding", Name: binding.Name}, nil
	case *ast.ParenExpr:
		return state.expr(item.X, expected)
	case *ast.UnaryExpr:
		if item.Op == token.NOT && expected == scalarBool {
			nested, refusal := state.expr(item.X, scalarBool)
			if refusal != nil {
				return nil, refusal
			}
			return &expression{Kind: "unary", Operator: "!", Value: nested}, nil
		}
		if expected == scalarInt64 {
			return nil, state.error(node, "RUNTIME_INTEGER_ARITHMETIC_UNAVAILABLE")
		}
	case *ast.BinaryExpr:
		if expected == scalarInt64 {
			return nil, state.error(node, "RUNTIME_INTEGER_ARITHMETIC_UNAVAILABLE")
		}
		return state.comparison(item)
	case *ast.CallExpr:
		return nil, state.error(node, "RUNTIME_CALL_OR_CONVERSION_UNAVAILABLE")
	}
	return nil, state.error(node, "EXPRESSION_SEMANTICS_UNAVAILABLE")
}

func (state *observedBody) comparison(node *ast.BinaryExpr) (*expression, *diagnostic) {
	switch node.Op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
	default:
		return nil, state.error(node, "EXPRESSION_SEMANTICS_UNAVAILABLE")
	}
	scalar := goScalar(state.info.Types[node.X].Type)
	if scalar == "" {
		scalar = goScalar(state.info.Types[node.Y].Type)
	}
	if scalar != scalarInt64 && (scalar != scalarBool || node.Op != token.EQL && node.Op != token.NEQ) {
		return nil, state.error(node, "EXPRESSION_SEMANTICS_UNAVAILABLE")
	}
	left, refusal := state.expr(node.X, scalar)
	if refusal != nil {
		return nil, refusal
	}
	right, refusal := state.expr(node.Y, scalar)
	if refusal != nil {
		return nil, refusal
	}
	return &expression{Kind: "binary", Operator: node.Op.String(), Left: left, Right: right}, nil
}

func (state *observedBody) block(items []ast.Stmt) ([]statement, *diagnostic) {
	statements := make([]statement, 0, len(items))
	for _, child := range items {
		result, refused := state.lower(child)
		if refused != nil {
			return nil, refused
		}
		statements = append(statements, result)
	}
	return statements, nil
}

func (state *observedBody) branch(node ast.Stmt) ([]statement, *diagnostic) {
	switch item := node.(type) {
	case nil:
		return []statement{}, nil
	case *ast.BlockStmt:
		return state.block(item.List)
	case *ast.IfStmt:
		return state.block([]ast.Stmt{item})
	default:
		return nil, state.error(node, "STATEMENT_SEMANTICS_UNAVAILABLE")
	}
}

func (state *observedBody) assignment(node *ast.AssignStmt, result statement) (statement, *diagnostic) {
	if len(node.Lhs) != 1 || len(node.Rhs) != 1 || (node.Tok != token.DEFINE && node.Tok != token.ASSIGN) {
		return result, state.error(node, "ASSIGNMENT_FORM_UNAVAILABLE")
	}
	name, ok := node.Lhs[0].(*ast.Ident)
	if !ok {
		return result, state.error(node, "ASSIGNMENT_PLACE_UNAVAILABLE")
	}
	if node.Tok == token.DEFINE {
		definition := state.info.Defs[name]
		if definition == nil {
			return result, state.error(name, "UNBOUND_OR_NONLOCAL_VALUE")
		}
		scalar := goScalar(definition.Type())
		if scalar == "" {
			return result, state.error(name, "SCALAR_TYPE_UNAVAILABLE")
		}
		value, refused := state.expr(node.Rhs[0], scalar)
		if refused != nil {
			return result, refused
		}
		bound, refused := state.add(definition, name)
		if refused != nil {
			return result, refused
		}
		state.locals = append(state.locals, bound)
		result.Kind = "let"
		result.Pattern = &bindingPattern{Kind: "binding", Name: bound.Name}
		result.Value = value
		return result, nil
	}
	binding, known := state.objects[state.info.Uses[name]]
	if !known {
		return result, state.error(name, "UNBOUND_OR_NONLOCAL_VALUE")
	}
	value, refused := state.expr(node.Rhs[0], binding.Scalar)
	if refused != nil {
		return result, refused
	}
	result.Kind, result.Target, result.Value = "assign", binding.Name, value
	return result, nil
}

func (state *observedBody) lower(node ast.Stmt) (statement, *diagnostic) {
	result := statement{Span: span(state.positions, node.Pos(), node.End())}
	if refusal := state.admitNode(node); refusal != nil {
		return result, refusal
	}
	state.depth++
	defer func() { state.depth-- }()

	switch item := node.(type) {
	case *ast.AssignStmt:
		return state.assignment(item, result)
	case *ast.ReturnStmt:
		if len(item.Results) != 1 {
			return result, state.error(node, "RETURN_ARITY_UNAVAILABLE")
		}
		result.Kind = "return"
		value, refused := state.expr(item.Results[0], state.resultScalar)
		result.Value = value
		return result, refused
	case *ast.IfStmt:
		if item.Init != nil {
			return result, state.error(node, "CONDITIONAL_INITIALIZER_UNAVAILABLE")
		}
		result.Kind = "if"
		condition, refused := state.expr(item.Cond, scalarBool)
		if refused != nil {
			return result, refused
		}
		thenBody, refused := state.branch(item.Body)
		if refused != nil {
			return result, refused
		}
		elseBody, refused := state.branch(item.Else)
		if refused != nil {
			return result, refused
		}
		result.Condition, result.ThenBranch, result.ElseBranch = condition, &thenBody, &elseBody
		return result, nil
	case *ast.GoStmt:
		return result, state.error(node, "GOROUTINE_UNAVAILABLE")
	case *ast.DeferStmt:
		return result, state.error(node, "DEFER_UNAVAILABLE")
	default:
		return result, state.error(node, "STATEMENT_SEMANTICS_UNAVAILABLE")
	}
}

func functionBody(decl *ast.FuncDecl, info *types.Info, places *token.FileSet) bodyObservation {
	state := observedBody{info: info, positions: places, names: map[string]bool{},
		objects: map[types.Object]scalarBinding{}, locals: []scalarBinding{}}
	result := bodyObservation{
		Status: "UNAVAILABLE", Parameters: []scalarBinding{}, Locals: []scalarBinding{}, Body: []statement{},
	}
	if !bodyIdentifier(decl.Name.Name) {
		result.Diagnostic = state.error(decl, "IDENTIFIER_OUTSIDE_ASCII_SCOPE")
		return result
	}
	result.Symbol = &bodySymbol{
		identifier:      identifier{decl.Name.Name, span(places, decl.Name.Pos(), decl.Name.End())},
		DeclarationSpan: span(places, decl.Pos(), decl.End()),
	}
	if decl.Recv != nil || decl.Body == nil {
		result.Diagnostic = state.error(decl, "NONFREE_OR_BODYLESS_FUNCTION")
		return result
	}
	obj, bound := info.Defs[decl.Name].(*types.Func)
	if !bound {
		result.Diagnostic = state.error(decl.Name, "UNRESOLVED_SYMBOL")
		return result
	}
	sig := obj.Type().(*types.Signature)
	if sig.TypeParams().Len() != 0 || sig.Variadic() || sig.Results().Len() != 1 {
		result.Diagnostic = state.error(decl, "SIGNATURE_FORM_UNAVAILABLE")
		return result
	}
	if sig.Results().At(0).Name() != "" {
		result.Diagnostic = state.error(decl, "NAMED_RETURN_UNAVAILABLE")
		return result
	}
	state.resultScalar = goScalar(sig.Results().At(0).Type())
	if state.resultScalar == "" {
		result.Diagnostic = state.error(decl, "SCALAR_TYPE_UNAVAILABLE")
		return result
	}
	parameters := make([]scalarBinding, 0, sig.Params().Len())
	for index := 0; index < sig.Params().Len(); index++ {
		param, refused := state.add(sig.Params().At(index), decl)
		if refused != nil {
			result.Diagnostic = refused
			return result
		}
		parameters = append(parameters, param)
	}
	statements, refused := state.block(decl.Body.List)
	if refused != nil {
		result.Diagnostic = refused
		return result
	}
	result.Status, result.Parameters, result.ResultScalar = "LOWERABLE", parameters, state.resultScalar
	result.Locals, result.Body = state.locals, statements
	return result
}

func observeFirstOrder(raw []byte) firstOrderReceipt {
	result := firstOrderReceipt{Version: 1, Producer: bodyProducer,
		Toolchain: runtime.Version(), RequestSHA: sha(raw), Status: "INVALID_REQUEST",
		Inventory: []identity{}, Functions: []bodyObservation{},
	}
	req, code := decodeRequest(raw)
	if code != "" {
		result.Diagnostic = &diagnostic{Code: code}
		return result
	}
	for _, file := range req.Files {
		result.Inventory = append(result.Inventory, identity{file.Path, file.SHA256})
	}
	places := token.NewFileSet()
	files, reply := parsePackage(req, baseResponse(sha(raw)), places)
	if reply.Status != "" {
		result.Status, result.Diagnostic = reply.Status, reply.Diagnostic
		return result
	}
	info := types.Info{Types: map[ast.Expr]types.TypeAndValue{},
		Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	settings := types.Config{GoVersion: req.GoVersion, Sizes: types.SizesFor("gc", req.TargetArch)}
	if _, err := settings.Check(req.PackagePath, places, files, &info); err != nil {
		result.Status, result.Diagnostic = "INVALID_SOURCE", &diagnostic{Code: "GO_TYPE_CHECK_REJECTED"}
		return result
	}
	for _, file := range files {
		for _, item := range file.Decls {
			if decl, ok := item.(*ast.FuncDecl); ok {
				if len(result.Functions) >= maxBodyRows {
					return result.resourceLimit("GO_OBSERVATION_LIMIT")
				}
				result.Functions = append(result.Functions, functionBody(decl, &info, places))
			}
		}
	}
	result.Status = "OBSERVED_BODIES"
	return result
}

func (result firstOrderReceipt) resourceLimit(code string) firstOrderReceipt {
	result.Status, result.Diagnostic = "RESOURCE_LIMIT", &diagnostic{Code: code}
	result.Functions = []bodyObservation{}
	return result
}

func init() {
	if len(os.Args) == 1 {
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "--lower-first-order-go" {
		os.Exit(2)
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxWireBytes+1))
	if err != nil || len(raw) > maxWireBytes {
		os.Exit(2)
	}
	result := observeFirstOrder(raw)
	wire, err := json.Marshal(result)
	if err == nil && len(wire)+1 > maxWireBytes {
		wire, err = json.Marshal(result.resourceLimit("GO_OBSERVATION_LIMIT"))
	}
	if err != nil || len(wire)+1 > maxWireBytes {
		os.Exit(2)
	}
	if _, err := fmt.Fprintln(os.Stdout, string(wire)); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
