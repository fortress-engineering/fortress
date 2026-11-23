// Prototype stdio-only Go observation backend for a separately trusted host.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxWireBytes   = 1 << 20
	maxSourceBytes = 512 << 10
	maxFileBytes   = 64 << 10
	maxFiles       = 64
	maxASTNodes    = 20000
	maxASTDepth    = 128
	maxRecords     = 4096
	maxTypeBytes   = 2048
)

type sourceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Base64 string `json:"source_base64"`
	bytes  []byte
}

type request struct {
	Version     int          `json:"schema_version"`
	PackagePath string       `json:"package_path"`
	GoVersion   string       `json:"go_version"`
	TargetOS    string       `json:"target_os"`
	TargetArch  string       `json:"target_arch"`
	Files       []sourceFile `json:"files"`
}

type identity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type contextualIdentity struct {
	PackagePath string     `json:"package_path"`
	GoVersion   string     `json:"go_version"`
	TargetOS    string     `json:"target_os"`
	TargetArch  string     `json:"target_arch"`
	Files       []identity `json:"source_inventory"`
}

type sourceSpan struct {
	Path            string `json:"path"`
	StartByte       int    `json:"start_byte"`
	EndByte         int    `json:"end_byte"`
	StartLine       int    `json:"start_line"`
	StartByteColumn int    `json:"start_byte_column"`
}

type diagnostic struct {
	Code string      `json:"code"`
	Span *sourceSpan `json:"span,omitempty"`
}

type declaration struct {
	Implementation string     `json:"implementation"`
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	Signature      string     `json:"declared_signature"`
	Span           sourceSpan `json:"span"`
}

type callObservation struct {
	Name        string      `json:"name,omitempty"`
	Resolution  string      `json:"resolution"`
	Activation  string      `json:"activation"`
	Span        sourceSpan  `json:"span"`
	Declaration *sourceSpan `json:"declaration,omitempty"`
}

type response struct {
	Version      int                 `json:"schema_version"`
	Producer     string              `json:"producer"`
	GoToolchain  string              `json:"go_toolchain"`
	RequestSHA   string              `json:"request_sha256,omitempty"`
	ContextSHA   string              `json:"context_sha256,omitempty"`
	Context      *contextualIdentity `json:"context,omitempty"`
	Status       string              `json:"status"`
	Diagnostic   *diagnostic         `json:"diagnostic,omitempty"`
	PackageName  string              `json:"package_name,omitempty"`
	Declarations []declaration       `json:"declarations"`
	Calls        []callObservation   `json:"calls"`
	Limitations  []string            `json:"limitations"`
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var pathSegment = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)
var hostSHA = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validSlashPath(value string) bool {
	if len(value) > 240 {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if !pathSegment.MatchString(part) || strings.HasSuffix(part, ".") || strings.HasPrefix(part, ".") {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if slices.Contains([]string{"CON", "PRN", "AUX", "NUL"}, base) ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) &&
				base[3] >= '0' && base[3] <= '9') {
			return false
		}
	}
	return true
}

func filename(path string) string {
	return path[strings.LastIndexByte(path, '/')+1:]
}

func rejectDuplicateKeys(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON depth limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		keys := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || name != strings.ToLower(name) {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := keys[name]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			if len(keys) >= 64 {
				return errors.New("JSON object key limit")
			}
			keys[name] = struct{}{}
			if err := rejectDuplicateKeys(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case json.Delim('['):
		count := 0
		for decoder.More() {
			count++
			if count > maxFiles {
				return errors.New("JSON collection limit")
			}
			if err := rejectDuplicateKeys(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return nil
	}
}

func decodeRequest(raw []byte) (request, string) {
	var result request
	if !utf8.Valid(raw) {
		return result, "INVALID_JSON"
	}
	duplicateCheck := json.NewDecoder(bytes.NewReader(raw))
	duplicateCheck.UseNumber()
	if err := rejectDuplicateKeys(duplicateCheck, 0); err != nil {
		return result, "INVALID_OR_EXCESSIVE_JSON"
	}
	if _, err := duplicateCheck.Token(); err != io.EOF {
		return result, "TRAILING_JSON"
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, "UNEXPECTED_REQUEST_FIELDS"
	}
	if result.Version != 1 || !validSlashPath(result.PackagePath) || len(result.Files) == 0 {
		return result, "INVALID_REQUEST_CONTEXT"
	}
	if result.TargetArch != "amd64" || (result.TargetOS != "windows" && result.TargetOS != "linux") ||
		(result.GoVersion != "go1.17" && result.GoVersion != "go1.22") {
		return result, "UNSUPPORTED_TARGET_CONTEXT"
	}
	seen := make(map[string]struct{}, len(result.Files))
	sourceBytes := 0
	packageDirectory := path.Dir(result.Files[0].Path)
	for index := range result.Files {
		file := &result.Files[index]
		if !validSlashPath(file.Path) || !strings.HasSuffix(file.Path, ".go") || !hostSHA.MatchString(file.SHA256) {
			return result, "INVALID_SOURCE_IDENTITY"
		}
		if path.Dir(file.Path) != packageDirectory {
			return result, "PACKAGE_DIRECTORY_CONTEXT_REQUIRED"
		}
		folded := strings.ToLower(file.Path)
		if _, duplicate := seen[folded]; duplicate {
			return result, "SOURCE_PATH_COLLISION"
		}
		seen[folded] = struct{}{}
		if len(file.Base64) > base64.StdEncoding.EncodedLen(maxFileBytes) {
			return result, "FILE_BYTE_LIMIT"
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(file.Base64)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != file.Base64 {
			return result, "INVALID_BASE64"
		}
		if len(decoded) > maxFileBytes {
			return result, "FILE_BYTE_LIMIT"
		}
		if sha(decoded) != file.SHA256 {
			return result, "SOURCE_DIGEST_MISMATCH"
		}
		sourceBytes += len(decoded)
		if sourceBytes > maxSourceBytes {
			return result, "SOURCE_BYTE_LIMIT"
		}
		file.bytes = decoded
	}
	slices.SortFunc(result.Files, func(left, right sourceFile) int {
		return strings.Compare(left.Path, right.Path)
	})
	return result, ""
}

func span(positionSet *token.FileSet, start, end token.Pos) sourceSpan {
	first := positionSet.PositionFor(start, false)
	last := positionSet.PositionFor(end, false)
	return sourceSpan{first.Filename, first.Offset, last.Offset, first.Line, first.Column}
}

func point(position token.Position) *sourceSpan {
	if !position.IsValid() {
		return nil
	}
	return &sourceSpan{position.Filename, position.Offset, position.Offset, position.Line, position.Column}
}

func baseResponse(requestSHA string) response {
	return response{
		Version: 1, Producer: "fortress.go-observations@0.1.1", GoToolchain: runtime.Version(), RequestSHA: requestSHA,
		Declarations: []declaration{}, Calls: []callObservation{},
		Limitations: []string{
			"HOST_MUST_ESTABLISH_PACKAGE_AND_CONTEXT_COMPLETENESS",
			"NO_DEPENDENCIES_BUILD_CONDITIONS_OR_FOREIGN_CONTEXT",
			"BODYLESS_DECLARATIONS_DO_NOT_ESTABLISH_IMPLEMENTATION",
			"NO_RUNTIME_EFFECT_REACHABILITY_OR_EXECUTION_PROOF",
			"INTERFACE_FUNCTION_VALUE_AND_OTHER_UNSUPPORTED_DISPATCH_REMAINS_UNRESOLVED",
		},
	}
}

func refuse(result response, status, code string, location *sourceSpan) response {
	result.Status = status
	result.Diagnostic = &diagnostic{code, location}
	return result
}

func directive(file *ast.File) string {
	for _, group := range file.Comments {
		for _, comment := range group.List {
			switch {
			case strings.HasPrefix(comment.Text, "//go:build"), strings.HasPrefix(comment.Text, "// +build"):
				return "BUILD_CONTEXT_REQUIRED"
			case strings.HasPrefix(comment.Text, "//go:"), strings.HasPrefix(comment.Text, "//line "),
				strings.HasPrefix(comment.Text, "/*line "):
				return "COMPILER_DIRECTIVE_CONTEXT_REQUIRED"
			}
		}
	}
	return ""
}

func parsePackage(req request, result response, positions *token.FileSet) ([]*ast.File, response) {
	files := make([]*ast.File, 0, len(req.Files))
	nodes := 0
	for _, source := range req.Files {
		if strings.Contains(filename(source.Path), "_") {
			return nil, refuse(result, "UNSUPPORTED", "BUILD_CONTEXT_REQUIRED", nil)
		}
		file, err := parser.ParseFile(positions, source.Path, source.bytes, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			var location *sourceSpan
			if list, ok := err.(scanner.ErrorList); ok && len(list) > 0 {
				// Position returned by parser may honor source line directives.
				// Only the own physical file location is eligible for reporting.
				physical := positions.File(filePos(file))
				if physical != nil && list[0].Pos.Offset <= physical.Size() && list[0].Pos.Offset >= 0 {
					location = point(physical.PositionFor(physical.Pos(list[0].Pos.Offset), false))
				}
			}
			return nil, refuse(result, "INVALID_SOURCE", "GO_PARSE_FAILURE", location)
		}
		if code := directive(file); code != "" {
			return nil, refuse(result, "UNSUPPORTED", code, nil)
		}
		for _, imported := range file.Imports {
			target, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return nil, refuse(result, "INVALID_SOURCE", "INVALID_GO_IMPORT", nil)
			}
			code := "DEPENDENCY_CONTEXT_REQUIRED"
			if target == "C" {
				code = "FOREIGN_CONTEXT_REQUIRED"
			}
			loc := span(positions, imported.Pos(), imported.End())
			return nil, refuse(result, "UNSUPPORTED", code, &loc)
		}
		depth := 0
		exceeded := false
		ast.Inspect(file, func(node ast.Node) bool {
			if node == nil {
				depth--
				return true
			}
			nodes++
			if nodes > maxASTNodes || depth >= maxASTDepth {
				exceeded = true
				return false
			}
			depth++
			return true
		})
		if exceeded {
			return nil, refuse(result, "RESOURCE_LIMIT", "GO_AST_LIMIT", nil)
		}
		files = append(files, file)
	}
	return files, result
}

func filePos(file *ast.File) token.Pos {
	if file == nil {
		return token.NoPos
	}
	return file.Pos()
}

func classify(expr *ast.CallExpr, info *types.Info, positions *token.FileSet, activation string, bindings map[*types.Func]declaration) callObservation {
	out := callObservation{
		Span: span(positions, expr.Pos(), expr.End()), Resolution: "UNRESOLVED_CALL_FORM", Activation: activation,
	}
	var object types.Object
	switch callee := expr.Fun.(type) {
	case *ast.Ident:
		out.Name = callee.Name
		object = info.Uses[callee]
	case *ast.SelectorExpr:
		out.Name = callee.Sel.Name
		selection := info.Selections[callee]
		if selection == nil {
			return out
		}
		if _, dynamic := selection.Recv().Underlying().(*types.Interface); dynamic {
			out.Resolution = "UNRESOLVED_INTERFACE_DISPATCH"
			return out
		}
		object = selection.Obj()
	}
	switch target := object.(type) {
	case *types.Func:
		signature := target.Type().(*types.Signature)
		if signature.Recv() != nil {
			if _, dynamic := signature.Recv().Type().Underlying().(*types.Interface); dynamic {
				out.Resolution = "UNRESOLVED_INTERFACE_DISPATCH"
				return out
			}
			out.Resolution = "DIRECT_METHOD"
		} else {
			out.Resolution = "DIRECT_FUNCTION"
		}
		binding, found := bindings[target.Origin()]
		if !found {
			out.Resolution = "UNRESOLVED_DECLARATION"
		} else {
			out.Declaration = &binding.Span
			if binding.Implementation != "SOURCE_BODY" {
				out.Resolution = "EXTERNAL_BODY_UNOBSERVED"
			}
		}
	case *types.Var:
		out.Resolution = "UNRESOLVED_FUNCTION_VALUE"
	case *types.TypeName:
		out.Resolution = "TYPE_CONVERSION"
	case *types.Builtin:
		out.Resolution = "BUILTIN"
	}
	return out
}

func project(req request, physical *token.FileSet, files []*ast.File, base response) response {
	info := types.Info{
		Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	config := types.Config{GoVersion: req.GoVersion, Sizes: types.SizesFor("gc", req.TargetArch)}
	pkg, err := config.Check(req.PackagePath, physical, files, &info)
	if err != nil {
		var location *sourceSpan
		if typed, ok := err.(types.Error); ok {
			location = point(physical.PositionFor(typed.Pos, false))
		}
		return refuse(base, "INVALID_SOURCE", "GO_TYPE_CHECK_REJECTED", location)
	}
	declarations := make([]declaration, 0)
	bindings := make(map[*types.Func]declaration)
	for _, file := range files {
		for _, node := range file.Decls {
			decl, isFunction := node.(*ast.FuncDecl)
			if !isFunction || decl.Name.Name == "_" {
				continue
			}
			function, bound := info.Defs[decl.Name].(*types.Func)
			if !bound {
				return refuse(base, "UNSUPPORTED", "GO_UNRESOLVED_DECLARATION", nil)
			}
			kind := "FUNCTION"
			if decl.Recv != nil {
				kind = "METHOD"
			}
			implementation := "SOURCE_BODY"
			if decl.Body == nil {
				implementation = "EXTERNAL_BODY_UNOBSERVED"
			}
			signature := types.TypeString(function.Type(), func(pkg *types.Package) string { return pkg.Path() })
			if len(signature) > maxTypeBytes || len(declarations) >= maxRecords {
				return refuse(base, "RESOURCE_LIMIT", "GO_OBSERVATION_LIMIT", nil)
			}
			entry := declaration{
				Implementation: implementation,
				Name:           decl.Name.Name,
				Kind:           kind,
				Signature:      signature,
				Span:           span(physical, decl.Name.Pos(), decl.Name.End()),
			}
			declarations = append(declarations, entry)
			bindings[function.Origin()] = entry
		}
	}
	calls := make([]callObservation, 0)
	for _, file := range files {
		activations := make(map[*ast.CallExpr]string)
		exceeded := false
		ast.Inspect(file, func(node ast.Node) bool {
			if exceeded {
				return false
			}
			switch current := node.(type) {
			case *ast.GoStmt:
				activations[current.Call] = "GOROUTINE"
			case *ast.DeferStmt:
				activations[current.Call] = "DEFERRED"
			case *ast.CallExpr:
				if len(declarations)+len(calls) >= maxRecords {
					exceeded = true
					return false
				}
				activation := activations[current]
				if activation == "" {
					activation = "ORDINARY"
				}
				calls = append(calls, classify(current, &info, physical, activation, bindings))
			}
			return true
		})
		if exceeded {
			return refuse(base, "RESOURCE_LIMIT", "GO_OBSERVATION_LIMIT", nil)
		}
	}
	base.Status = "OBSERVED"
	base.PackageName = pkg.Name()
	base.Declarations = declarations
	base.Calls = calls
	return base
}

func observe(raw []byte) response {
	base := baseResponse(sha(raw))
	req, code := decodeRequest(raw)
	if code != "" {
		if code == "UNSUPPORTED_TARGET_CONTEXT" || code == "PACKAGE_DIRECTORY_CONTEXT_REQUIRED" {
			return refuse(base, "UNSUPPORTED", code, nil)
		}
		if strings.HasSuffix(code, "_LIMIT") {
			return refuse(base, "RESOURCE_LIMIT", code, nil)
		}
		return refuse(base, "INVALID_REQUEST", code, nil)
	}
	context := contextualIdentity{req.PackagePath, req.GoVersion, req.TargetOS, req.TargetArch, make([]identity, 0, len(req.Files))}
	for _, file := range req.Files {
		context.Files = append(context.Files, identity{file.Path, file.SHA256})
	}
	data, _ := json.Marshal(context)
	base.ContextSHA = sha(data)
	base.Context = &context
	positions := token.NewFileSet()
	files, intermediate := parsePackage(req, base, positions)
	if files == nil {
		return intermediate
	}
	return project(req, positions, files, intermediate)
}

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxWireBytes+1))
	var result response
	switch {
	case err != nil:
		result = refuse(baseResponse(""), "INVALID_REQUEST", "STDIN_READ_FAILURE", nil)
	case len(raw) > maxWireBytes:
		result = refuse(baseResponse(""), "RESOURCE_LIMIT", "REQUEST_BYTE_LIMIT", nil)
	default:
		result = observe(raw)
	}
	wire, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Go observation response encoding failed")
		os.Exit(2)
	}
	if len(wire)+1 > maxWireBytes {
		wire, _ = json.Marshal(refuse(baseResponse(result.RequestSHA), "RESOURCE_LIMIT", "RESPONSE_BYTE_LIMIT", nil))
	}
	if _, err := os.Stdout.Write(append(wire, '\n')); err != nil {
		os.Exit(2)
	}
}
