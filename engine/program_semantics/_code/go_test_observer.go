// Observes declarations in a closed, explicitly selected Go test source context.
package main

import (
	"encoding/json"
	"go/ast"
	"go/token"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const goTestProducer = "fortress.go-test-declarations@0.1.0"

type goTestFile struct {
	goFileSelection
	PackageName string      `json:"package_name,omitempty"`
	PackageRole string      `json:"package_role,omitempty"`
	PackageSpan *sourceSpan `json:"package_span,omitempty"`
}

type goTestParameter struct {
	Qualifier      string     `json:"qualifier"`
	QualifierSpan  sourceSpan `json:"qualifier_span"`
	TypeNameSpan   sourceSpan `json:"type_name_span"`
	ImportPathSpan sourceSpan `json:"import_path_span"`
}

type goTestDeclaration struct {
	Name          string           `json:"name"`
	Kind          string           `json:"kind"`
	Disposition   string           `json:"disposition"`
	Span          sourceSpan       `json:"span"`
	SignatureSpan sourceSpan       `json:"signature_span"`
	Parameter     *goTestParameter `json:"parameter,omitempty"`
}

type goTestResponse struct {
	Version      int                 `json:"schema_version"`
	Producer     string              `json:"producer"`
	Toolchain    string              `json:"go_toolchain"`
	RequestSHA   string              `json:"request_sha256"`
	ContextSHA   string              `json:"context_sha256,omitempty"`
	Context      *contextualIdentity `json:"context,omitempty"`
	BuildContext *goBuildContext     `json:"build_context,omitempty"`
	Status       string              `json:"status"`
	Diagnostic   string              `json:"diagnostic,omitempty"`
	Package      string              `json:"package_name,omitempty"`
	Files        []goTestFile        `json:"selection"`
	Declarations []goTestDeclaration `json:"test_declarations"`
}

func testResponse(requestSHA string) goTestResponse {
	return goTestResponse{
		Version: 1, Producer: goTestProducer, Toolchain: runtime.Version(), RequestSHA: requestSHA,
		Files: []goTestFile{}, Declarations: []goTestDeclaration{},
	}
}

func (result *goTestResponse) stop(status, code string) {
	if result.Status == "" {
		result.Status, result.Diagnostic = status, code
	}
}

func goTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") {
		return false
	}
	if name == "Test" {
		return true
	}
	leading, _ := utf8.DecodeRuneInString(name[len("Test"):])
	return !unicode.IsLower(leading)
}

func testingImport(file *ast.File, qualifier string) (*ast.BasicLit, string) {
	var matched *ast.BasicLit
	for _, declared := range file.Imports {
		path, err := strconv.Unquote(declared.Path.Value)
		if err != nil {
			return nil, "PARAMETER_IMPORT_UNRESOLVED"
		}
		name := ""
		if declared.Name != nil {
			name = declared.Name.Name
		} else if path == "testing" {
			name = "testing"
		}
		if name != qualifier {
			continue
		}
		if matched != nil {
			return nil, "PARAMETER_IMPORT_UNRESOLVED"
		}
		matched = declared.Path
	}
	if matched == nil {
		return nil, "PARAMETER_IMPORT_UNRESOLVED"
	}
	if matched.Value != "\"testing\"" && matched.Value != "`testing`" {
		path, _ := strconv.Unquote(matched.Value)
		if path == "testing" {
			return nil, "PARAMETER_IMPORT_UNRESOLVED"
		}
		return nil, "PARAMETER_IMPORT_MISMATCH"
	}
	return matched, ""
}

func testDeclaration(file *ast.File, fn *ast.FuncDecl, positions *token.FileSet) goTestDeclaration {
	head := span(positions, fn.Pos(), fn.Type.End())
	result := goTestDeclaration{
		Name: fn.Name.Name, Kind: "TEST", Disposition: "INVALID_SIGNATURE",
		Span: span(positions, fn.Name.Pos(), fn.Name.End()), SignatureSpan: head,
	}
	if fn.Type.Params.NumFields() != 1 || fn.Type.TypeParams.NumFields() != 0 || fn.Type.Results.NumFields() != 0 {
		return result
	}
	pointer, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return result
	}
	selection, ok := pointer.X.(*ast.SelectorExpr)
	if !ok {
		if name, named := pointer.X.(*ast.Ident); named {
			if name.Name == "T" || fn.Name.Name == "TestMain" && name.Name == "M" {
				result.Disposition = "PARAMETER_IMPORT_UNRESOLVED"
			}
		}
		return result
	}
	if fn.Name.Name == "TestMain" && selection.Sel.Name == "M" {
		result.Kind = "TEST_MAIN_HOOK"
	} else if selection.Sel.Name != "T" {
		return result
	}
	qualifier, ok := selection.X.(*ast.Ident)
	if !ok || qualifier.Name == "_" {
		return result
	}
	path, code := testingImport(file, qualifier.Name)
	if code != "" {
		result.Disposition = code
		return result
	}
	if fn.Body == nil {
		result.Disposition = "EXTERNAL_BODY_UNOBSERVED"
		return result
	}
	result.Disposition = "DIRECT_STANDARD_SIGNATURE"
	result.Parameter = &goTestParameter{
		Qualifier: qualifier.Name, QualifierSpan: span(positions, qualifier.Pos(), qualifier.End()),
		TypeNameSpan:   span(positions, selection.Sel.Pos(), selection.Sel.End()),
		ImportPathSpan: span(positions, path.Pos(), path.End()),
	}
	return result
}

func observeGoTestDeclarations(raw []byte) goTestResponse {
	result := testResponse(sha(raw))
	req, code := decodeGoBuildRequest(raw)
	if code != "" {
		result.stop("INVALID_REQUEST", code)
		return result
	}
	if req.GoVersion != "go1.22" || req.BuildContext.ReleaseMinor != 22 ||
		req.BuildContext.TestMode != "REQUIRE_SEPARATE_TEST_CONTEXT" || req.TargetArch != "amd64" {
		result.stop("UNSUPPORTED", "TEST_DECLARATION_CONTEXT_REQUIRED")
		return result
	}
	context := contextualIdentity{req.PackagePath, req.GoVersion, req.TargetOS, req.TargetArch, make([]identity, 0, len(req.Files))}
	for _, source := range req.Files {
		context.Files = append(context.Files, identity{source.Path, source.SHA256})
	}
	contextBytes, _ := json.Marshal(struct {
		SourceContext *contextualIdentity `json:"source_context"`
		BuildContext  *goBuildContext     `json:"build_context"`
	}{&context, req.BuildContext})
	result.ContextSHA, result.Context, result.BuildContext = sha(contextBytes), &context, req.BuildContext

	positions := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(req.Files))
	nodes := 0
	for _, source := range req.Files {
		selection, file := selectedGoFileForObservation(req, source, positions, &nodes, true, true)
		row := goTestFile{goFileSelection: selection}
		if file != nil {
			row.PackageName = file.Name.Name
			location := span(positions, file.Name.Pos(), file.Name.End())
			row.PackageSpan = &location
			if !strings.HasSuffix(source.Path, "_test.go") {
				if result.Package != "" && result.Package != row.PackageName {
					result.stop("INVALID_SOURCE", "CONFLICTING_PRODUCTION_PACKAGES")
				} else if result.Package == "" {
					result.Package = row.PackageName
				}
			}
			for _, imported := range file.Imports {
				if path, err := strconv.Unquote(imported.Path.Value); err == nil && path == "C" {
					result.stop("UNSUPPORTED", "CGO_CONTEXT_UNSUPPORTED")
				}
			}
		} else if status := goSelectionFailureStatus(selection.Disposition); status != "" {
			result.stop(status, selection.Disposition)
		}
		result.Files = append(result.Files, row)
		parsed = append(parsed, file)
	}
	if result.Status == "" && (result.Package == "" || result.Package == "_") {
		result.stop("UNSUPPORTED", "PRODUCTION_PACKAGE_UNESTABLISHED")
	}
	for index, file := range parsed {
		if file == nil {
			continue
		}
		row := &result.Files[index]
		switch {
		case !strings.HasSuffix(row.Path, "_test.go"):
			row.PackageRole = "PRODUCTION"
		case row.PackageName == result.Package:
			row.PackageRole = "INTERNAL_TEST"
		case row.PackageName == result.Package+"_test" && result.Package != "":
			row.PackageRole = "EXTERNAL_TEST"
		default:
			row.PackageRole = "UNRESOLVED_TEST_PACKAGE"
			result.stop("INVALID_SOURCE", "UNRECOGNIZED_TEST_PACKAGE")
		}
	}
	if result.Status != "" {
		return result
	}
	for index, file := range parsed {
		if file == nil || result.Files[index].PackageRole == "PRODUCTION" {
			continue
		}
		for _, item := range file.Decls {
			fn, ok := item.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !goTestName(fn.Name.Name) {
				continue
			}
			if len(result.Declarations) >= maxRecords {
				result.stop("RESOURCE_LIMIT", "GO_TEST_DECLARATION_LIMIT")
				result.Declarations = []goTestDeclaration{}
				return result
			}
			result.Declarations = append(result.Declarations, testDeclaration(file, fn, positions))
		}
	}
	result.Status = "DECLARATIONS_OBSERVED"
	return result
}

func executeGoTestDeclarations() int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxWireBytes+1))
	if err != nil || len(raw) > maxWireBytes {
		return 2
	}
	result := observeGoTestDeclarations(raw)
	wire, err := json.Marshal(result)
	if err != nil {
		return 2
	}
	if len(wire)+1 > maxWireBytes {
		result.Status, result.Diagnostic = "RESOURCE_LIMIT", "GO_TEST_DECLARATION_LIMIT"
		result.Declarations = []goTestDeclaration{}
		wire, err = json.Marshal(result)
		if err != nil || len(wire)+1 > maxWireBytes {
			return 2
		}
	}
	if _, err := os.Stdout.Write(append(wire, '\n')); err != nil {
		return 2
	}
	return 0
}

var _ = func() bool {
	goTestDeclarationsMode = executeGoTestDeclarations
	return true
}()
