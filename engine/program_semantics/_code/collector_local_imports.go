// Explicit, module-local Go type observations over trusted captured source bytes.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
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
	maxGoModulePackages = 8
	maxGoModuleBytes    = 4096
	maxGoLocalImports   = 64
)

type goModulePackage struct {
	ImportPath string `json:"import_path"`
	Directory  string `json:"directory"`
}

type goModuleInput struct {
	RootDirectory string            `json:"root_directory"`
	Path          string            `json:"path"`
	Definition    sourceFile        `json:"definition"`
	Packages      []goModulePackage `json:"packages"`
}

type goTypeSelector struct {
	PackagePath string `json:"package_path"`
	Name        string `json:"name"`
}

type goTypeComparison struct {
	Left  goTypeSelector `json:"left"`
	Right goTypeSelector `json:"right"`
}

type goModuleRequest struct {
	goBuildRequest
	Module         *goModuleInput    `json:"module"`
	TypeComparison *goTypeComparison `json:"type_comparison,omitempty"`
}

type goModuleIdentity struct {
	RootDirectory string            `json:"root_directory"`
	Path          string            `json:"path"`
	Definition    identity          `json:"definition"`
	Packages      []goModulePackage `json:"packages"`
}

type goModuleCall struct {
	callObservation
	DeclarationPackage string `json:"declaration_package,omitempty"`
}

type goModuleImport struct {
	TargetPackage string     `json:"target_package"`
	Alias         string     `json:"alias"`
	Span          sourceSpan `json:"span"`
}

type goModuleFacts struct {
	ImportPath   string           `json:"import_path"`
	PackageName  string           `json:"package_name"`
	Imports      []goModuleImport `json:"imports"`
	Declarations []declaration    `json:"declarations"`
	Calls        []goModuleCall   `json:"calls"`
}

type goTypeComparisonResult struct {
	goTypeComparison
	Identical   bool       `json:"identical"`
	LeftSource  sourceSpan `json:"left_source"`
	RightSource sourceSpan `json:"right_source"`
}

type goModuleResponse struct {
	Version        int                     `json:"schema_version"`
	Producer       string                  `json:"producer"`
	GoToolchain    string                  `json:"go_toolchain"`
	RequestSHA     string                  `json:"request_sha256,omitempty"`
	ContextSHA     string                  `json:"context_sha256,omitempty"`
	Context        *contextualIdentity     `json:"context,omitempty"`
	BuildContext   *goBuildContext         `json:"build_context,omitempty"`
	Module         *goModuleIdentity       `json:"module,omitempty"`
	Status         string                  `json:"status"`
	Diagnostic     *diagnostic             `json:"diagnostic,omitempty"`
	Selection      []goFileSelection       `json:"selection"`
	Packages       []goModuleFacts         `json:"observed_packages"`
	TypeComparison *goTypeComparisonResult `json:"type_comparison,omitempty"`
	Limitations    []string                `json:"limitations"`
}

type goModuleRefusal struct {
	Status     string
	Diagnostic diagnostic
}

func refuseGoModule(code, status string, location *sourceSpan) *goModuleRefusal {
	return &goModuleRefusal{Status: status, Diagnostic: diagnostic{Code: code, Span: location}}
}

var goSimpleDirectory = regexp.MustCompile(`^([a-z][a-z0-9]*|_code)(/([a-z][a-z0-9]*|_code))*$`)
var goModulePathPattern = regexp.MustCompile(`^[a-z0-9]+([.-][a-z0-9]+)*[.][a-z]+(/[a-z][a-z0-9._-]*)*$`)
var goTypeName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]{0,95}$`)

func specialGoPackageDirectory(value string) bool {
	for _, part := range strings.Split(value, "/") {
		switch part {
		case "internal", "vendor", "testdata":
			return true
		}
	}
	return false
}

func validateGoModuleDefinition(module *goModuleInput) *goModuleRefusal {
	file := &module.Definition
	if file.Path != path.Join(module.RootDirectory, "go.mod") || !hostSHA.MatchString(file.SHA256) {
		return refuseGoModule("INVALID_MODULE_DEFINITION_IDENTITY", "INVALID_REQUEST", nil)
	}
	if len(file.Base64) > base64.StdEncoding.EncodedLen(maxGoModuleBytes) {
		return refuseGoModule("MODULE_DEFINITION_BYTE_LIMIT", "RESOURCE_LIMIT", nil)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(file.Base64)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != file.Base64 {
		return refuseGoModule("INVALID_BASE64", "INVALID_REQUEST", nil)
	}
	if len(decoded) > maxGoModuleBytes {
		return refuseGoModule("MODULE_DEFINITION_BYTE_LIMIT", "RESOURCE_LIMIT", nil)
	}
	if sha(decoded) != file.SHA256 {
		return refuseGoModule("MODULE_DEFINITION_DIGEST_MISMATCH", "INVALID_REQUEST", nil)
	}
	// This closed scope admits only a module directive followed by a Go version.
	// All dependency, workspace, toolchain, and other directives require separate context.
	lines := make([][]string, 0, 2)
	for _, line := range strings.Split(strings.ReplaceAll(string(decoded), "\r\n", "\n"), "\n") {
		if strings.ContainsRune(line, '\r') {
			return refuseGoModule("MODULE_DEFINITION_CONTEXT_UNSUPPORTED", "UNSUPPORTED", nil)
		}
		if tokens := strings.Fields(line); len(tokens) > 0 {
			lines = append(lines, tokens)
		}
	}
	if !utf8.Valid(decoded) || len(lines) != 2 || len(lines[0]) != 2 ||
		len(lines[1]) != 2 || lines[0][0] != "module" || lines[1][0] != "go" ||
		lines[1][1] != "1.22" {
		return refuseGoModule("MODULE_DEFINITION_CONTEXT_UNSUPPORTED", "UNSUPPORTED", nil)
	}
	if lines[0][1] != module.Path {
		return refuseGoModule("MODULE_PATH_MISMATCH", "INVALID_REQUEST", nil)
	}
	for _, b := range decoded {
		if (b < 32 && b != '\t' && b != '\n' && b != '\r') || b >= 127 {
			return refuseGoModule("MODULE_DEFINITION_CONTEXT_UNSUPPORTED", "UNSUPPORTED", nil)
		}
	}
	return nil
}

func (module *goModuleInput) importPath(directory string) string {
	if directory == "." {
		return module.Path
	}
	return module.Path + "/" + directory
}

func validateGoModule(req *goModuleRequest) *goModuleRefusal {
	context := req.goBuildRequest
	context.Version = 2
	if code := validateGoBuildContext(&context); code != "" {
		status := "UNSUPPORTED"
		if code == "INVALID_REQUEST_CONTEXT" {
			status = "INVALID_REQUEST"
		}
		if code == "BUILD_TAG_LIMIT" {
			status = "RESOURCE_LIMIT"
		}
		return refuseGoModule(code, status, nil)
	}
	module := req.Module
	if req.Version != 3 || module == nil || len(module.Packages) == 0 {
		return refuseGoModule("INVALID_MODULE_REQUEST_CONTEXT", "INVALID_REQUEST", nil)
	}
	if req.GoVersion != "go1.22" || req.TargetArch != "amd64" ||
		runtime.GOARCH != "amd64" || (runtime.GOOS != "windows" && runtime.GOOS != "linux") ||
		(runtime.Version() != "go1.22.12" && runtime.Version() != "go1.22.2") ||
		os.Getenv("GODEBUG") != "gotypesalias=0" {
		return refuseGoModule("MODULE_TOOLCHAIN_CONTEXT_UNSUPPORTED", "UNSUPPORTED", nil)
	}
	if len(module.Packages) > maxGoModulePackages {
		return refuseGoModule("PACKAGE_COUNT_LIMIT", "RESOURCE_LIMIT", nil)
	}
	if !validSlashPath(module.Path) || !goModulePathPattern.MatchString(module.Path) ||
		specialGoPackageDirectory(module.Path) ||
		(module.RootDirectory != "." && !validSlashPath(module.RootDirectory)) {
		return refuseGoModule("MODULE_PATH_CONTEXT_UNSUPPORTED", "UNSUPPORTED", nil)
	}
	if failure := validateGoModuleDefinition(module); failure != nil {
		return failure
	}
	dirs := make(map[string]bool, len(module.Packages))
	for _, entry := range module.Packages {
		if entry.Directory != "." && (!goSimpleDirectory.MatchString(entry.Directory) ||
			!validSlashPath(entry.Directory) || specialGoPackageDirectory(entry.Directory)) {
			return refuseGoModule("PACKAGE_DIRECTORY_CONTEXT_UNSUPPORTED", "UNSUPPORTED", nil)
		}
		if entry.ImportPath != module.importPath(entry.Directory) || !validSlashPath(entry.ImportPath) ||
			dirs[entry.Directory] {
			return refuseGoModule("INVALID_MODULE_PACKAGE_MAPPING", "INVALID_REQUEST", nil)
		}
		dirs[entry.Directory] = true
	}
	slices.SortFunc(module.Packages, func(left, right goModulePackage) int {
		return strings.Compare(left.ImportPath, right.ImportPath)
	})
	if req.TypeComparison != nil {
		for _, selector := range []goTypeSelector{req.TypeComparison.Left, req.TypeComparison.Right} {
			if !validSlashPath(selector.PackagePath) || !goTypeName.MatchString(selector.Name) {
				return refuseGoModule("INVALID_TYPE_SELECTOR", "INVALID_REQUEST", nil)
			}
		}
	}
	return nil
}

type loadedGoModulePackage struct {
	source []sourceFile
	files  []*ast.File
	info   *types.Info
	pkg    *types.Package
	active bool
}

type goModuleImporter struct {
	request   goModuleRequest
	positions *token.FileSet
	members   map[string]*loadedGoModulePackage
	selection map[string]goFileSelection
	failure   *goModuleRefusal
	nodes     int
	imports   int
}

func newGoModuleImporter(req goModuleRequest) (*goModuleImporter, *goModuleRefusal) {
	graph := &goModuleImporter{
		request: req, positions: token.NewFileSet(),
		members:   make(map[string]*loadedGoModulePackage, len(req.Module.Packages)),
		selection: make(map[string]goFileSelection, len(req.Files)),
	}
	dirs := make(map[string]*loadedGoModulePackage, len(req.Module.Packages))
	for _, entry := range req.Module.Packages {
		member := &loadedGoModulePackage{}
		graph.members[entry.ImportPath] = member
		dirs[path.Join(req.Module.RootDirectory, entry.Directory)] = member
	}
	for _, source := range req.Files {
		member := dirs[path.Dir(source.Path)]
		if member == nil {
			return nil, refuseGoModule("SOURCE_OUTSIDE_MODULE_PACKAGE_MAPPING", "INVALID_REQUEST", nil)
		}
		member.source = append(member.source, source)
		graph.selection[source.Path] = goFileSelection{
			Path: source.Path, SHA256: source.SHA256, Disposition: "UNVISITED_MODULE_PACKAGE",
		}
	}
	if graph.members[req.PackagePath] == nil {
		return nil, refuseGoModule("ENTRY_PACKAGE_MAPPING_MISSING", "INVALID_REQUEST", nil)
	}
	return graph, nil
}

func (graph *goModuleImporter) resolve(name string, location *sourceSpan) *goModuleRefusal {
	if name == "C" {
		return refuseGoModule("CGO_CONTEXT_UNSUPPORTED", "UNSUPPORTED", location)
	}
	if name == "." || name == ".." || strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../") {
		return refuseGoModule("RELATIVE_IMPORT_UNSUPPORTED", "UNSUPPORTED", location)
	}
	root := graph.request.Module.Path
	if name != root && !strings.HasPrefix(name, root+"/") {
		return refuseGoModule("EXTERNAL_IMPORT_UNSUPPORTED", "UNSUPPORTED", location)
	}
	if name != root {
		dir := strings.TrimPrefix(name, root+"/")
		if !goSimpleDirectory.MatchString(dir) || specialGoPackageDirectory(dir) {
			return refuseGoModule("PACKAGE_DIRECTORY_CONTEXT_UNSUPPORTED", "UNSUPPORTED", location)
		}
	}
	if graph.members[name] == nil {
		return refuseGoModule("MISSING_LOCAL_PACKAGE", "UNSUPPORTED", location)
	}
	return nil
}

func (graph *goModuleImporter) Import(name string) (*types.Package, error) {
	failure := graph.resolve(name, nil)
	if failure == nil {
		failure = graph.load(name)
	}
	if failure != nil {
		if graph.failure == nil {
			graph.failure = failure
		}
		return nil, errors.New(failure.Diagnostic.Code)
	}
	return graph.members[name].pkg, nil
}

func (graph *goModuleImporter) load(name string) *goModuleRefusal {
	member := graph.members[name]
	if member.active {
		return refuseGoModule("CYCLIC_LOCAL_IMPORT", "INVALID_SOURCE", nil)
	}
	if member.pkg != nil {
		return nil
	}
	member.active = true
	defer func() { member.active = false }()
	for _, source := range member.source {
		selection, file := selectedGoFile(graph.request.goBuildRequest, source, graph.positions, &graph.nodes, true)
		graph.selection[selection.Path] = selection
		if status := goSelectionFailureStatus(selection.Disposition); status != "" {
			return refuseGoModule(selection.Disposition, status, nil)
		}
		if file == nil {
			continue
		}
		if file.Name.Name == "main" {
			return refuseGoModule("MAIN_PACKAGE_UNSUPPORTED", "UNSUPPORTED", nil)
		}
		for _, entry := range file.Imports {
			graph.imports++
			if graph.imports > maxGoLocalImports {
				return refuseGoModule("MODULE_IMPORT_COUNT_LIMIT", "RESOURCE_LIMIT", nil)
			}
			loc := span(graph.positions, entry.Path.Pos(), entry.Path.End())
			target, err := strconv.Unquote(entry.Path.Value)
			if err != nil {
				return refuseGoModule("INVALID_GO_IMPORT", "INVALID_SOURCE", &loc)
			}
			// Reject special and external imports before go/types can synthesize a
			// package for them without consulting the importer.
			if failure := graph.resolve(target, &loc); failure != nil {
				return failure
			}
		}
		member.files = append(member.files, file)
	}
	if len(member.files) == 0 {
		return refuseGoModule("NO_TARGET_PACKAGE_SOURCE", "UNSUPPORTED", nil)
	}
	member.info = &types.Info{
		Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	config := types.Config{GoVersion: graph.request.GoVersion, Sizes: types.SizesFor("gc", graph.request.TargetArch),
		Importer: graph}
	pkg, err := config.Check(name, graph.positions, member.files, member.info)
	if err != nil {
		if graph.failure != nil {
			return graph.failure
		}
		var location *sourceSpan
		if typed, ok := err.(types.Error); ok {
			location = point(graph.positions.PositionFor(typed.Pos, false))
		}
		return refuseGoModule("TYPE_CHECK_REJECTED", "INVALID_SOURCE", location)
	}
	member.pkg = pkg
	return nil
}

func goModuleDeclaration(decl *ast.FuncDecl, function *types.Func, positions *token.FileSet) declaration {
	kind, implementation := "FUNCTION", "SOURCE_BODY"
	if decl.Recv != nil {
		kind = "METHOD"
	}
	if decl.Body == nil {
		implementation = "EXTERNAL_BODY_UNOBSERVED"
	}
	return declaration{Implementation: implementation, Name: decl.Name.Name, Kind: kind,
		Signature: types.TypeString(function.Type(), func(pkg *types.Package) string { return pkg.Path() }),
		Span:      span(positions, decl.Name.Pos(), decl.Name.End())}
}

func classifyGoModuleCall(expr *ast.CallExpr, info *types.Info, positions *token.FileSet,
	activation string, bindings map[*types.Func]declaration) callObservation {
	out := classify(expr, info, positions, activation, bindings)
	selector, selected := expr.Fun.(*ast.SelectorExpr)
	if !selected {
		return out
	}
	qualifier, qualified := selector.X.(*ast.Ident)
	if !qualified {
		return out
	}
	if _, pkg := info.Uses[qualifier].(*types.PkgName); !pkg {
		return out
	}
	switch object := info.Uses[selector.Sel].(type) {
	case *types.Func:
		out.Resolution = "UNRESOLVED_DECLARATION"
		if binding, found := bindings[object.Origin()]; found {
			out.Resolution = "DIRECT_FUNCTION"
			out.Declaration = &binding.Span
			if binding.Implementation != "SOURCE_BODY" {
				out.Resolution = "EXTERNAL_BODY_UNOBSERVED"
			}
		}
	case *types.Var:
		out.Resolution = "UNRESOLVED_FUNCTION_VALUE"
	case *types.TypeName:
		out.Resolution = "TYPE_CONVERSION"
	}
	return out
}

func (graph *goModuleImporter) facts() ([]goModuleFacts, *goModuleRefusal) {
	packages := []goModuleFacts{}
	bindings := make(map[*types.Func]declaration)
	sources := make(map[string]string)
	total := 0
	for _, identity := range graph.request.Module.Packages {
		entry := graph.members[identity.ImportPath]
		if entry.pkg == nil {
			continue
		}
		facts := goModuleFacts{ImportPath: identity.ImportPath, PackageName: entry.pkg.Name(),
			Imports: []goModuleImport{}, Declarations: []declaration{}, Calls: []goModuleCall{}}
		for _, file := range entry.files {
			sources[graph.positions.PositionFor(file.Pos(), false).Filename] = facts.ImportPath
			for _, spec := range file.Imports {
				// A complete type check establishes the dependency in this package
				// universe. Retain the exact import spelling's physical span.
				name, _ := strconv.Unquote(spec.Path.Value)
				alias := graph.members[name].pkg.Name()
				if spec.Name != nil {
					alias = spec.Name.Name
				}
				facts.Imports = append(facts.Imports, goModuleImport{TargetPackage: name, Alias: alias,
					Span: span(graph.positions, spec.Path.Pos(), spec.Path.End())})
			}
			for _, node := range file.Decls {
				decl, isFunc := node.(*ast.FuncDecl)
				if !isFunc || decl.Name.Name == "_" {
					continue
				}
				function, bound := entry.info.Defs[decl.Name].(*types.Func)
				if !bound {
					return nil, refuseGoModule("GO_UNRESOLVED_DECLARATION", "UNSUPPORTED", nil)
				}
				fact := goModuleDeclaration(decl, function, graph.positions)
				total++
				if total > maxRecords || len(fact.Signature) > maxTypeBytes {
					return nil, refuseGoModule("GO_OBSERVATION_LIMIT", "RESOURCE_LIMIT", nil)
				}
				facts.Declarations = append(facts.Declarations, fact)
				bindings[function.Origin()] = fact
			}
		}
		packages = append(packages, facts)
	}
	for index := range packages {
		facts := &packages[index]
		entry := graph.members[facts.ImportPath]
		for _, file := range entry.files {
			activations := make(map[*ast.CallExpr]string)
			ast.Inspect(file, func(node ast.Node) bool {
				if total > maxRecords {
					return false
				}
				switch current := node.(type) {
				case *ast.GoStmt:
					activations[current.Call] = "GOROUTINE"
				case *ast.DeferStmt:
					activations[current.Call] = "DEFERRED"
				case *ast.CallExpr:
					total++
					if total > maxRecords {
						return false
					}
					activation := activations[current]
					if activation == "" {
						activation = "ORDINARY"
					}
					row := classifyGoModuleCall(current, entry.info, graph.positions, activation, bindings)
					observed := goModuleCall{callObservation: row}
					if row.Declaration != nil {
						observed.DeclarationPackage = sources[row.Declaration.Path]
					}
					facts.Calls = append(facts.Calls, observed)
				}
				return true
			})
			if total > maxRecords {
				return nil, refuseGoModule("GO_OBSERVATION_LIMIT", "RESOURCE_LIMIT", nil)
			}
		}
	}
	return packages, nil
}

func (graph *goModuleImporter) compare(request *goTypeComparison) (*goTypeComparisonResult, *goModuleRefusal) {
	if request == nil {
		return nil, nil
	}
	result := goTypeComparisonResult{goTypeComparison: *request}
	first := func(selector goTypeSelector, source *sourceSpan) *types.TypeName {
		member := graph.members[selector.PackagePath]
		if member == nil || member.pkg == nil {
			return nil
		}
		value, ok := member.pkg.Scope().Lookup(selector.Name).(*types.TypeName)
		if !ok || !value.Pos().IsValid() {
			return nil
		}
		*source = span(graph.positions, value.Pos(), value.Pos()+token.Pos(len(value.Name())))
		return value
	}
	left, right := first(request.Left, &result.LeftSource), first(request.Right, &result.RightSource)
	if left == nil || right == nil {
		return nil, refuseGoModule("TYPE_IDENTITY_UNAVAILABLE", "UNSUPPORTED", nil)
	}
	result.Identical = types.Identical(left.Type(), right.Type())
	return &result, nil
}

func baseGoModuleResult(requestSHA string) goModuleResponse {
	return goModuleResponse{Version: 3, Producer: "fortress.go-module-observations@0.1.0",
		GoToolchain: runtime.Version(), RequestSHA: requestSHA, Selection: []goFileSelection{},
		Packages: []goModuleFacts{}, Limitations: []string{
			"HOST_MUST_ESTABLISH_COMPLETE_ORDINARY_MODULE_AND_CONTEXT",
			"ONLY_REACHABLE_PURE_GO_LIBRARY_PACKAGES_ARE_OBSERVED",
			"NO_EXTERNAL_STANDARD_LIBRARY_CGO_WORKSPACE_OR_GENERATED_CONTEXT",
			"BODYLESS_DECLARATIONS_DO_NOT_ESTABLISH_IMPLEMENTATION",
			"NO_RUNTIME_EFFECT_REACHABILITY_OR_EXECUTION_PROOF",
			"INTERFACE_FUNCTION_VALUE_AND_OTHER_UNSUPPORTED_DISPATCH_REMAINS_UNRESOLVED",
		}}
}

func (result goModuleResponse) refused(failure *goModuleRefusal) goModuleResponse {
	result.Status, result.Diagnostic = failure.Status, &failure.Diagnostic
	return result
}

func observeGoModule(raw []byte) goModuleResponse {
	result := baseGoModuleResult(sha(raw))
	var req goModuleRequest
	if code := decodeGoBuildWire(raw, &req); code != "" {
		return result.refused(refuseGoModule(code, "INVALID_REQUEST", nil))
	}
	if failure := validateGoModule(&req); failure != nil {
		return result.refused(failure)
	}
	if code := decodeGoBuildFiles(req.Files, false); code != "" {
		status := "INVALID_REQUEST"
		if strings.HasSuffix(code, "_LIMIT") {
			status = "RESOURCE_LIMIT"
		}
		return result.refused(refuseGoModule(code, status, nil))
	}
	graph, failure := newGoModuleImporter(req)
	if failure != nil {
		return result.refused(failure)
	}
	context := contextualIdentity{req.PackagePath, req.GoVersion, req.TargetOS, req.TargetArch,
		make([]identity, 0, len(req.Files))}
	for _, source := range req.Files {
		context.Files = append(context.Files, identity{source.Path, source.SHA256})
	}
	module := goModuleIdentity{req.Module.RootDirectory, req.Module.Path,
		identity{req.Module.Definition.Path, req.Module.Definition.SHA256}, req.Module.Packages}
	result.Context, result.BuildContext, result.Module = &context, req.BuildContext, &module
	contextBytes, _ := json.Marshal(struct {
		SourceContext *contextualIdentity `json:"source_context"`
		BuildContext  *goBuildContext     `json:"build_context"`
		Module        *goModuleIdentity   `json:"module"`
	}{&context, req.BuildContext, &module})
	result.ContextSHA = sha(contextBytes)

	failure = graph.load(req.PackagePath)
	for _, source := range req.Files {
		result.Selection = append(result.Selection, graph.selection[source.Path])
	}
	if failure != nil {
		return result.refused(failure)
	}
	comparison, failure := graph.compare(req.TypeComparison)
	if failure != nil {
		return result.refused(failure)
	}
	facts, failure := graph.facts()
	if failure != nil {
		return result.refused(failure)
	}
	result.Status, result.Packages, result.TypeComparison = "OBSERVED", facts, comparison
	return result
}

func executeGoModule() int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxWireBytes+1))
	var result goModuleResponse
	switch {
	case err != nil:
		result = baseGoModuleResult("").refused(refuseGoModule("STDIN_READ_FAILURE", "INVALID_REQUEST", nil))
	case len(raw) > maxWireBytes:
		result = baseGoModuleResult("").refused(refuseGoModule("REQUEST_BYTE_LIMIT", "RESOURCE_LIMIT", nil))
	default:
		result = observeGoModule(raw)
	}
	wire, err := json.Marshal(result)
	if err != nil {
		return 2
	}
	if len(wire)+1 > maxWireBytes {
		limited := baseGoModuleResult(result.RequestSHA).refused(refuseGoModule("RESPONSE_BYTE_LIMIT", "RESOURCE_LIMIT", nil))
		wire, _ = json.Marshal(limited)
	}
	if _, err := os.Stdout.Write(append(wire, '\n')); err != nil {
		return 2
	}
	return 0
}

var _ = registerGoModuleMode()

func registerGoModuleMode() bool {
	goLocalImportsMode = executeGoModule
	return true
}
