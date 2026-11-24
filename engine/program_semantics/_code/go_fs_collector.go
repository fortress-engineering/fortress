// Inspect call identities with an independently packaged standard-library export set.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sort"
)

const (
	goFilesystemFlag     = "--observe-go-filesystem"
	maxGoFilesystemCalls = 64
	maxGoExportFiles     = 160
	maxGoExportBytes     = 16 << 20
	maxGoExportTotal     = 128 << 20
)

// Only build-time selected assets can populate this boundary. The source
// request has no external package paths, executables, or installation pins.
var goFilesystemAssets *goFilesystemLibrary

type goFilesystemLibrary struct {
	files      fs.FS
	exports    map[string]string
	sourceRef  string
	toolchain  string
	targetOS   string
	targetArch string
}

type goFilesystemResponse struct {
	Version          int                `json:"schema_version"`
	Producer         string             `json:"producer"`
	RequestRef       string             `json:"request_ref,omitempty"`
	Status           string             `json:"status"`
	Reason           string             `json:"reason,omitempty"`
	PackageSourceRef string             `json:"package_source_ref,omitempty"`
	ExportSetRef     string             `json:"export_set_ref,omitempty"`
	DeclarationRef   string             `json:"declaration_ref,omitempty"`
	Source           *identity          `json:"source,omitempty"`
	Calls            []goFilesystemSite `json:"calls"`
}

type goFilesystemSite struct {
	Span       sourceSpan `json:"span"`
	Resolution string     `json:"resolution"`
}

func (out goFilesystemResponse) unavailable(reason string) goFilesystemResponse {
	out.Status = "UNAVAILABLE"
	out.Reason = reason
	out.Calls = []goFilesystemSite{}
	return out
}

type goFilesystemImporter struct {
	standardOS *types.Package
}

func (installed goFilesystemImporter) Import(path string) (*types.Package, error) {
	if path != "os" {
		return nil, errors.New("unsupported package import")
	}
	return installed.standardOS, nil
}

func (assets *goFilesystemLibrary) exportSetRef() (string, bool) {
	if assets == nil || assets.files == nil || assets.toolchain != runtime.Version() ||
		assets.targetOS != runtime.GOOS || assets.targetArch != runtime.GOARCH ||
		!hostSHA.MatchString(assets.sourceRef) || len(assets.exports) == 0 ||
		len(assets.exports) > maxGoExportFiles {
		return "", false
	}
	if _, ok := assets.exports["os"]; !ok {
		return "", false
	}
	rows := make([]identity, 0, len(assets.exports))
	for path, digest := range assets.exports {
		if !validSlashPath(path) || !hostSHA.MatchString(digest) {
			return "", false
		}
		rows = append(rows, identity{path, digest})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	bytes, err := json.Marshal(rows)
	if err != nil {
		return "", false
	}
	return sha(bytes), true
}

func (assets *goFilesystemLibrary) importer(positions *token.FileSet) types.Importer {
	// Package data is selected by the embedded relative name and verified before
	// native decoding. A nil or ambient package lookup is never supplied.
	retained := 0
	return importer.ForCompiler(positions, "gc", func(path string) (io.ReadCloser, error) {
		expected, allowed := assets.exports[path]
		if !allowed {
			return nil, errors.New("package is absent from the selected standard export set")
		}
		file, err := assets.files.Open("exports/" + path + ".a")
		if err != nil {
			return nil, err
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil || !stat.Mode().IsRegular() || stat.Size() <= 0 ||
			stat.Size() > maxGoExportBytes || stat.Size() > int64(maxGoExportTotal-retained) {
			return nil, errors.New("standard export is outside the admitted byte budget")
		}
		data, err := io.ReadAll(io.LimitReader(file, stat.Size()+1))
		if err != nil || int64(len(data)) != stat.Size() || sha(data) != expected {
			return nil, errors.New("standard export identity mismatch")
		}
		retained += len(data)
		return io.NopCloser(bytes.NewReader(data)), nil
	})
}

func goFilesystemCallResolution(call *ast.CallExpr, checker types.Info, writeFile *types.Func, bodies map[*types.Func]bool) string {
	// Object identity comes from the compiler's selected package and source
	// environment. Names, source spelling and the nominal path do not suffice.
	var bound types.Object
	switch callee := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		bound = checker.Uses[callee]
	case *ast.SelectorExpr:
		if method := checker.Selections[callee]; method != nil {
			if _, dynamic := method.Recv().Underlying().(*types.Interface); dynamic {
				return "UNRESOLVED"
			}
			bound = method.Obj()
		} else {
			bound = checker.Uses[callee.Sel]
		}
	}
	if bound == writeFile {
		return "RESOLVED_STANDARD_LIBRARY"
	}
	if function, ok := bound.(*types.Func); ok {
		signature := function.Type().(*types.Signature)
		if receiver := signature.Recv(); receiver != nil {
			if _, dynamic := receiver.Type().Underlying().(*types.Interface); dynamic {
				return "UNRESOLVED"
			}
		}
		if bodies[function.Origin()] {
			return "LOCAL_OR_SHADOWED"
		}
	}
	return "UNRESOLVED"
}

func goFilesystemCallSites(file *ast.File, positions *token.FileSet, checker types.Info, writeFile *types.Func) ([]goFilesystemSite, bool) {
	bodies := make(map[*types.Func]bool)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Body != nil {
			if object, ok := checker.Defs[function.Name].(*types.Func); ok {
				bodies[object] = true
			}
		}
	}
	rows := make([]goFilesystemSite, 0)
	complete := true
	ast.Inspect(file, func(node ast.Node) bool {
		call, selected := node.(*ast.CallExpr)
		if !selected || !complete {
			return complete
		}
		if len(rows) >= maxGoFilesystemCalls {
			complete = false
			return false
		}
		rows = append(rows, goFilesystemSite{
			Span:       span(positions, call.Pos(), call.End()),
			Resolution: goFilesystemCallResolution(call, checker, writeFile, bodies),
		})
		return true
	})
	return rows, complete
}

func boundedGoFilesystemFile(file *ast.File) bool {
	depth, nodes := 0, 0
	within := true
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			depth--
			return true
		}
		if nodes >= maxASTNodes || depth >= maxASTDepth {
			within = false
			return false
		}
		depth++
		nodes++
		return true
	})
	return within
}

func observeGoFilesystem(raw []byte, assets *goFilesystemLibrary) goFilesystemResponse {
	out := goFilesystemResponse{
		Version: 1, Producer: "fortress.go-filesystem@0.1.0", Calls: []goFilesystemSite{},
	}
	if len(raw) > maxWireBytes {
		return out.unavailable("REQUEST_BYTE_LIMIT")
	}
	out.RequestRef = sha(raw)
	req, failed := decodeRequest(raw)
	if failed != "" {
		return out.unavailable(failed)
	}
	if len(req.Files) != 1 || req.PackagePath == "os" || req.GoVersion != "go1.22" ||
		req.TargetOS != runtime.GOOS || req.TargetArch != runtime.GOARCH {
		return out.unavailable("CLOSED_PACKAGE_CONTEXT_UNAVAILABLE")
	}
	source := req.Files[0]
	out.Source = &identity{source.Path, source.SHA256}
	// The initial mode has no conditional source selection or implicit tests.
	if bytes.ContainsRune([]byte(filename(source.Path)), '_') {
		return out.unavailable("BUILD_CONTEXT_REQUIRED")
	}
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, source.Path, source.bytes, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return out.unavailable("GO_PARSE_FAILURE")
	}
	if code := directive(file); code != "" {
		return out.unavailable(code)
	}
	if !boundedGoFilesystemFile(file) {
		return out.unavailable("GO_AST_LIMIT")
	}
	exports, ok := assets.exportSetRef()
	if !ok {
		return out.unavailable("STANDARD_EXPORT_CONTEXT_UNAVAILABLE")
	}
	installed, err := assets.importer(positions).Import("os")
	if err != nil || installed == nil || installed.Path() != "os" || !installed.Complete() {
		return out.unavailable("STANDARD_EXPORT_UNAVAILABLE")
	}
	writeFile, ok := installed.Scope().Lookup("WriteFile").(*types.Func)
	if !ok || writeFile.Pkg() != installed {
		return out.unavailable("STANDARD_DECLARATION_UNAVAILABLE")
	}
	info := types.Info{
		Uses:       map[*ast.Ident]types.Object{},
		Defs:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	native := types.Config{
		GoVersion: req.GoVersion, Sizes: types.SizesFor("gc", req.TargetArch),
		Importer: goFilesystemImporter{installed},
	}
	if _, err := native.Check(req.PackagePath, positions, []*ast.File{file}, &info); err != nil {
		return out.unavailable("GO_TYPE_CONTEXT_UNAVAILABLE")
	}
	rows, complete := goFilesystemCallSites(file, positions, info, writeFile)
	if !complete {
		return out.unavailable("CALL_INVENTORY_LIMIT")
	}
	declaration, err := json.Marshal([]string{"os", "WriteFile", assets.sourceRef, exports, assets.toolchain, assets.targetOS, assets.targetArch})
	if err != nil {
		return out.unavailable("DECLARATION_IDENTITY_UNAVAILABLE")
	}
	out.Status = "OBSERVED"
	out.PackageSourceRef = assets.sourceRef
	out.ExportSetRef = exports
	out.DeclarationRef = sha(declaration)
	out.Calls = rows
	return out
}

func init() {
	if len(os.Args) != 2 || os.Args[1] != goFilesystemFlag {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxWireBytes+1))
	if err != nil {
		os.Exit(2)
	}
	out := observeGoFilesystem(raw, goFilesystemAssets)
	wire, err := json.Marshal(out)
	if err != nil || len(wire)+1 > maxWireBytes {
		os.Exit(2)
	}
	if _, err := os.Stdout.Write(append(wire, '\n')); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
