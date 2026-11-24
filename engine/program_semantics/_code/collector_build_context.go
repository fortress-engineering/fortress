// Explicit build selection for a bounded Go collector with trusted host inputs.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	goBuildSelectionFlag = "--select-build-go"
	virtualGoDirectory   = "fortress-virtual-go"
	maxBuildTags         = 8
)

type goBuildContext struct {
	Compiler     string   `json:"compiler"`
	ReleaseMinor int      `json:"release_minor"`
	CgoEnabled   *bool    `json:"cgo_enabled"`
	TestMode     string   `json:"test_mode"`
	CustomTags   []string `json:"custom_tags"`
	ToolTags     []string `json:"tool_tags"`
}

type goBuildRequest struct {
	request
	BuildContext *goBuildContext `json:"build_context"`
}

type goFileSelection struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	NativeMatch *bool  `json:"native_match"`
	Disposition string `json:"disposition"`
}

type goBuildResponse struct {
	response
	BuildContext *goBuildContext   `json:"build_context,omitempty"`
	Selection    []goFileSelection `json:"selection"`
}

var customGoTag = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func reservedGoTag(tag string) bool {
	switch tag {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios",
		"js", "linux", "nacl", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos",
		"386", "amd64", "amd64p32", "arm", "armbe", "arm64", "arm64be",
		"loong64", "mips", "mipsle", "mips64", "mips64le", "mips64p32", "mips64p32le",
		"ppc", "ppc64", "ppc64le", "riscv", "riscv64", "s390", "s390x", "sparc", "sparc64", "wasm",
		"unix", "cgo", "gc", "gccgo", "boringcrypto", "race", "msan", "asan", "fuzz", "ignore",
		"goexperiment", "test", "go1":
		return true
	default:
		return false
	}
}

func validateGoBuildContext(req *goBuildRequest) string {
	context := req.BuildContext
	if context == nil || context.CgoEnabled == nil || context.CustomTags == nil || context.ToolTags == nil {
		return "INVALID_REQUEST_CONTEXT"
	}
	if req.Version != 2 || !validSlashPath(req.PackagePath) || len(req.Files) == 0 || len(req.Files) > maxFiles {
		return "INVALID_REQUEST_CONTEXT"
	}
	if context.Compiler != "gc" || context.ReleaseMinor < 17 || context.ReleaseMinor > 22 ||
		(req.TargetOS != "windows" && req.TargetOS != "linux") ||
		(req.TargetArch != "amd64" && req.TargetArch != "arm64") ||
		(req.GoVersion != "go1.17" && req.GoVersion != "go1.22") ||
		(req.GoVersion == "go1.22" && context.ReleaseMinor < 22) {
		return "UNSUPPORTED_TARGET_CONTEXT"
	}
	if *context.CgoEnabled {
		return "CGO_CONTEXT_UNSUPPORTED"
	}
	if context.TestMode != "REQUIRE_SEPARATE_TEST_CONTEXT" && context.TestMode != "PRODUCTION_ONLY" {
		return "TEST_CONTEXT_REQUIRED"
	}
	if len(context.CustomTags) > maxBuildTags || len(context.ToolTags) > 4 {
		return "BUILD_TAG_LIMIT"
	}
	seen := make(map[string]bool, len(context.CustomTags))
	for _, tag := range context.CustomTags {
		if !customGoTag.MatchString(tag) || reservedGoTag(tag) {
			return "UNADMITTED_CUSTOM_BUILD_TAG"
		}
		if seen[tag] {
			return "DUPLICATE_CUSTOM_BUILD_TAG"
		}
		seen[tag] = true
	}
	slices.Sort(context.CustomTags)
	// Go 1.22 amd64 compiler feature tags are a cumulative selected series.
	// No other tool-generated tags are admitted by this release profile.
	if req.TargetArch == "amd64" && len(context.ToolTags) == 0 ||
		req.TargetArch == "arm64" && len(context.ToolTags) != 0 {
		return "UNSUPPORTED_GO_TOOL_TAGS"
	}
	slices.Sort(context.ToolTags)
	for index, tag := range context.ToolTags {
		if tag != "amd64.v"+strconv.Itoa(index+1) {
			return "UNSUPPORTED_GO_TOOL_TAGS"
		}
	}
	return ""
}

func validGoBuildSourcePath(value string) bool {
	use := value
	name := filename(value)
	if strings.HasPrefix(name, ".") {
		// The final hidden basename is needed for a native excluded-file receipt.
		// Parent path segments remain within the same admitted grammar.
		use = value[:len(value)-len(name)] + strings.TrimPrefix(name, ".")
	}
	return len(value) <= 240 && len(name) <= 96 && validSlashPath(use) &&
		strings.HasSuffix(name, ".go") && name != ".go"
}

func decodeGoBuildWire(raw []byte, out any) string {
	if !utf8.Valid(raw) {
		return "INVALID_JSON"
	}
	shape := json.NewDecoder(bytes.NewReader(raw))
	shape.UseNumber()
	if err := rejectDuplicateKeys(shape, 0); err != nil {
		return "INVALID_OR_EXCESSIVE_JSON"
	}
	if _, err := shape.Token(); err != io.EOF {
		return "TRAILING_JSON"
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return "UNEXPECTED_REQUEST_FIELDS"
	}
	return ""
}

func decodeGoBuildFiles(files []sourceFile, singleDirectory bool) string {
	root := path.Dir(files[0].Path)
	folded := make(map[string]bool, len(files))
	total := 0
	for index := range files {
		file := &files[index]
		if !validGoBuildSourcePath(file.Path) || !hostSHA.MatchString(file.SHA256) {
			return "INVALID_SOURCE_IDENTITY"
		}
		if singleDirectory && path.Dir(file.Path) != root {
			return "PACKAGE_DIRECTORY_CONTEXT_REQUIRED"
		}
		key := strings.ToLower(file.Path)
		if folded[key] {
			return "SOURCE_PATH_COLLISION"
		}
		folded[key] = true
		if len(file.Base64) > base64.StdEncoding.EncodedLen(maxFileBytes) {
			return "FILE_BYTE_LIMIT"
		}
		value, err := base64.StdEncoding.Strict().DecodeString(file.Base64)
		if err != nil || base64.StdEncoding.EncodeToString(value) != file.Base64 {
			return "INVALID_BASE64"
		}
		if len(value) > maxFileBytes {
			return "FILE_BYTE_LIMIT"
		}
		total += len(value)
		if total > maxSourceBytes {
			return "SOURCE_BYTE_LIMIT"
		}
		if sha(value) != file.SHA256 {
			return "SOURCE_DIGEST_MISMATCH"
		}
		file.bytes = value
	}
	slices.SortFunc(files, func(left, right sourceFile) int {
		return strings.Compare(left.Path, right.Path)
	})
	return ""
}

func decodeGoBuildRequest(raw []byte) (goBuildRequest, string) {
	var result goBuildRequest
	if code := decodeGoBuildWire(raw, &result); code != "" {
		return result, code
	}
	if failure := validateGoBuildContext(&result); failure != "" {
		return result, failure
	}
	return result, decodeGoBuildFiles(result.Files, true)
}

var errUnknownVirtualGoFile = errors.New("unbound virtual Go file")
var errUnexpectedGoBuildAccess = errors.New("unexpected Go build filesystem operation")

func goBuildMatcher(req goBuildRequest, source sourceFile) build.Context {
	releaseTags := make([]string, 0, req.BuildContext.ReleaseMinor)
	for version := 1; version <= req.BuildContext.ReleaseMinor; version++ {
		releaseTags = append(releaseTags, "go1."+strconv.Itoa(version))
	}
	name := filename(source.Path)
	opened := false
	return build.Context{
		GOOS: req.TargetOS, GOARCH: req.TargetArch, Compiler: req.BuildContext.Compiler,
		CgoEnabled: false, UseAllFiles: false,
		BuildTags: req.BuildContext.CustomTags, ToolTags: req.BuildContext.ToolTags, ReleaseTags: releaseTags,
		JoinPath: func(parts ...string) string {
			if len(parts) == 2 && parts[0] == virtualGoDirectory && parts[1] == name {
				return virtualGoDirectory + "/" + name
			}
			return ""
		},
		OpenFile: func(file string) (io.ReadCloser, error) {
			if opened || file != virtualGoDirectory+"/"+name {
				return nil, errUnknownVirtualGoFile
			}
			opened = true
			return io.NopCloser(bytes.NewReader(source.bytes)), nil
		},
		// MatchFile has no legitimate need for any of these callbacks. None
		// fall back to the filesystem if the native selection path evolves.
		IsAbsPath:     func(string) bool { panic(errUnexpectedGoBuildAccess) },
		IsDir:         func(string) bool { panic(errUnexpectedGoBuildAccess) },
		HasSubdir:     func(string, string) (string, bool) { panic(errUnexpectedGoBuildAccess) },
		ReadDir:       func(string) ([]fs.FileInfo, error) { panic(errUnexpectedGoBuildAccess) },
		SplitPathList: func(string) []string { panic(errUnexpectedGoBuildAccess) },
	}
}

func matchVirtualGoFile(req goBuildRequest, source sourceFile) (matched bool, err error) {
	defer func() {
		if failure := recover(); failure == errUnexpectedGoBuildAccess {
			err = errUnexpectedGoBuildAccess
		} else if failure != nil {
			panic(failure)
		}
	}()
	matcher := goBuildMatcher(req, source)
	return matcher.MatchFile(virtualGoDirectory, filename(source.Path))
}

func hasDualGoConstraints(file *ast.File) bool {
	modern, legacy := false, false
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if comment.Pos() < file.Package {
				modern = modern || constraint.IsGoBuild(comment.Text)
				legacy = legacy || constraint.IsPlusBuild(comment.Text)
			}
		}
	}
	return modern && legacy
}

func goSelectionFailureStatus(code string) string {
	switch code {
	case "EXCLUDED_BY_NAME_OR_CONSTRAINT", "PRODUCTION_TEST_EXCLUDED", "SELECTED_GO_SOURCE":
		return ""
	case "NATIVE_SELECTION_ERROR", "GO_PARSE_FAILURE":
		return "INVALID_SOURCE"
	case "GO_AST_LIMIT":
		return "RESOURCE_LIMIT"
	default:
		return "UNSUPPORTED"
	}
}

func selectedGoFile(req goBuildRequest, source sourceFile, positions *token.FileSet, nodes *int, localImports bool) (goFileSelection, *ast.File) {
	result := goFileSelection{Path: source.Path, SHA256: source.SHA256, Disposition: "EXCLUDED_BY_NAME_OR_CONSTRAINT"}
	matched, err := matchVirtualGoFile(req, source)
	if errors.Is(err, errUnknownVirtualGoFile) || errors.Is(err, errUnexpectedGoBuildAccess) {
		result.Disposition = "VIRTUAL_SOURCE_UNAVAILABLE"
		return result, nil
	}
	result.NativeMatch = &matched
	if err != nil {
		result.Disposition = "NATIVE_SELECTION_ERROR"
		return result, nil
	}
	if !matched {
		return result, nil
	}
	if strings.HasSuffix(source.Path, "_test.go") {
		result.Disposition = "TEST_CONTEXT_REQUIRED"
		if req.BuildContext.TestMode == "PRODUCTION_ONLY" {
			result.Disposition = "PRODUCTION_TEST_EXCLUDED"
		}
		return result, nil
	}

	file, err := parser.ParseFile(positions, source.Path, source.bytes, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		result.Disposition = "GO_PARSE_FAILURE"
		return result, nil
	}
	if hasDualGoConstraints(file) {
		result.Disposition = "DUAL_CONSTRAINTS_UNSUPPORTED"
		return result, nil
	}
	if ast.IsGenerated(file) {
		result.Disposition = "GENERATED_SOURCE_CONTEXT_REQUIRED"
		return result, nil
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if comment.Pos() < file.Package &&
				(constraint.IsGoBuild(comment.Text) || constraint.IsPlusBuild(comment.Text)) {
				continue
			}
			if strings.HasPrefix(comment.Text, "//go:") || strings.HasPrefix(comment.Text, "//line ") ||
				strings.HasPrefix(comment.Text, "/*line ") || constraint.IsPlusBuild(comment.Text) {
				result.Disposition = "COMPILER_DIRECTIVE_CONTEXT_REQUIRED"
				return result, nil
			}
		}
	}
	if !localImports {
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				result.Disposition = "GO_PARSE_FAILURE"
			} else if name == "C" {
				result.Disposition = "CGO_CONTEXT_UNSUPPORTED"
			} else {
				result.Disposition = "DEPENDENCY_CONTEXT_REQUIRED"
			}
			return result, nil
		}
	}
	depth := 0
	exceeded := false
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			depth--
			return true
		}
		*nodes = *nodes + 1
		if *nodes > maxASTNodes || depth >= maxASTDepth {
			exceeded = true
			return false
		}
		depth++
		return true
	})
	if exceeded {
		result.Disposition = "GO_AST_LIMIT"
		return result, nil
	}
	result.Disposition = "SELECTED_GO_SOURCE"
	return result, file
}

func baseGoBuildResult(requestSHA string) goBuildResponse {
	base := baseResponse(requestSHA)
	base.Version = 2
	base.Producer = "fortress.go-build-selection@0.1.0"
	base.Limitations = []string{
		"HOST_MUST_ESTABLISH_PACKAGE_AND_CONTEXT_COMPLETENESS",
		"FILE_SELECTION_DOES_NOT_ESTABLISH_PACKAGE_OR_BUILD_COMPLETENESS",
		"NO_DEPENDENCIES_FOREIGN_GENERATED_OR_TEST_EXECUTION_CONTEXT",
		"BODYLESS_DECLARATIONS_DO_NOT_ESTABLISH_IMPLEMENTATION",
		"NO_RUNTIME_EFFECT_REACHABILITY_OR_EXECUTION_PROOF",
		"INTERFACE_FUNCTION_VALUE_AND_OTHER_UNSUPPORTED_DISPATCH_REMAINS_UNRESOLVED",
	}
	return goBuildResponse{response: base, Selection: []goFileSelection{}}
}

func observeGoBuild(raw []byte) goBuildResponse {
	base := baseGoBuildResult(sha(raw))
	req, code := decodeGoBuildRequest(raw)
	if code != "" {
		status := "INVALID_REQUEST"
		switch {
		case strings.HasSuffix(code, "_LIMIT"):
			status = "RESOURCE_LIMIT"
		case code == "UNSUPPORTED_TARGET_CONTEXT", code == "PACKAGE_DIRECTORY_CONTEXT_REQUIRED",
			code == "CGO_CONTEXT_UNSUPPORTED", code == "TEST_CONTEXT_REQUIRED",
			code == "UNSUPPORTED_GO_TOOL_TAGS", code == "UNADMITTED_CUSTOM_BUILD_TAG":
			status = "UNSUPPORTED"
		}
		base.response = refuse(base.response, status, code, nil)
		return base
	}
	context := contextualIdentity{req.PackagePath, req.GoVersion, req.TargetOS, req.TargetArch, make([]identity, 0, len(req.Files))}
	for _, source := range req.Files {
		context.Files = append(context.Files, identity{source.Path, source.SHA256})
	}
	contextBytes, _ := json.Marshal(struct {
		SourceContext *contextualIdentity `json:"source_context"`
		BuildContext  *goBuildContext     `json:"build_context"`
	}{&context, req.BuildContext})
	base.ContextSHA = sha(contextBytes)
	base.Context = &context
	base.BuildContext = req.BuildContext
	positions := token.NewFileSet()
	selected := make([]*ast.File, 0, len(req.Files))
	nodes := 0
	for _, source := range req.Files {
		selection, file := selectedGoFile(req, source, positions, &nodes, false)
		base.Selection = append(base.Selection, selection)
		if status := goSelectionFailureStatus(selection.Disposition); status != "" && base.Status == "" {
			base.response = refuse(base.response, status, selection.Disposition, nil)
		}
		if file != nil {
			selected = append(selected, file)
		}
	}
	if base.Status != "" {
		return base
	}
	if len(selected) == 0 {
		base.response = refuse(base.response, "UNSUPPORTED", "NO_SELECTED_GO_SOURCE", nil)
		return base
	}
	base.response = project(req.request, positions, selected, base.response)
	return base
}

func executeSelectedGoBuild() int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxWireBytes+1))
	var result goBuildResponse
	switch {
	case err != nil:
		result = baseGoBuildResult("")
		result.response = refuse(result.response, "INVALID_REQUEST", "STDIN_READ_FAILURE", nil)
	case len(raw) > maxWireBytes:
		result = baseGoBuildResult("")
		result.response = refuse(result.response, "RESOURCE_LIMIT", "REQUEST_BYTE_LIMIT", nil)
	default:
		result = observeGoBuild(raw)
	}
	wire, err := json.Marshal(result)
	if err != nil {
		return 2
	}
	if len(wire)+1 > maxWireBytes {
		limited := baseGoBuildResult(result.RequestSHA)
		limited.response = refuse(limited.response, "RESOURCE_LIMIT", "RESPONSE_BYTE_LIMIT", nil)
		wire, _ = json.Marshal(limited)
	}
	if _, err := os.Stdout.Write(append(wire, '\n')); err != nil {
		return 2
	}
	return 0
}

// A combined worker optionally links the module-local mode while two-file workers
// retain their original protocol. Package variable initialization precedes init.
var goLocalImportsMode func() int

// This file is linked only into trusted builds exposing the explicit v2 mode.
// The single-file v1 collector and its byte identity remain untouched.
func init() {
	if len(os.Args) == 1 {
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--observe-go-module" && goLocalImportsMode != nil {
		os.Exit(goLocalImportsMode())
	}
	if len(os.Args) != 2 || os.Args[1] != goBuildSelectionFlag {
		fmt.Fprintln(os.Stderr, "unsupported Go collector invocation")
		os.Exit(2)
	}
	os.Exit(executeSelectedGoBuild())
}
