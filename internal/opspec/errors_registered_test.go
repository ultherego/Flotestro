package opspec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The guard next door walks catalogue to page. This one walks the other way:
// from the source of the host to the catalogue. A refusal the host writes onto
// a result and the catalogue does not list is a word the operator reads in the
// panel and can look up nowhere, and only this direction sees it.
//
// It is on purpose not a list of codes. It finds the places a code is written
// into a result - the field the panel reads it from, and the arguments of the
// functions that fill that field - and resolves what each place can put there,
// so a constant added to a const block that already existed is caught by the
// walk that caught its neighbours. Adding a name to a list in this file cannot
// silence it: either the code gets an entry, or it is declared an alias of the
// code the panel really reports in its place.

// resultCodeField is the field of a task result and of a helper response that
// the panel reads the refusal from. Writing it is what makes a code reach the
// operator, so every such write is a position this walk resolves.
const resultCodeField = "ErrorCode"

// carrierFields are the fields a code travels in on its way to that one: the
// module adapters hand their refusals up in a typed value with a Code.
var carrierFields = map[string]bool{resultCodeField: true, "Code": true}

// localMarkerType is the type the agent declares the words with that it leaves
// in the code of a result for its own session loop, which reads them and sends
// nothing back. A constant of that type never reaches an operator, so it is not
// a refusal and belongs in no catalogue; saying so is the declaring package's
// job, not this test's.
const localMarkerType = "LocalMarker"

// forwardingCall is the getter that reads a code another component already
// set. A position that forwards produces no code of its own: whatever it
// carries was written at a position this walk covers as well.
const forwardingCall = "Get" + resultCodeField

// codeProducers are the packages walked for code positions: the agent builds
// every task result, the helper every response the agent passes on.
var codeProducers = []string{
	filepath.Join("..", "agent"),
	filepath.Join("..", "helper"),
}

// codeSources are the packages a code position may name a constant or a
// function from. They are parsed for what they declare, not for positions.
var codeSources = []string{
	filepath.Join("..", "helpercap"),
	filepath.Join("..", "modules"),
	filepath.Join("..", "packages"),
	filepath.Join("..", "plan"),
	filepath.Join("..", "systemd"),
}

// sourcePackage is what one parsed package offers: its files, the expression
// behind every constant it declares, the returns of every function it declares,
// and the import names its files call other packages by.
type sourcePackage struct {
	files     []*ast.File
	constants map[string]ast.Expr
	returns   map[string][]functionReturn
	imports   map[string]string
}

// functionReturn is one return of a function, with the body it stands in: a
// result that names a local of that function is only readable there.
type functionReturn struct {
	results []ast.Expr
	body    *ast.BlockStmt
}

// tree is every package this walk knows, plus every value it has seen written
// into a carrier field, which is how a code that travels in a struct field is
// resolved where the field is passed on.
type tree struct {
	packages    map[string]*sourcePackage
	fieldValues map[string][]scopedExpr
	locals      map[*ast.BlockStmt]map[string][]scopedExpr
}

// scopedExpr is an expression together with everything needed to read it: the
// package it was written in, the body whose local names it may use and, when it
// is a call of several results, which of them is meant.
type scopedExpr struct {
	expr   ast.Expr
	pkg    *sourcePackage
	body   *ast.BlockStmt
	result int
}

// codeOrigin is one resolved code and the place that writes it.
type codeOrigin struct {
	code  string
	where string
}

func TestEveryRefusalTheHostReportsIsInTheCatalogue(t *testing.T) {
	fset := token.NewFileSet()
	parsed := newTree()
	for _, dir := range append(codeProducers, codeSources...) {
		if err := parseInto(fset, dir, parsed, true); err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
	}
	// The catalogue's own package holds the codes the verifier puts on a result,
	// so the agent can name one. Its entries are the catalogue, not a producer,
	// so nothing is harvested from them.
	if err := parseInto(fset, ".", parsed, false); err != nil {
		t.Fatalf("reading the catalogue's own package: %v", err)
	}

	registered := map[string]bool{}
	for _, guide := range ErrorGuides() {
		registered[guide.Code] = true
	}

	var found []codeOrigin
	var unresolved []string
	for _, dir := range codeProducers {
		pkg, ok := parsed.packages[filepath.Base(dir)]
		if !ok {
			t.Fatalf("%s holds no package this test could parse", dir)
		}
		codes, open := codesWrittenBy(fset, pkg, parsed)
		found = append(found, codes...)
		unresolved = append(unresolved, open...)
	}
	if len(found) == 0 {
		t.Fatal("no refusal code was found at all; the code positions have changed shape")
	}

	missing := map[string][]string{}
	for _, origin := range found {
		if registered[origin.code] {
			continue
		}
		missing[origin.code] = append(missing[origin.code], origin.where)
	}
	for _, code := range sortedNames(missing) {
		t.Errorf("%s reaches the operator and internal/opspec/errors.go does not list it (%s);\n"+
			"  give it an entry, or - when the panel really reports another code in its place - make it an alias of that one",
			code, strings.Join(firstFew(missing[code]), ", "))
	}

	// A code position the walk cannot read is a hole, not a pass: it would let
	// the next code through without a word.
	sort.Strings(unresolved)
	if len(unresolved) > 0 {
		t.Errorf("%d code positions could not be resolved, so this guard does not cover them:\n  %s",
			len(unresolved), strings.Join(unresolved, "\n  "))
	}
}

func newTree() *tree {
	return &tree{
		packages:    map[string]*sourcePackage{},
		fieldValues: map[string][]scopedExpr{},
		locals:      map[*ast.BlockStmt]map[string][]scopedExpr{},
	}
}

// parseInto parses one directory, and its subdirectories when it holds the
// adapters of the modules rather than Go files of its own.
func parseInto(fset *token.FileSet, dir string, parsed *tree, harvest bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var paths []string
	for _, entry := range entries {
		switch {
		case entry.IsDir():
			if err := parseInto(fset, filepath.Join(dir, entry.Name()), parsed, harvest); err != nil {
				return err
			}
		case strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go"):
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	if len(paths) == 0 {
		return nil
	}
	pkg := &sourcePackage{
		constants: map[string]ast.Expr{},
		returns:   map[string][]functionReturn{},
		imports:   map[string]string{},
	}
	name := ""
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		name = file.Name.Name
		pkg.files = append(pkg.files, file)
		collectConstants(file, pkg.constants)
		collectReturns(file, pkg.returns)
		collectImports(file, pkg.imports)
	}
	// Two directories may hold a package of one name; merging them is enough,
	// because a code position names one of the two.
	existing, ok := parsed.packages[name]
	if !ok {
		parsed.packages[name] = pkg
		existing = pkg
	} else {
		existing.files = append(existing.files, pkg.files...)
		for key, expr := range pkg.constants {
			existing.constants[key] = expr
		}
		for key, returns := range pkg.returns {
			existing.returns[key] = append(existing.returns[key], returns...)
		}
		for alias, target := range pkg.imports {
			existing.imports[alias] = target
		}
	}
	if harvest {
		collectFieldValues(pkg.files, existing, parsed.fieldValues)
	}
	return nil
}

// collectConstants records the expression behind every constant, which may be
// a literal or another constant.
func collectConstants(file *ast.File, into map[string]ast.Expr) {
	for _, decl := range file.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if named, ok := value.Type.(*ast.Ident); ok && named.Name == localMarkerType {
				// Declared a marker of the host's own loop: it leaves no code behind.
				for _, name := range value.Names {
					into[name.Name] = nil
				}
				continue
			}
			for i, name := range value.Names {
				if i < len(value.Values) {
					into[name.Name] = value.Values[i]
				}
			}
		}
	}
}

// collectReturns records what every function returns, result by result and
// with the body it returns from, so a code position that calls one can be
// followed into it without losing the local names it is written in.
func collectReturns(file *ast.File, into map[string][]functionReturn) {
	for _, decl := range file.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Body == nil || function.Recv != nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			statement, ok := node.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			if len(statement.Results) > 0 {
				into[function.Name.Name] = append(into[function.Name.Name],
					functionReturn{results: statement.Results, body: function.Body})
			}
			return true
		})
	}
}

// collectImports records the name each file calls another package by, so a
// constant reached through an import alias still resolves.
func collectImports(file *ast.File, into map[string]string) {
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		target := filepath.Base(path)
		if spec.Name != nil {
			into[spec.Name.Name] = target
			continue
		}
		into[target] = target
	}
}

// collectFieldValues records every expression written into a carrier field, so
// a code a module hands up inside a struct can be resolved where the helper
// passes that struct's field on.
func collectFieldValues(files []*ast.File, pkg *sourcePackage, into map[string][]scopedExpr) {
	for _, file := range files {
		for _, position := range fieldWrites(file, carrierFields) {
			into[position.field] = append(into[position.field],
				scopedExpr{expr: position.expr, pkg: pkg})
		}
	}
}

// fieldWrite is one expression written into a named field, either in a
// composite literal or by an assignment.
type fieldWrite struct {
	field string
	expr  ast.Expr
}

// fieldWrites finds every write into one of the named fields under a node.
func fieldWrites(node ast.Node, fields map[string]bool) []fieldWrite {
	var writes []fieldWrite
	ast.Inspect(node, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.KeyValueExpr:
			if key, ok := typed.Key.(*ast.Ident); ok && fields[key.Name] {
				writes = append(writes, fieldWrite{field: key.Name, expr: typed.Value})
			}
		case *ast.AssignStmt:
			for i, target := range typed.Lhs {
				selector, ok := target.(*ast.SelectorExpr)
				if !ok || !fields[selector.Sel.Name] || i >= len(typed.Rhs) {
					continue
				}
				writes = append(writes, fieldWrite{field: selector.Sel.Name, expr: typed.Rhs[i]})
			}
		}
		return true
	})
	return writes
}

// codePosition is one expression written into the code of a result.
type codePosition struct {
	scopedExpr
	where string
}

// codesWrittenBy resolves every code position of one producing package.
func codesWrittenBy(fset *token.FileSet, pkg *sourcePackage,
	parsed *tree) (found []codeOrigin, unresolved []string) {
	for _, position := range codePositionsOf(fset, pkg) {
		codes, ok := resolve(position.scopedExpr, parsed, 0)
		if !ok {
			unresolved = append(unresolved, position.where)
			continue
		}
		for _, code := range codes {
			found = append(found, codeOrigin{code: code, where: position.where})
		}
	}
	return found, unresolved
}

// codePositionsOf finds every place a producing package writes a code into a
// result. A function that writes a parameter of its own there is not such a
// place but a constructor of refusals - reject, rejected and the handful built
// on them - so the positions are its call sites instead, which is what the
// first pass below works out before the second one reads them.
func codePositionsOf(fset *token.FileSet, pkg *sourcePackage) []codePosition {
	constructors := refusalConstructorsOf(pkg)
	var positions []codePosition
	for _, function := range functionsOf(pkg) {
		if _, isConstructor := constructors[function.Name.Name]; isConstructor {
			continue
		}
		for _, expr := range writesOfCode(function.Body, constructors) {
			positions = append(positions, codePosition{
				scopedExpr: scopedExpr{expr: expr, pkg: pkg, body: function.Body},
				where:      relativeTo(fset.Position(expr.Pos()).String()),
			})
		}
	}
	return positions
}

// refusalConstructorsOf works out which functions of a package only pass a
// code they were given on: the name of each, and which argument carries it.
// It settles, because a function built on a constructor becomes one itself.
func refusalConstructorsOf(pkg *sourcePackage) map[string]int {
	constructors := map[string]int{}
	for {
		grown := false
		for _, function := range functionsOf(pkg) {
			if _, known := constructors[function.Name.Name]; known {
				continue
			}
			index, ok := forwardedParameter(function, constructors)
			if !ok {
				continue
			}
			constructors[function.Name.Name] = index
			grown = true
		}
		if !grown {
			return constructors
		}
	}
}

// forwardedParameter says whether a function writes one of its own parameters
// into the code of a result, and which parameter it is.
func forwardedParameter(function *ast.FuncDecl, constructors map[string]int) (int, bool) {
	parameters := map[string]int{}
	index := 0
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			parameters[name.Name] = index
			index++
		}
	}
	for _, expr := range writesOfCode(function.Body, constructors) {
		name, ok := expr.(*ast.Ident)
		if !ok {
			continue
		}
		if at, ok := parameters[name.Name]; ok {
			return at, true
		}
	}
	return 0, false
}

// writesOfCode finds every expression a body writes into the code of a result:
// into the field the panel reads, or as the code argument of a constructor.
func writesOfCode(body *ast.BlockStmt, constructors map[string]int) []ast.Expr {
	if body == nil {
		return nil
	}
	var written []ast.Expr
	for _, write := range fieldWrites(body, map[string]bool{resultCodeField: true}) {
		written = append(written, write.expr)
	}
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := calleeName(call.Fun)
		if !ok {
			return true
		}
		if at, ok := constructors[name]; ok && at < len(call.Args) {
			written = append(written, call.Args[at])
		}
		return true
	})
	return written
}

// functionsOf lists the functions a package declares, methods included.
func functionsOf(pkg *sourcePackage) []*ast.FuncDecl {
	var functions []*ast.FuncDecl
	for _, file := range pkg.files {
		for _, decl := range file.Decls {
			if function, ok := decl.(*ast.FuncDecl); ok && function.Body != nil {
				functions = append(functions, function)
			}
		}
	}
	return functions
}

// localValues records every value a local name takes inside one body, so a
// code built up in a variable resolves to all of the codes it can hold. The
// answer is kept, because a body is read once per code position that leads into
// it.
func localValues(body *ast.BlockStmt, pkg *sourcePackage, parsed *tree) map[string][]scopedExpr {
	if known, ok := parsed.locals[body]; ok {
		return known
	}
	locals := map[string][]scopedExpr{}
	parsed.locals[body] = locals
	record := func(names, values []ast.Expr) {
		// One call feeding several names: each name takes its own result of it.
		if len(values) == 1 && len(names) > 1 {
			if call, ok := values[0].(*ast.CallExpr); ok {
				for i, target := range names {
					if name, ok := target.(*ast.Ident); ok {
						locals[name.Name] = append(locals[name.Name],
							scopedExpr{expr: call, pkg: pkg, body: body, result: i})
					}
				}
				return
			}
		}
		for i, target := range names {
			name, ok := target.(*ast.Ident)
			if !ok || i >= len(values) {
				continue
			}
			locals[name.Name] = append(locals[name.Name],
				scopedExpr{expr: values[i], pkg: pkg, body: body})
		}
	}
	ast.Inspect(body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.AssignStmt:
			record(typed.Lhs, typed.Rhs)
		case *ast.ValueSpec:
			names := make([]ast.Expr, 0, len(typed.Names))
			for _, name := range typed.Names {
				names = append(names, name)
			}
			record(names, typed.Values)
		}
		return true
	})
	return locals
}

// maxResolutionDepth bounds the walk through the constants, the functions and
// the variables a code position leads into.
const maxResolutionDepth = 12

// resolve reads the codes one expression can put on a result. It reports false
// when it cannot tell, which the caller treats as a hole rather than a pass.
func resolve(scoped scopedExpr, parsed *tree, depth int) ([]string, bool) {
	if depth > maxResolutionDepth {
		return nil, false
	}
	pkg := scoped.pkg
	switch typed := scoped.expr.(type) {
	case *ast.BasicLit:
		if text, ok := stringLiteral(typed); ok {
			return withoutEmpty(text), true
		}
	case *ast.ParenExpr:
		inner := scoped
		inner.expr = typed.X
		return resolve(inner, parsed, depth)
	case *ast.Ident:
		if scoped.body != nil {
			if values, ok := localValues(scoped.body, pkg, parsed)[typed.Name]; ok {
				return resolveAll(values, parsed, depth+1)
			}
		}
		if expr, ok := pkg.constants[typed.Name]; ok {
			if expr == nil {
				return nil, true
			}
			return resolve(scopedExpr{expr: expr, pkg: pkg}, parsed, depth+1)
		}
		if returns, ok := pkg.returns[typed.Name]; ok {
			return resolveAll(resultsOf(returns, 0, pkg), parsed, depth+1)
		}
	case *ast.SelectorExpr:
		return resolveSelector(typed, pkg, parsed, depth)
	case *ast.CallExpr:
		name, ok := calleeName(typed.Fun)
		if !ok {
			break
		}
		// A getter of the code field reads what another component already set;
		// that writer is a position of its own.
		if name == forwardingCall {
			return nil, true
		}
		if returns, ok := pkg.returns[name]; ok {
			return resolveAll(resultsOf(returns, scoped.result, pkg), parsed, depth+1)
		}
		if selector, ok := typed.Fun.(*ast.SelectorExpr); ok {
			if source, ok := sourceOf(selector, pkg, parsed); ok {
				if returns, ok := source.returns[name]; ok {
					return resolveAll(resultsOf(returns, scoped.result, source), parsed, depth+1)
				}
			}
		}
	}
	return nil, false
}

// resolveSelector reads a constant of another package, or - when the qualifier
// is a value rather than a package - every code that field is ever given.
func resolveSelector(selector *ast.SelectorExpr, pkg *sourcePackage,
	parsed *tree, depth int) ([]string, bool) {
	if source, ok := sourceOf(selector, pkg, parsed); ok {
		if expr, ok := source.constants[selector.Sel.Name]; ok {
			if expr == nil {
				return nil, true
			}
			return resolve(scopedExpr{expr: expr, pkg: source}, parsed, depth+1)
		}
		if returns, ok := source.returns[selector.Sel.Name]; ok {
			return resolveAll(resultsOf(returns, 0, source), parsed, depth+1)
		}
		return nil, false
	}
	if !carrierFields[selector.Sel.Name] {
		return nil, false
	}
	// The code travels in a field of a typed refusal, so what the field can
	// hold is everything anybody writes into a field of that name.
	return resolveAll(parsed.fieldValues[selector.Sel.Name], parsed, depth+1)
}

// sourceOf reads the package a selector names, whether by its own name or by
// the name the file imports it under.
func sourceOf(selector *ast.SelectorExpr, pkg *sourcePackage,
	parsed *tree) (*sourcePackage, bool) {
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return nil, false
	}
	name := qualifier.Name
	if target, ok := pkg.imports[name]; ok {
		name = target
	}
	source, ok := parsed.packages[name]
	return source, ok
}

// resultsOf picks one result out of every return of a function, keeping the
// body each stands in so its local names stay readable.
func resultsOf(returns []functionReturn, index int, pkg *sourcePackage) []scopedExpr {
	var exprs []scopedExpr
	for _, returned := range returns {
		switch {
		case index < len(returned.results):
			exprs = append(exprs, scopedExpr{
				expr: returned.results[index], pkg: pkg, body: returned.body})
		case len(returned.results) == 1:
			// A bare return of another call of the same shape passes every result
			// on, so that call is what carries the one asked for.
			exprs = append(exprs, scopedExpr{
				expr: returned.results[0], pkg: pkg, body: returned.body, result: index})
		}
	}
	return exprs
}

// resolveAll resolves a set of expressions and keeps what it could read. It
// fails only when it could read none of them: an unreadable branch of a
// variable that also holds constants must not hide the constants.
func resolveAll(exprs []scopedExpr, parsed *tree, depth int) ([]string, bool) {
	var codes []string
	resolved := false
	for _, scoped := range exprs {
		values, ok := resolve(scoped, parsed, depth)
		if !ok {
			continue
		}
		resolved = true
		codes = append(codes, values...)
	}
	return codes, resolved
}

// calleeName reads the name of a called function, plain or through a package.
func calleeName(fun ast.Expr) (string, bool) {
	switch typed := fun.(type) {
	case *ast.Ident:
		return typed.Name, true
	case *ast.SelectorExpr:
		return typed.Sel.Name, true
	}
	return "", false
}

// stringLiteral reads an unquoted string literal.
func stringLiteral(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	text, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return text, true
}

// withoutEmpty turns the empty code - a result that refuses nothing - into no
// code at all.
func withoutEmpty(code string) []string {
	if code == "" {
		return nil
	}
	return []string{code}
}

// relativeTo names a position the way the rest of the suite does.
func relativeTo(position string) string {
	return strings.TrimPrefix(filepath.ToSlash(position), "../")
}

// firstFew keeps a failure short when one code is written in many places.
func firstFew(places []string) []string {
	sort.Strings(places)
	if len(places) > 3 {
		return append(places[:3:3], "and more")
	}
	return places
}

// sortedNames keeps a failure report in an order that does not move between
// runs.
func sortedNames(byCode map[string][]string) []string {
	names := make([]string, 0, len(byCode))
	for name := range byCode {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
