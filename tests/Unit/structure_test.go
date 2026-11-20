package unit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type parsedFile struct {
	path string
	file *ast.File
}

// productionFiles parses every non-test Go file of the module.
func productionFiles(t *testing.T) []parsedFile {
	t.Helper()
	root := packageRoot(t)
	var out []parsedFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "tests":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		out = append(out, parsedFile{path: strings.TrimPrefix(path, root+string(filepath.Separator)), file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no Go file found, so every rule below would pass by having nothing to read")
	}
	return out
}

// TestThePackageUsesOnlyTheStandardLibrary holds the dependency rule of an
// Arandu library module: the standard library and golang.org/x/*, and no other
// module. This one needs none at all, and says so.
func TestThePackageUsesOnlyTheStandardLibrary(t *testing.T) {
	for _, source := range productionFiles(t) {
		for _, imp := range source.file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Errorf("%s: unreadable import %s", source.path, imp.Path.Value)
				continue
			}
			first, _, _ := strings.Cut(path, "/")
			if strings.Contains(first, ".") {
				t.Errorf("%s imports %s; production code imports the standard library only", source.path, path)
			}
		}
	}

	goMod := readFile(t, packageRoot(t), "go.mod")
	if regexp.MustCompile(`(?m)^\s*(require|replace)\b`).MatchString(goMod) {
		t.Errorf("go.mod has a require or replace line:\n%s", goMod)
	}
	if !strings.HasPrefix(goMod, "module github.com/hyz-is/arandu-smtpd\n") {
		t.Errorf("go.mod does not name github.com/hyz-is/arandu-smtpd:\n%s", goMod)
	}
}

// TestThePackageIsALibrary holds what a library of this kind does not have: no
// entity, no table, no policy, no route, nothing to register, no init and no
// package-level state that a caller could change.
func TestThePackageIsALibrary(t *testing.T) {
	root := packageRoot(t)
	for _, name := range []string{"module.go", "model.go", "policy.go", "service.go", "views.go",
		"resources", "migrations", "database", "routes", "CLAUDE.md"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			t.Errorf("%s exists; this package is a library with no entity, no table, no policy and no route", name)
		}
	}

	for _, source := range productionFiles(t) {
		for _, decl := range source.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && fn.Name.Name == "init" {
				t.Errorf("%s declares init: importing the package must do nothing", source.path)
			}
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				for _, name := range spec.(*ast.ValueSpec).Names {
					if name.IsExported() && !strings.HasPrefix(name.Name, "Err") {
						t.Errorf("%s: exported package variable %s; a caller could change it for everybody", source.path, name.Name)
					}
				}
			}
		}
	}
}

// TestNoFileSpeaksForAnAIVendor holds the repository rule: instructions for
// agents live in AGENTS.md, never in a file named after a vendor.
func TestNoFileSpeaksForAnAIVendor(t *testing.T) {
	root := packageRoot(t)
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if strings.EqualFold(d.Name(), "CLAUDE.md") || strings.EqualFold(d.Name(), "GEMINI.md") {
			t.Errorf("%s exists; agent instructions live in AGENTS.md only", path)
		}
		return nil
	})
	if _, err := os.Stat(filepath.Join(root, "AGENTS.md")); err != nil {
		t.Errorf("AGENTS.md is missing: %v", err)
	}
}

// capabilities is what arandu.mod.toml declares and what the code does, under
// the same four names.
type capabilities struct{ network, filesystem, exec, migrations bool }

func declaredCapabilities(t *testing.T) capabilities {
	t.Helper()
	var declared capabilities
	seen := map[string]bool{}
	inside := false
	for _, line := range strings.Split(readFile(t, packageRoot(t), "arandu.mod.toml"), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inside = line == "[permissions]"
			continue
		}
		if !inside {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		seen[key] = true
		switch key {
		case "network":
			declared.network = value == "true"
		case "filesystem":
			declared.filesystem = value == "true"
		case "exec":
			declared.exec = value == "true"
		case "migrations":
			declared.migrations = value == "true"
		}
	}
	for _, key := range []string{"network", "filesystem", "exec", "migrations"} {
		if !seen[key] {
			t.Errorf("arandu.mod.toml leaves %s undeclared under [permissions]", key)
		}
	}
	return declared
}

// usedCapabilities reads the production code as syntax and reports what it
// calls: a listener or a dial is network, a read of a path is filesystem, a
// package that starts a process is exec, a database package is migrations.
func usedCapabilities(t *testing.T) capabilities {
	t.Helper()
	var used capabilities
	for _, source := range productionFiles(t) {
		imports := map[string]string{} // local name -> path
		for _, imp := range source.file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			name := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			imports[name] = path
			switch path {
			case "os/exec", "os/signal", "syscall":
				if path == "os/exec" {
					used.exec = true
				}
			case "database/sql":
				used.migrations = true
			}
		}
		ast.Inspect(source.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch imports[pkg.Name] {
			case "net":
				switch sel.Sel.Name {
				case "Listen", "ListenTCP", "ListenPacket", "Dial", "DialTimeout", "DialTCP", "LookupHost", "LookupAddr", "LookupMX":
					used.network = true
				}
			case "crypto/tls":
				switch sel.Sel.Name {
				case "Dial", "DialWithDialer", "Listen":
					used.network = true
				}
			case "os":
				switch sel.Sel.Name {
				case "ReadFile", "Open", "OpenFile", "Create", "WriteFile", "ReadDir", "Stat", "Lstat", "Remove", "Mkdir", "MkdirAll", "Rename":
					used.filesystem = true
				}
			}
			return true
		})
		// A Listener handed in by the application is network too: Serve accepts
		// on it. The package says so by calling Accept.
		ast.Inspect(source.file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Accept" {
				used.network = true
			}
			return true
		})
	}
	return used
}

// TestTheDeclaredCapabilitiesAreWhatTheCodeDoes is the audit an installer
// cannot run: `aru doctor` never opens the manifest of a package it installed,
// so this comparison happens here or nowhere. Both directions fail.
func TestTheDeclaredCapabilitiesAreWhatTheCodeDoes(t *testing.T) {
	declared, used := declaredCapabilities(t), usedCapabilities(t)
	for _, c := range []struct {
		name           string
		declared, used bool
	}{
		{"network", declared.network, used.network},
		{"filesystem", declared.filesystem, used.filesystem},
		{"exec", declared.exec, used.exec},
		{"migrations", declared.migrations, used.migrations},
	} {
		switch {
		case c.used && !c.declared:
			t.Errorf("arandu.mod.toml declares %s = false and the code uses it", c.name)
		case c.declared && !c.used:
			t.Errorf("arandu.mod.toml declares %s = true and nothing uses it", c.name)
		}
	}
}

func TestTheManifestNamesTheModule(t *testing.T) {
	manifest := readFile(t, packageRoot(t), "arandu.mod.toml")
	if !regexp.MustCompile(`(?m)^name = "hyz-is/smtpd"$`).MatchString(manifest) {
		t.Errorf("arandu.mod.toml does not say name = \"hyz-is/smtpd\":\n%s", manifest)
	}
	if !regexp.MustCompile(`(?m)^framework = ">= [0-9]+\.[0-9]+"$`).MatchString(manifest) {
		t.Errorf("arandu.mod.toml has no framework floor")
	}
}

// TestEveryChangelogVersionHasUpgradeNotes keeps the two files describing the
// same set of releases.
func TestEveryChangelogVersionHasUpgradeNotes(t *testing.T) {
	root := packageRoot(t)
	changelog, upgrade := readFile(t, root, "CHANGELOG.md"), readFile(t, root, "UPGRADE.md")
	inChangelog := regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - `).FindAllStringSubmatch(changelog, -1)
	inUpgrade := regexp.MustCompile(`(?m)^## v([0-9]+\.[0-9]+\.[0-9]+)$`).FindAllStringSubmatch(upgrade, -1)
	if len(inChangelog) == 0 && len(inUpgrade) == 0 {
		t.Skip("nothing released yet: neither file has a version heading")
	}
	versions := func(m [][]string) map[string]bool {
		out := map[string]bool{}
		for _, x := range m {
			out[x[1]] = true
		}
		return out
	}
	logged, upgraded := versions(inChangelog), versions(inUpgrade)
	for v := range logged {
		if !upgraded[v] {
			t.Errorf("CHANGELOG.md has %s and UPGRADE.md has no notes for it", v)
		}
	}
	for v := range upgraded {
		if !logged[v] {
			t.Errorf("UPGRADE.md has notes for %s and CHANGELOG.md has no entry for it", v)
		}
	}
}

// TestEveryExportedSymbolHasADocComment holds the rule of the package: what
// pkg.go.dev publishes is what its users read.
func TestEveryExportedSymbolHasADocComment(t *testing.T) {
	for _, source := range productionFiles(t) {
		for _, decl := range source.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv != nil {
					if recv := receiverName(d); !ast.IsExported(recv) {
						continue
					}
				}
				if d.Doc == nil {
					t.Errorf("%s: exported func %s has no doc comment", source.path, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() && d.Doc == nil && s.Doc == nil {
							t.Errorf("%s: exported type %s has no doc comment", source.path, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, name := range s.Names {
							if name.IsExported() && d.Doc == nil && s.Doc == nil {
								t.Errorf("%s: exported %s has no doc comment", source.path, name.Name)
							}
						}
					}
				}
			}
		}
	}
}

func receiverName(d *ast.FuncDecl) string {
	switch x := d.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return x.Name
	}
	return ""
}
