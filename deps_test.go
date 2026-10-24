package guard

import (
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestPackageDependencies checks what the README promises: every package
// depends on the standard library alone, apart from pow on replay, and
// only webguard links net/http.
func TestPackageDependencies(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("cannot run the go command")
	}
	goCmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	const module = "github.com/djylb/guard"
	allowed := map[string][]string{
		module:               nil,
		module + "/replay":   nil,
		module + "/pow":      {module + "/replay"},
		module + "/failban":  nil,
		module + "/otp":      nil,
		module + "/webguard": nil,
	}
	listed, err := exec.Command(goCmd, "list", module+"/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for line := range strings.Lines(string(listed)) {
		if _, ok := allowed[strings.TrimSpace(line)]; !ok {
			t.Errorf("package %s has no dependency rule", strings.TrimSpace(line))
		}
	}
	for pkg, internal := range allowed {
		// -test includes the dependencies of the package's tests.
		out, err := exec.Command(goCmd, "list", "-deps", "-test", "-f", "{{.ImportPath}} {{.Standard}}", pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for line := range strings.Lines(string(out)) {
			path, std, _ := strings.Cut(strings.TrimSpace(line), " ")
			path, _, _ = strings.Cut(path, " ") // "pkg [pkg.test]"
			switch {
			case path == pkg || path == pkg+".test" || strings.HasPrefix(path, pkg+"_test"):
			case path == "net/http" && pkg != module+"/webguard":
				t.Errorf("%s links net/http", pkg)
			case strings.HasPrefix(path, module):
				if pkg != module && !slices.Contains(internal, path) {
					t.Errorf("%s depends on %s", pkg, path)
				}
			case std != "true":
				t.Errorf("%s depends on %s outside the standard library", pkg, path)
			}
		}
	}
}
