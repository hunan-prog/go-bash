package bashruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForegroundOutputIsTruncatedToInlineLimit(t *testing.T) {
	rt, err := New(Config{
		Permissions:    PermissionsConfig{Allow: []string{"Bash(printf:*)"}},
		ResourceLimits: ResourceLimitsConfig{MaxInlineBytes: 8},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Run(context.Background(), Request{Command: "printf 1234567890"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatalf("Truncated = false, want true; result=%+v", res)
	}
	if res.Stdout != "34567890" {
		t.Fatalf("stdout = %q, want tail", res.Stdout)
	}
}

func TestOpenOutputFileRefusesExistingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "out")
	if err := os.WriteFile(target, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	file, err := openOutputFile(link)
	if err == nil {
		file.Close()
		t.Fatal("openOutputFile succeeded on symlink")
	}
	if !strings.Contains(err.Error(), "exist") && !strings.Contains(err.Error(), "too many") {
		t.Fatalf("error = %v, want symlink/exist refusal", err)
	}
}
