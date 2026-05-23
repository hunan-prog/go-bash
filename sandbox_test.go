package bashruntime

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSystemSandboxProviderWrapsForCurrentOS(t *testing.T) {
	provider := systemSandboxProvider{
		cfg:       Config{Sandbox: SandboxConfig{Filesystem: FilesystemSandboxConfig{AllowWrite: []string{"/tmp/work"}}}},
		outputDir: "/tmp/out",
	}
	inv := SandboxInvocation{Argv: []string{"/bin/bash", "-lc", "echo ok"}, Cwd: "/tmp/work"}
	wrapped, err := provider.WrapCommand(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	switch runtime.GOOS {
	case "darwin":
		if wrapped.Argv[0] != "sandbox-exec" {
			t.Fatalf("argv[0] = %q, want sandbox-exec", wrapped.Argv[0])
		}
		if !strings.Contains(strings.Join(wrapped.Argv, "\n"), "/tmp/work") {
			t.Fatalf("profile does not mention cwd: %#v", wrapped.Argv)
		}
	case "linux":
		if wrapped.Argv[0] != "bwrap" {
			t.Fatalf("argv[0] = %q, want bwrap", wrapped.Argv[0])
		}
	default:
		if wrapped.Argv[0] != "/bin/bash" {
			t.Fatalf("argv[0] = %q, want original command", wrapped.Argv[0])
		}
	}
}

func TestSandboxProviderIncludesDenyWriteAndTempInWrappers(t *testing.T) {
	provider := systemSandboxProvider{
		cfg: Config{Sandbox: SandboxConfig{Filesystem: FilesystemSandboxConfig{
			AllowWrite: []string{"/tmp/work/extra"},
			DenyWrite:  []string{"/tmp/work/secret"},
		}}},
		outputDir: "/tmp/out",
	}
	inv := SandboxInvocation{Argv: []string{"/bin/bash", "-lc", "echo ok"}, Cwd: "/tmp/work"}
	darwinProfile := provider.seatbeltProfile(inv.Cwd)
	for _, want := range []string{"/tmp/work", "/tmp/out", "/tmp/work/extra", "/tmp/work/secret", ".claude/skills"} {
		if !strings.Contains(darwinProfile, want) {
			t.Fatalf("seatbelt profile missing %q:\n%s", want, darwinProfile)
		}
	}

	linux := provider.bubblewrapInvocation(inv)
	joined := strings.Join(linux.Argv, " ")
	for _, want := range []string{"--bind /tmp/work /tmp/work", "--bind /tmp/out /tmp/out", "--bind /tmp/work/extra /tmp/work/extra", "--tmpfs /tmp/work/secret"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("bwrap argv missing %q:\n%s", want, joined)
		}
	}
}

func TestDetectWorktreeMainRepoPath(t *testing.T) {
	dir := t.TempDir()
	mainRepo := filepath.Join(dir, "main")
	worktree := filepath.Join(dir, "worktree")
	gitDir := filepath.Join(mainRepo, ".git", "worktrees", "worktree")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := detectWorktreeMainRepoPath(worktree)
	if got != mainRepo {
		t.Fatalf("main repo = %q, want %q", got, mainRepo)
	}
}

func TestCleanupScrubsBareRepoFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"HEAD", "config"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	provider := systemSandboxProvider{}
	if err := provider.CleanupAfterCommand(context.Background(), SandboxCleanup{Cwd: dir}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"HEAD", "config"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after cleanup", name)
		}
	}
}
