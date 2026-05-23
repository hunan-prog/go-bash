package bashruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeSourcesShellSnapshot(t *testing.T) {
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "snapshot.bash")
	if err := os.WriteFile(snapshot, []byte("alias ll='printf snapshot-ok'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err := New(Config{
		Permissions: PermissionsConfig{Allow: []string{"Bash(ll)"}},
	}, WithShellSnapshot(snapshot))
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Run(context.Background(), Request{Command: "ll"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d output=%q", res.ExitCode, res.Stdout)
	}
	if !strings.Contains(res.Stdout, "snapshot-ok") {
		t.Fatalf("stdout = %q, want snapshot alias output", res.Stdout)
	}
}

func TestBuildScriptSourcesSessionEnvBeforeCommand(t *testing.T) {
	script := buildScript("printf \"$GO_BASH_HELLO\"", "/tmp/cwd", "/tmp/snapshot", SessionEnv{"GO_BASH_HELLO": "world"})
	if !strings.Contains(script, "export GO_BASH_HELLO=") {
		t.Fatalf("script does not export session env: %s", script)
	}
	if strings.Index(script, "export GO_BASH_HELLO=") > strings.Index(script, "eval ") {
		t.Fatalf("session env appears after eval: %s", script)
	}
}

func TestSpawnArgsUseLoginShellWhenSnapshotMissing(t *testing.T) {
	snapshot := filepath.Join(t.TempDir(), "missing.sh")
	rt, err := New(Config{Shell: ShellConfig{SnapshotPath: snapshot}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(snapshot); err != nil {
		t.Fatal(err)
	}
	req := Request{Command: "echo ok", Cwd: t.TempDir()}
	cmd, err := rt.command(context.Background(), req, filepath.Join(t.TempDir(), "cwd"), false)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmd.Args, " ")
	if !strings.Contains(got, " -l ") {
		t.Fatalf("args = %q, want login shell flag when snapshot missing", got)
	}
}
