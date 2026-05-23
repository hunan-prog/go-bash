package bashruntime

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCheckAsksForTooComplexCommandSubstitution(t *testing.T) {
	rt, err := New(Config{
		Permissions: PermissionsConfig{
			Allow: []string{"Bash(echo:*)"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "echo $(id)"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAsk {
		t.Fatalf("behavior = %s, want ask", res.Behavior)
	}
	if !strings.Contains(res.Reason, "too-complex") {
		t.Fatalf("reason = %q, want too-complex", res.Reason)
	}
}

func TestCheckAsksForTreeSitterUnsupportedCompoundStatement(t *testing.T) {
	rt, err := New(Config{
		Permissions: PermissionsConfig{
			Allow: []string{"Bash(echo:*)"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "{ echo ok; }"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAsk {
		t.Fatalf("behavior = %s, want ask", res.Behavior)
	}
	if !strings.Contains(res.Reason, "tree-sitter") && !strings.Contains(res.Reason, "too-complex") {
		t.Fatalf("reason = %q, want tree-sitter/too-complex", res.Reason)
	}
}

func TestDangerousBashSyntaxAsks(t *testing.T) {
	rt, err := New(Config{Permissions: PermissionsConfig{Allow: []string{"Bash(echo:*)", "Bash(cat:*)"}}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		"echo ${HOME}",
		"echo $((1+1))",
		"echo {a,b}",
		"cat <<EOF\nhello\nEOF",
		"if true; then echo ok; fi",
		"for x in a; do echo $x; done",
		"function f() { echo ok; }",
	}
	for _, command := range cases {
		res, err := rt.Check(context.Background(), Request{Command: command})
		if err != nil {
			t.Fatal(err)
		}
		if res.Behavior != BehaviorAsk {
			t.Fatalf("%q behavior = %s, want ask; reason=%s", command, res.Behavior, res.Reason)
		}
	}
}

func TestCompoundSubcommandDenyBeatsAllow(t *testing.T) {
	rt, err := New(Config{
		Permissions: PermissionsConfig{
			Allow: []string{"Bash(echo:*)"},
			Deny:  []string{"Bash(rm:*)"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "echo ok && rm -rf ./tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorDeny {
		t.Fatalf("behavior = %s, want deny", res.Behavior)
	}
	if !strings.Contains(res.Reason, "rm") {
		t.Fatalf("reason = %q, want rm mention", res.Reason)
	}
}

func TestSandboxUnavailableDegradesUnlessRequired(t *testing.T) {
	provider := fakeSandboxProvider{available: false, reason: "missing sandbox binary"}
	rt, err := New(Config{
		Sandbox: SandboxConfig{
			Enabled:                  true,
			FailIfUnavailable:        false,
			AutoAllowBashIfSandboxed: true,
		},
		Permissions: PermissionsConfig{Allow: []string{"Bash(echo:*)"}},
	}, WithSandboxProvider(provider))
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Run(context.Background(), Request{Command: "echo degraded"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Behavior != BehaviorAllow {
		t.Fatalf("decision = %s, want allow", res.Decision.Behavior)
	}
	if res.SandboxUsed {
		t.Fatal("SandboxUsed = true, want false")
	}
	if !strings.Contains(res.Decision.Reason, "degraded") {
		t.Fatalf("reason = %q, want degraded", res.Decision.Reason)
	}

	rtRequired, err := New(Config{
		Sandbox: SandboxConfig{
			Enabled:           true,
			FailIfUnavailable: true,
		},
		Permissions: PermissionsConfig{Allow: []string{"Bash(echo:*)"}},
	}, WithSandboxProvider(provider))
	if err != nil {
		t.Fatal(err)
	}
	res, err = rtRequired.Run(context.Background(), Request{Command: "echo blocked"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Behavior != BehaviorDeny {
		t.Fatalf("decision = %s, want deny", res.Decision.Behavior)
	}
}

func TestRunTracksCwd(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	physicalChild, err := filepath.EvalSymlinks(child)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := New(Config{
		Permissions: PermissionsConfig{Allow: []string{"Bash(cd:*)", "Bash(pwd)"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Run(context.Background(), Request{Command: "cd child && pwd", Cwd: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d output=%q", res.ExitCode, res.Stdout)
	}
	if res.Cwd != physicalChild {
		t.Fatalf("cwd = %q, want %q", res.Cwd, physicalChild)
	}
	if !strings.Contains(res.Stdout, physicalChild) {
		t.Fatalf("stdout = %q, want child path", res.Stdout)
	}
}

func TestBackgroundTaskCanBeReadAndKilled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash runtime targets macOS and Linux")
	}
	rt, err := New(Config{
		Permissions: PermissionsConfig{Allow: []string{"Bash(sh:*)"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Run(context.Background(), Request{
		Command:         "sh -c 'echo ready; sleep 5'",
		RunInBackground: true,
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.TaskID == "" {
		t.Fatal("TaskID is empty")
	}

	deadline := time.Now().Add(2 * time.Second)
	var out TaskOutput
	for time.Now().Before(deadline) {
		out, err = rt.ReadTask(context.Background(), res.TaskID, ReadOptions{TailBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.Output, "ready") {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !strings.Contains(out.Output, "ready") {
		t.Fatalf("output = %q, want ready", out.Output)
	}
	if err := rt.KillTask(context.Background(), res.TaskID); err != nil {
		t.Fatal(err)
	}
	out, err = rt.ReadTask(context.Background(), res.TaskID, ReadOptions{TailBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != TaskStatusKilled {
		t.Fatalf("status = %s, want killed", out.Status)
	}
}

func TestForegroundTimeoutAutoBackgroundsLongCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash runtime targets macOS and Linux")
	}
	rt, err := New(Config{
		Permissions: PermissionsConfig{Allow: []string{"Bash(sh:*)"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Run(context.Background(), Request{
		Command: "sh -c 'sleep 1; echo after-timeout'",
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.TaskID == "" {
		t.Fatalf("TaskID is empty; result=%+v", res)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		out, err := rt.ReadTask(context.Background(), res.TaskID, ReadOptions{TailBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.Output, "after-timeout") {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for backgrounded command output")
}

func TestBackgroundTaskOutputLimitMarksTask(t *testing.T) {
	rt, err := New(Config{
		Permissions:    PermissionsConfig{Allow: []string{"Bash(yes)"}},
		ResourceLimits: ResourceLimitsConfig{MaxTaskOutputBytes: 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := rt.Run(context.Background(), Request{Command: "yes", RunInBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.KillTask(context.Background(), res.TaskID)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		out, err := rt.ReadTask(context.Background(), res.TaskID, ReadOptions{TailBytes: 32})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.Reason, "output exceeded") {
			if out.Running {
				t.Fatal("Running = true after output exceeded")
			}
			if out.Status != TaskStatusOutputLimitExceeded {
				t.Fatalf("status = %s, want output_limit_exceeded", out.Status)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("task was not marked after output limit")
}

type fakeSandboxProvider struct {
	available bool
	reason    string
}

func (f fakeSandboxProvider) CheckDependencies(context.Context) SandboxDiagnostics {
	return SandboxDiagnostics{Available: f.available, Reason: f.reason, Platform: runtime.GOOS}
}

func (f fakeSandboxProvider) WrapCommand(context.Context, SandboxInvocation) (SandboxInvocation, error) {
	return SandboxInvocation{}, nil
}

func (f fakeSandboxProvider) CleanupAfterCommand(context.Context, SandboxCleanup) error {
	return nil
}
