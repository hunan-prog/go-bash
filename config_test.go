package bashruntime

import (
	"context"
	"strings"
	"testing"
)

func TestDefaultConfigAllowsDisablingSandboxAutoAllow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Sandbox.Enabled = true
	cfg.Sandbox.AutoAllowBashIfSandboxed = false
	rt, err := New(cfg, WithSandboxProvider(fakeSandboxProvider{available: true}))
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "go test ./..."})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAsk {
		t.Fatalf("behavior = %s, want ask when auto allow is disabled", res.Behavior)
	}
	if strings.Contains(res.Reason, "auto-allowed") {
		t.Fatalf("reason = %q, should not auto allow", res.Reason)
	}
}

func TestDefaultConfigAllowsDisablingBackgroundTasks(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BackgroundTasks.Enabled = false
	cfg.Permissions.Allow = []string{"Bash(sleep:*)"}
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Run(context.Background(), Request{Command: "sleep 1", RunInBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Behavior != BehaviorAsk {
		t.Fatalf("behavior = %s, want ask", res.Decision.Behavior)
	}
}
