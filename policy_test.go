package bashruntime

import (
	"context"
	"strings"
	"testing"
)

func TestDenyStripsEnvButAllowDoesNot(t *testing.T) {
	rt, err := New(Config{
		Permissions: PermissionsConfig{
			Allow: []string{"Bash(docker ps:*)"},
			Deny:  []string{"Bash(curl:*)"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "DOCKER_HOST=tcp://evil docker ps"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAsk {
		t.Fatalf("behavior = %s, want ask because allow matching is conservative", res.Behavior)
	}

	res, err = rt.Check(context.Background(), Request{Command: "HTTPS_PROXY=x curl https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorDeny {
		t.Fatalf("behavior = %s, want deny because deny strips env vars", res.Behavior)
	}
}

func TestPathValidationRejectsDangerousWrites(t *testing.T) {
	rt, err := New(Config{Permissions: PermissionsConfig{Allow: []string{"Bash(rm:*)", "Bash(echo:*)"}}})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "rm -rf /"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorDeny {
		t.Fatalf("behavior = %s, want deny", res.Behavior)
	}

	res, err = rt.Check(context.Background(), Request{Command: "echo x > .git/config"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAsk {
		t.Fatalf("behavior = %s, want ask", res.Behavior)
	}
	if !strings.Contains(res.Reason, ".git/config") {
		t.Fatalf("reason = %q, want blocked path", res.Reason)
	}
}

func TestSandboxAutoAllowWhenAvailable(t *testing.T) {
	rt, err := New(Config{
		Sandbox: SandboxConfig{Enabled: true, AutoAllowBashIfSandboxed: true},
	}, WithSandboxProvider(fakeSandboxProvider{available: true}))
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "go test ./..."})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAllow {
		t.Fatalf("behavior = %s, want allow", res.Behavior)
	}
	if !strings.Contains(res.Reason, "sandbox") {
		t.Fatalf("reason = %q, want sandbox mention", res.Reason)
	}
}

func TestTreeSitterExtractionHandlesQuotedOperators(t *testing.T) {
	rt, err := New(Config{
		Permissions: PermissionsConfig{
			Allow: []string{"Bash(printf:*)"},
			Deny:  []string{"Bash(rm:*)"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "printf 'not && rm -rf /'"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAllow {
		t.Fatalf("behavior = %s, want allow; reason=%s", res.Behavior, res.Reason)
	}
}

func TestTreeSitterExtractionChecksPipelineSubcommands(t *testing.T) {
	rt, err := New(Config{
		Permissions: PermissionsConfig{
			Allow: []string{"Bash(echo:*)"},
			Deny:  []string{"Bash(rm:*)"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "echo ok | rm -rf ./tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorDeny {
		t.Fatalf("behavior = %s, want deny; reason=%s", res.Behavior, res.Reason)
	}
}

func TestTreeSitterSimpleExpansionIsTooComplex(t *testing.T) {
	rt, err := New(Config{
		Permissions: PermissionsConfig{Allow: []string{"Bash(rm:*)"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "rm $TARGET"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAsk {
		t.Fatalf("behavior = %s, want ask; reason=%s", res.Behavior, res.Reason)
	}
}

func TestTreeSitterRedirectedStatementDoesNotDuplicateCommand(t *testing.T) {
	analysis := analyzeCommand("echo ok > out.txt")
	if analysis.Kind != analysisSimple {
		t.Fatalf("kind = %v reason=%s", analysis.Kind, analysis.Reason)
	}
	if len(analysis.Commands) != 1 {
		t.Fatalf("commands = %#v, want exactly one command", analysis.Commands)
	}
	if len(analysis.Commands[0].Redirects) != 1 {
		t.Fatalf("redirects = %#v, want one redirect", analysis.Commands[0].Redirects)
	}
}

func TestNumberRedirectToGitConfigAsks(t *testing.T) {
	rt, err := New(Config{Permissions: PermissionsConfig{Allow: []string{"Bash(echo:*)"}}})
	if err != nil {
		t.Fatal(err)
	}

	res, err := rt.Check(context.Background(), Request{Command: "echo x 2> .git/config"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Behavior != BehaviorAsk {
		t.Fatalf("behavior = %s, want ask; reason=%s", res.Behavior, res.Reason)
	}
}

func TestDangerousGitFlagsAskEvenWithGitAllowRule(t *testing.T) {
	rt, err := New(Config{Permissions: PermissionsConfig{Allow: []string{"Bash(git:*)"}}})
	if err != nil {
		t.Fatal(err)
	}

	for _, command := range []string{
		"git -c core.fsmonitor=evil status",
		"git --exec-path=/tmp status",
		"git --config-env=foo=bar status",
	} {
		res, err := rt.Check(context.Background(), Request{Command: command})
		if err != nil {
			t.Fatal(err)
		}
		if res.Behavior != BehaviorAsk {
			t.Fatalf("%q behavior = %s, want ask; reason=%s", command, res.Behavior, res.Reason)
		}
	}
}
