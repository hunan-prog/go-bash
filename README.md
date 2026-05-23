# go-bash

`go-bash` is a local Bash runtime for coding agents. It mirrors the broad shape
of Claude Code's Bash tool: static Bash analysis, permission decisions, optional
OS sandboxing, output/resource isolation, cwd tracking, and background tasks.

## Quick Start

```go
cfg := bashruntime.DefaultConfig()
cfg.Permissions.Allow = []string{"Bash(git status)", "Bash(rg:*)"}
cfg.Sandbox.Enabled = true

rt, err := bashruntime.New(cfg)
if err != nil {
    return err
}

res, err := rt.Run(ctx, bashruntime.Request{
    Command: "git status --short",
})
if err != nil {
    return err
}
if res.Decision.Behavior == bashruntime.BehaviorAsk {
    // Ask the host application or user. The runtime does not own UI.
}
```

Use `DefaultConfig()` when you want Claude-style defaults and then override
them. Passing a zero `Config{}` also works, but Go boolean zero values cannot
distinguish "unset" from "explicit false"; `DefaultConfig()` is the clean path
for disabling defaults such as sandbox auto-allow or background tasks.

## Security Model

- Bash is parsed with `tree-sitter-bash` before execution.
- Unsupported or risky syntax is fail-closed and returns `BehaviorAsk`,
  including shell expansion, command substitution, heredocs, control flow,
  functions, subshells, and unsupported AST nodes.
- Deny rules are checked before ask and allow rules.
- Compound commands are checked per subcommand.
- Deny/ask matching strips common env assignments and safe wrappers; allow
  matching is conservative.
- Path validation blocks or asks for dangerous write/removal patterns.
- Output files are created with exclusive/no-follow semantics.
- stdout and stderr are merged into a single output file to preserve ordering.

This is defense in depth, not a proof that arbitrary shell is safe. The host
application should treat `BehaviorAsk` as requiring a real policy decision.

## Sandbox Behavior

Sandboxing is optional and defaults to Claude-compatible graceful degradation:

- `Sandbox.Enabled=true` tries to use an OS sandbox.
- `Sandbox.FailIfUnavailable=false` allows fallback to unsandboxed execution
  with a diagnostic reason.
- `Sandbox.FailIfUnavailable=true` returns `BehaviorDeny` if dependencies are
  missing.
- `Sandbox.AutoAllowBashIfSandboxed=true` auto-allows commands inside a working
  sandbox unless explicit deny/ask rules match.

Current providers generate wrappers for:

- macOS: `sandbox-exec`
- Linux: `bubblewrap`

Network domain-specific enforcement is represented in config and provider
interfaces; advanced proxy behavior is intentionally left for host integration.
Linux deny-write paths are represented with mount overlays in the generated
`bwrap` argv; macOS deny-write paths are emitted in the generated seatbelt
profile. Worktree main repositories are detected from `.git` files and added to
the Linux write allow-list so normal git worktree operations can proceed.

## Background Tasks

Set `Request.RunInBackground=true` to return immediately with a task ID:

```go
res, _ := rt.Run(ctx, bashruntime.Request{
    Command: "go test ./...",
    RunInBackground: true,
})

out, _ := rt.ReadTask(ctx, res.TaskID, bashruntime.ReadOptions{TailBytes: 4096})
```

Foreground commands that exceed `Request.Timeout` are auto-backgrounded unless
the command is explicitly disallowed for auto-backgrounding, such as `sleep`.
`TaskOutput.Status` reports `running`, `completed`, `killed`,
`output_limit_exceeded`, or `needs_input`.

## Tree-sitter Version Note

The Go tree-sitter binding `v0.24.0` supports language versions through 14, so
this module pins `tree-sitter-bash` to `v0.23.3`. Newer bash grammar releases
currently require a newer Go binding.
