package bashruntime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type SandboxProvider interface {
	CheckDependencies(context.Context) SandboxDiagnostics
	WrapCommand(context.Context, SandboxInvocation) (SandboxInvocation, error)
	CleanupAfterCommand(context.Context, SandboxCleanup) error
}

type SandboxDiagnostics struct {
	Available bool
	Platform  string
	Reason    string
	Warnings  []string
}

type SandboxInvocation struct {
	Argv []string
	Cwd  string
	Env  []string
}

type SandboxCleanup struct {
	Cwd         string
	OriginalCwd string
}

type systemSandboxProvider struct {
	cfg       Config
	outputDir string
}

func (systemSandboxProvider) CheckDependencies(context.Context) SandboxDiagnostics {
	if !supportedPlatform() {
		return SandboxDiagnostics{Platform: runtime.GOOS, Reason: "unsupported platform"}
	}
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err == nil {
			return SandboxDiagnostics{Available: true, Platform: runtime.GOOS}
		}
		return SandboxDiagnostics{Available: false, Platform: runtime.GOOS, Reason: "sandbox-exec is unavailable"}
	case "linux":
		if _, err := exec.LookPath("bwrap"); err != nil {
			return SandboxDiagnostics{Available: false, Platform: runtime.GOOS, Reason: "bubblewrap is unavailable"}
		}
		return SandboxDiagnostics{Available: true, Platform: runtime.GOOS}
	default:
		return SandboxDiagnostics{Platform: runtime.GOOS, Reason: "unsupported platform"}
	}
}

func (p systemSandboxProvider) WrapCommand(_ context.Context, inv SandboxInvocation) (SandboxInvocation, error) {
	switch runtime.GOOS {
	case "darwin":
		profile := p.seatbeltProfile(inv.Cwd)
		argv := append([]string{"sandbox-exec", "-p", profile}, inv.Argv...)
		inv.Argv = argv
		return inv, nil
	case "linux":
		return p.bubblewrapInvocation(inv), nil
	default:
		return inv, nil
	}
}

func (systemSandboxProvider) CleanupAfterCommand(_ context.Context, cleanup SandboxCleanup) error {
	scrubBareRepoFiles(cleanup.Cwd)
	if cleanup.OriginalCwd != cleanup.Cwd {
		scrubBareRepoFiles(cleanup.OriginalCwd)
	}
	return nil
}

func (p systemSandboxProvider) seatbeltProfile(cwd string) string {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	b.WriteString("(allow process*)\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow file-read*)\n")
	for _, path := range append([]string{cwd, p.outputDir}, p.cfg.Sandbox.Filesystem.AllowWrite...) {
		if path == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", path))
	}
	for _, path := range append(defaultDenyWritePaths(cwd), p.cfg.Sandbox.Filesystem.DenyWrite...) {
		if path == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", path))
	}
	if len(p.cfg.Sandbox.Network.AllowedDomains) == 0 && !p.cfg.Sandbox.Network.AllowLocalBinding {
		b.WriteString("(deny network*)\n")
	} else {
		b.WriteString("(allow network*)\n")
	}
	return b.String()
}

func (p systemSandboxProvider) bubblewrapInvocation(inv SandboxInvocation) SandboxInvocation {
	argv := []string{
		"bwrap",
		"--die-with-parent",
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--bind", inv.Cwd, inv.Cwd,
		"--bind", p.outputDir, p.outputDir,
		"--chdir", inv.Cwd,
	}
	for _, path := range p.cfg.Sandbox.Filesystem.AllowWrite {
		if path != "" {
			argv = append(argv, "--bind", path, path)
		}
	}
	if mainRepo := detectWorktreeMainRepoPath(inv.Cwd); mainRepo != "" {
		argv = append(argv, "--bind", mainRepo, mainRepo)
	}
	for _, path := range append(defaultDenyWritePaths(inv.Cwd), p.cfg.Sandbox.Filesystem.DenyWrite...) {
		if path != "" {
			argv = append(argv, "--tmpfs", path)
		}
	}
	if len(p.cfg.Sandbox.Network.AllowedDomains) == 0 && !p.cfg.Sandbox.Network.AllowLocalBinding {
		argv = append(argv, "--unshare-net")
	}
	argv = append(argv, "--")
	argv = append(argv, inv.Argv...)
	inv.Argv = argv
	return inv
}

func detectWorktreeMainRepoPath(cwd string) string {
	data, err := os.ReadFile(filepath.Join(cwd, ".git"))
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(line, prefix) {
		return ""
	}
	gitdir := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Join(cwd, gitdir)
	}
	marker := string(filepath.Separator) + ".git" + string(filepath.Separator) + "worktrees" + string(filepath.Separator)
	idx := strings.LastIndex(gitdir, marker)
	if idx <= 0 {
		return ""
	}
	return filepath.Clean(gitdir[:idx])
}

func defaultDenyWritePaths(cwd string) []string {
	return []string{
		cwd + "/.claude/settings.json",
		cwd + "/.claude/settings.local.json",
		cwd + "/.claude/skills",
		cwd + "/.git/config",
		cwd + "/HEAD",
		cwd + "/objects",
		cwd + "/refs",
		cwd + "/hooks",
		cwd + "/config",
	}
}
