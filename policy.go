package bashruntime

import (
	"path/filepath"
	"strings"
)

func allow(reason string) PermissionDecision {
	return PermissionDecision{Behavior: BehaviorAllow, Reason: reason}
}

func ask(reason string) PermissionDecision {
	return PermissionDecision{Behavior: BehaviorAsk, Reason: reason}
}

func deny(reason string) PermissionDecision {
	return PermissionDecision{Behavior: BehaviorDeny, Reason: reason}
}

func evaluatePolicy(req Request, analysis commandAnalysis, cfg PermissionsConfig, sandboxAutoAllow bool) PermissionDecision {
	for _, cmd := range analysis.Commands {
		if matched, rule := matchRules(cmd, cfg.Deny, true); matched {
			return deny("denied by rule " + rule + " for subcommand " + cmdName(cmd))
		}
	}
	for _, cmd := range analysis.Commands {
		if matched, rule := matchRules(cmd, cfg.Ask, true); matched {
			return ask("asked by rule " + rule + " for subcommand " + cmdName(cmd))
		}
	}
	if pathDecision := validatePaths(analysis); pathDecision.Behavior != BehaviorPassthrough {
		return pathDecision
	}
	if sandboxAutoAllow {
		return allow("auto-allowed with sandbox")
	}
	if len(analysis.Commands) == 0 {
		return allow("empty command")
	}
	for _, cmd := range analysis.Commands {
		if matched, _ := matchRules(cmd, cfg.Allow, false); matched {
			continue
		}
		if isReadOnlyCommand(cmd) {
			continue
		}
		return ask("no allow rule for subcommand " + cmdName(cmd))
	}
	return allow("allowed by rule or read-only policy")
}

func matchRules(cmd simpleCommand, rules []string, strip bool) (bool, string) {
	candidates := []string{strings.TrimSpace(cmd.Text)}
	if strip || len(cmd.Env) == 0 {
		candidates = append(candidates, strings.Join(cmd.Argv, " "))
	}
	if strip {
		candidates = append(candidates, strings.Join(stripWrappersAndEnv(cmd.Argv), " "))
	}
	for _, raw := range rules {
		rule := parseBashRule(raw)
		if rule == "" {
			continue
		}
		for _, cand := range candidates {
			if matchRule(rule, cand) {
				return true, raw
			}
		}
	}
	return false, ""
}

func parseBashRule(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "Bash(") && strings.HasSuffix(raw, ")") {
		return strings.TrimSuffix(strings.TrimPrefix(raw, "Bash("), ")")
	}
	return raw
}

func matchRule(rule, command string) bool {
	command = strings.TrimSpace(command)
	if strings.HasSuffix(rule, ":*") {
		prefix := strings.TrimSuffix(rule, ":*")
		return command == prefix || strings.HasPrefix(command, prefix+" ")
	}
	if strings.Contains(rule, "*") {
		ok, _ := filepath.Match(rule, command)
		return ok
	}
	return command == rule
}

func stripWrappersAndEnv(argv []string) []string {
	out := append([]string(nil), argv...)
	for len(out) > 0 {
		if isEnvAssignment(out[0]) {
			out = out[1:]
			continue
		}
		switch out[0] {
		case "timeout", "command", "env", "nice", "nohup", "stdbuf":
			out = out[1:]
			continue
		}
		break
	}
	return out
}

func validatePaths(analysis commandAnalysis) PermissionDecision {
	hasCd := false
	hasGit := false
	for _, cmd := range analysis.Commands {
		if cmdName(cmd) == "cd" {
			hasCd = true
		}
		if cmdName(cmd) == "git" {
			hasGit = true
			if hasDangerousGitFlag(cmd.Argv[1:]) {
				return ask("dangerous git flags require confirmation")
			}
		}
		for _, redir := range cmd.Redirects {
			if isWriteRedirect(redir.Op) {
				if unsafeWritePath(redir.Target) {
					return ask("unsafe redirect target " + redir.Target)
				}
			}
		}
		if cmdName(cmd) == "rm" {
			for _, arg := range cmd.Argv[1:] {
				if unsafeWritePath(arg) {
					return deny("dangerous removal path " + arg)
				}
			}
		}
		if cmdName(cmd) == "mv" || cmdName(cmd) == "cp" {
			for _, arg := range cmd.Argv[1:] {
				if strings.HasPrefix(arg, "-") {
					return ask(cmdName(cmd) + " flags require confirmation")
				}
			}
		}
	}
	if hasCd && hasGit {
		return ask("compound cd+git requires confirmation")
	}
	return PermissionDecision{Behavior: BehaviorPassthrough}
}

func isWriteRedirect(op string) bool {
	return op == ">" || op == ">>" || op == "&>" || op == "&>>" || strings.HasSuffix(op, ">")
}

func unsafeWritePath(p string) bool {
	if p == "" || p == "/dev/null" {
		return false
	}
	if p == "/" || p == "~" || p == "$HOME" || strings.ContainsAny(p, "*?[") {
		return true
	}
	clean := filepath.Clean(p)
	if clean == ".git" || strings.HasPrefix(clean, ".git/") || strings.Contains(clean, "/.git/") {
		return true
	}
	return false
}

func isReadOnlyCommand(cmd simpleCommand) bool {
	name := cmdName(cmd)
	switch name {
	case "pwd", "ls", "tree", "du", "cat", "head", "tail", "sort", "uniq", "wc", "cut", "paste", "column", "tr", "file", "stat", "diff", "awk", "strings", "hexdump", "od", "base64", "nl", "grep", "rg", "find":
		return len(cmd.Redirects) == 0
	case "git":
		if len(cmd.Argv) < 2 {
			return false
		}
		switch cmd.Argv[1] {
		case "status", "log", "diff", "show", "branch", "rev-parse":
			return !hasDangerousGitFlag(cmd.Argv[2:])
		}
	}
	return false
}

func hasDangerousGitFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-c" || strings.HasPrefix(arg, "--exec-path") || strings.HasPrefix(arg, "--config-env") {
			return true
		}
	}
	return false
}

func cmdName(cmd simpleCommand) string {
	if len(cmd.Argv) == 0 {
		return ""
	}
	return cmd.Argv[0]
}

func containsExcludedCommand(command string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	parts, err := splitSubcommands(command)
	if err != nil {
		parts = []string{command}
	}
	for _, part := range parts {
		sc, err := parseSimpleCommand(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		for _, p := range patterns {
			if matchRule(parseBashRule(p), strings.Join(stripWrappersAndEnv(sc.Argv), " ")) {
				return true
			}
		}
	}
	return false
}
