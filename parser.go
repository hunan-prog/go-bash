package bashruntime

import (
	"fmt"
	"strings"
	"unicode"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
)

type analysisKind int

const (
	analysisSimple analysisKind = iota
	analysisTooComplex
	analysisParseError
)

type commandAnalysis struct {
	Kind     analysisKind
	Reason   string
	Commands []simpleCommand
}

type simpleCommand struct {
	Argv      []string
	Env       map[string]string
	Redirects []redirect
	Text      string
}

type redirect struct {
	Op     string
	Target string
}

func analyzeCommand(cmd string) commandAnalysis {
	if cmd == "" {
		return commandAnalysis{Kind: analysisSimple}
	}
	if reason := precheckDangerousSyntax(cmd); reason != "" {
		return commandAnalysis{Kind: analysisTooComplex, Reason: reason}
	}
	nodes, reason := treeSitterSecurityCheck(cmd)
	if reason != "" {
		return commandAnalysis{Kind: analysisTooComplex, Reason: reason}
	}
	if len(nodes) > 0 {
		var commands []simpleCommand
		for _, text := range nodes {
			sc, err := parseSimpleCommand(text)
			if err != nil {
				return commandAnalysis{Kind: analysisTooComplex, Reason: err.Error()}
			}
			if len(sc.Argv) > 0 {
				commands = append(commands, sc)
			}
		}
		return commandAnalysis{Kind: analysisSimple, Commands: commands}
	}
	parts, err := splitSubcommands(cmd)
	if err != nil {
		return commandAnalysis{Kind: analysisParseError, Reason: err.Error()}
	}
	var commands []simpleCommand
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		sc, err := parseSimpleCommand(part)
		if err != nil {
			return commandAnalysis{Kind: analysisTooComplex, Reason: err.Error()}
		}
		if len(sc.Argv) > 0 {
			commands = append(commands, sc)
		}
	}
	return commandAnalysis{Kind: analysisSimple, Commands: commands}
}

func treeSitterSecurityCheck(cmd string) ([]string, string) {
	if len(cmd) > 128*1024 {
		return nil, "command too large for tree-sitter security parse"
	}
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_bash.Language())); err != nil {
		return nil, "tree-sitter unavailable: " + err.Error()
	}
	tree := parser.Parse([]byte(cmd), nil)
	if tree == nil {
		return nil, "tree-sitter parser aborted"
	}
	defer tree.Close()
	root := tree.RootNode()
	if root == nil {
		return nil, "tree-sitter returned no root"
	}
	if root.HasError() {
		return nil, "tree-sitter parse error"
	}
	var commandTexts []string
	if reason := walkTreeSitterNode(root, []byte(cmd), &commandTexts); reason != "" {
		return nil, reason
	}
	return commandTexts, ""
}

func walkTreeSitterNode(node *tree_sitter.Node, src []byte, commandTexts *[]string) string {
	kind := node.Kind()
	if treeSitterDangerousNode(kind) {
		return "tree-sitter dangerous node: " + kind
	}
	if node.IsNamed() && !treeSitterAllowedNode(kind) {
		return "tree-sitter unsupported node: " + kind
	}
	if kind == "redirected_statement" {
		if reason := validateTreeSitterChildren(node, src); reason != "" {
			return reason
		}
		*commandTexts = append(*commandTexts, node.Utf8Text(src))
		return ""
	}
	cursor := node.Walk()
	defer cursor.Close()
	for _, child := range node.Children(cursor) {
		child := child
		if reason := walkTreeSitterNode(&child, src, commandTexts); reason != "" {
			return reason
		}
	}
	if kind == "redirected_statement" || kind == "command" {
		*commandTexts = append(*commandTexts, node.Utf8Text(src))
	}
	return ""
}

func validateTreeSitterChildren(node *tree_sitter.Node, src []byte) string {
	cursor := node.Walk()
	defer cursor.Close()
	for _, child := range node.Children(cursor) {
		child := child
		kind := child.Kind()
		if treeSitterDangerousNode(kind) {
			return "tree-sitter dangerous node: " + kind
		}
		if child.IsNamed() && !treeSitterAllowedNode(kind) {
			return "tree-sitter unsupported node: " + kind
		}
		if reason := validateTreeSitterChildren(&child, src); reason != "" {
			return reason
		}
	}
	return ""
}

func treeSitterDangerousNode(kind string) bool {
	switch kind {
	case "command_substitution", "process_substitution", "expansion", "simple_expansion", "subshell",
		"compound_statement", "for_statement", "while_statement", "until_statement",
		"if_statement", "case_statement", "function_definition", "test_command",
		"ansi_c_string", "translated_string", "herestring_redirect", "heredoc_redirect",
		"arithmetic_expansion", "brace_expression":
		return true
	default:
		return false
	}
}

func treeSitterAllowedNode(kind string) bool {
	switch kind {
	case "program", "list", "pipeline", "redirected_statement", "command",
		"command_name", "word", "string", "raw_string", "string_content",
		"file_redirect", "number_redirect", "variable_assignment", "variable_name", "number",
		"comment":
		return true
	default:
		return false
	}
}

func precheckDangerousSyntax(cmd string) string {
	for _, r := range cmd {
		if r < 0x20 && r != '\n' && r != '\t' {
			return "contains control characters"
		}
		if unicode.IsSpace(r) && r != ' ' && r != '\t' && r != '\n' {
			return "contains Unicode whitespace"
		}
	}
	checks := []struct {
		needle string
		reason string
	}{
		{"$(", "contains command substitution"},
		{"`", "contains backtick command substitution"},
		{"<(", "contains process substitution"},
		{">(", "contains process substitution"},
		{"<<", "contains heredoc"},
		{"<<<", "contains herestring"},
		{"~[", "contains zsh dynamic directory syntax"},
	}
	for _, check := range checks {
		if strings.Contains(cmd, check.needle) {
			return check.reason
		}
	}
	if strings.Contains(cmd, "function ") || strings.Contains(cmd, "() {") {
		return "contains function definition"
	}
	for _, kw := range []string{"if ", "for ", "while ", "until ", "case ", "[[", "(("} {
		if strings.HasPrefix(strings.TrimSpace(cmd), kw) || strings.Contains(cmd, "; "+kw) || strings.Contains(cmd, "&& "+kw) {
			return "contains shell control flow"
		}
	}
	fields := strings.Fields(cmd)
	for _, f := range fields {
		if strings.HasPrefix(f, "=") && len(f) > 1 {
			return "contains zsh =cmd equals expansion"
		}
	}
	return ""
}

func splitSubcommands(cmd string) ([]string, error) {
	var out []string
	start := 0
	inSingle, inDouble, escaped := false, false, false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}
		if c == ';' || c == '|' || c == '&' {
			out = append(out, cmd[start:i])
			if i+1 < len(cmd) && cmd[i+1] == c {
				i++
			}
			start = i + 1
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unclosed quote")
	}
	out = append(out, cmd[start:])
	return out, nil
}

func parseSimpleCommand(part string) (simpleCommand, error) {
	toks, err := shellWords(part)
	if err != nil {
		return simpleCommand{}, err
	}
	cmd := simpleCommand{Text: part, Env: map[string]string{}}
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		if isRedirectOp(tok) || isFDRredirectOp(tok) {
			if i+1 >= len(toks) {
				return simpleCommand{}, fmt.Errorf("redirect without target")
			}
			cmd.Redirects = append(cmd.Redirects, redirect{Op: tok, Target: toks[i+1]})
			i++
			continue
		}
		if len(cmd.Argv) == 0 && isEnvAssignment(tok) {
			k, v, _ := strings.Cut(tok, "=")
			cmd.Env[k] = v
			continue
		}
		cmd.Argv = append(cmd.Argv, tok)
	}
	if len(cmd.Argv) > 0 && isShellKeyword(cmd.Argv[0]) {
		return simpleCommand{}, fmt.Errorf("shell keyword %q as command name", cmd.Argv[0])
	}
	return cmd, nil
}

func shellWords(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	inSingle, inDouble, escaped := false, false, false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && (c == ' ' || c == '\t' || c == '\n') {
			flush()
			continue
		}
		if !inSingle && !inDouble && isRedirectByte(c) {
			flush()
			if i+1 < len(s) && s[i+1] == c {
				out = append(out, s[i:i+2])
				i++
			} else {
				out = append(out, string(c))
			}
			continue
		}
		b.WriteByte(c)
	}
	if escaped {
		return nil, fmt.Errorf("trailing escape")
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unclosed quote")
	}
	flush()
	return out, nil
}

func isRedirectByte(c byte) bool { return c == '>' || c == '<' }

func isRedirectOp(s string) bool {
	switch s {
	case ">", ">>", "<", "2>", "2>>", "&>", "&>>":
		return true
	default:
		return false
	}
}

func isFDRredirectOp(s string) bool {
	if len(s) < 2 || !strings.HasSuffix(s, ">") {
		return false
	}
	return allDigits(s[:len(s)-1])
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isEnvAssignment(s string) bool {
	k, _, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return false
	}
	for i, r := range k {
		if i == 0 && !(r == '_' || unicode.IsLetter(r)) {
			return false
		}
		if !(r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return false
		}
	}
	return true
}

func isShellKeyword(s string) bool {
	switch s {
	case "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "function", "{", "}":
		return true
	default:
		return false
	}
}
