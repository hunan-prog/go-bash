package bashruntime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ensureSnapshot(path, shellPath string) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	script := snapshotCreationScript(path, shellPath)
	cmd := exec.Command(shellPath, "-lc", script)
	cmd.Env = append(os.Environ(), "SHELL="+shellPath)
	if err := cmd.Run(); err != nil {
		return os.WriteFile(path, []byte(fallbackSnapshotContent()), 0o600)
	}
	return nil
}

func buildScript(command, cwdFile, snapshotPath string, sessionEnv SessionEnv) string {
	var b strings.Builder
	b.WriteString("set +H\n")
	b.WriteString("shopt -s expand_aliases 2>/dev/null || true\n")
	if snapshotPath != "" {
		b.WriteString(fmt.Sprintf("source %q 2>/dev/null || true\n", snapshotPath))
	}
	for k, v := range sessionEnv {
		if isEnvAssignment(k + "=x") {
			b.WriteString(fmt.Sprintf("export %s=%q\n", k, v))
		}
	}
	b.WriteString("{ shopt -u extglob || setopt NO_EXTENDED_GLOB; } >/dev/null 2>&1 || true\n")
	b.WriteString(fmt.Sprintf("eval %q\n", command))
	b.WriteString("status=$?\n")
	b.WriteString(fmt.Sprintf("pwd -P > %q\n", cwdFile))
	b.WriteString("exit $status\n")
	return b.String()
}

func snapshotCreationScript(snapshotPath, shellPath string) string {
	config := shellConfigFile(shellPath)
	return fmt.Sprintf(`SNAPSHOT_FILE=%q
if [ -f %q ]; then source %q < /dev/null; fi
echo "# go-bash runtime shell snapshot" >| "$SNAPSHOT_FILE"
echo "unalias -a 2>/dev/null || true" >> "$SNAPSHOT_FILE"
echo "# Functions" >> "$SNAPSHOT_FILE"
if command -v declare >/dev/null 2>&1; then
  declare -F | awk '{print $3}' | grep -vE '^_[^_]' | while read f; do declare -f "$f" >> "$SNAPSHOT_FILE"; done
elif command -v typeset >/dev/null 2>&1; then
  typeset +f | grep -vE '^_[^_]' | while read f; do typeset -f "$f" >> "$SNAPSHOT_FILE"; done
fi
echo "# Shell Options" >> "$SNAPSHOT_FILE"
shopt -p 2>/dev/null | head -n 1000 >> "$SNAPSHOT_FILE" || true
set -o 2>/dev/null | awk '$2 == "on" {print "set -o " $1}' | head -n 1000 >> "$SNAPSHOT_FILE" || true
echo "shopt -s expand_aliases 2>/dev/null || true" >> "$SNAPSHOT_FILE"
echo "# Aliases" >> "$SNAPSHOT_FILE"
alias 2>/dev/null | sed 's/^alias //g' | sed 's/^/alias -- /' | head -n 1000 >> "$SNAPSHOT_FILE" || true
echo "export PATH=%q" >> "$SNAPSHOT_FILE"
`, snapshotPath, config, config, os.Getenv("PATH"))
}

func fallbackSnapshotContent() string {
	return fmt.Sprintf("# go-bash runtime shell snapshot\nshopt -s expand_aliases 2>/dev/null || true\nexport PATH=%q\n", os.Getenv("PATH"))
}

func shellConfigFile(shellPath string) string {
	home, _ := os.UserHomeDir()
	if strings.Contains(shellPath, "zsh") {
		return filepath.Join(home, ".zshrc")
	}
	if strings.Contains(shellPath, "bash") {
		return filepath.Join(home, ".bashrc")
	}
	return filepath.Join(home, ".profile")
}
