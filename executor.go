package bashruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func (r *Runtime) runForeground(ctx context.Context, req Request, decision PermissionDecision, sandboxUsed bool) (Result, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = r.cfg.ResourceLimits.DefaultTimeout
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	outputPath := filepath.Join(r.outputDir, newID("fg")+".log")
	file, err := openOutputFile(outputPath)
	if err != nil {
		return Result{}, err
	}

	cwdFile := filepath.Join(r.outputDir, newID("cwd"))
	cmd, err := r.command(runCtx, req, cwdFile, sandboxUsed)
	if err != nil {
		file.Close()
		return Result{}, err
	}
	cmd.Stdout = file
	cmd.Stderr = file
	if err := cmd.Start(); err != nil {
		file.Close()
		return Result{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case waitErr = <-done:
		file.Close()
	case <-ctx.Done():
		killProcessTree(cmd)
		file.Close()
		waitErr = ctx.Err()
	case <-timer.C:
		if r.cfg.BackgroundTasks.AutoBackgroundOnTimeout && !disallowedAutoBackground(req.Command) {
			task := r.tasks.adopt(r, req, cmd.Process, file, outputPath, cwdFile, done)
			return Result{
				Decision:    decision,
				TaskID:      task.id,
				OutputPath:  task.outputPath,
				Cwd:         req.Cwd,
				SandboxUsed: sandboxUsed,
			}, nil
		}
		killProcessTree(cmd)
		file.Close()
		waitErr = <-done
	}
	_ = r.sandbox.CleanupAfterCommand(context.Background(), SandboxCleanup{Cwd: req.Cwd, OriginalCwd: r.originalCwd})

	exitCode := exitCodeFromError(waitErr)
	if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
		exitCode = 143
	}
	newCwd := readCwdFile(cwdFile, req.Cwd)
	r.setCwd(newCwd)
	out, truncated, readErr := readOutput(outputPath, r.cfg.ResourceLimits.MaxInlineBytes)
	if readErr != nil {
		return Result{}, readErr
	}
	return Result{
		Decision:    decision,
		ExitCode:    exitCode,
		Stdout:      out,
		Stderr:      "",
		Cwd:         newCwd,
		OutputPath:  outputPath,
		Truncated:   truncated,
		SandboxUsed: sandboxUsed,
	}, nil
}

func (r *Runtime) command(ctx context.Context, req Request, cwdFile string, sandboxUsed bool) (*exec.Cmd, error) {
	snapshotPath := r.snapshotPath
	snapshotExists := false
	if snapshotPath != "" {
		if _, err := os.Stat(snapshotPath); err == nil {
			snapshotExists = true
		}
	}
	script := buildScript(req.Command, cwdFile, snapshotPath, r.cfg.Shell.SessionEnv)
	args := []string{"-c", script}
	if !snapshotExists {
		args = []string{"-c", "-l", script}
	}
	inv := SandboxInvocation{
		Argv: append([]string{r.shellPath}, args...),
		Cwd:  req.Cwd,
		Env:  envList(req.Env),
	}
	wrapped := inv
	if sandboxUsed {
		var err error
		wrapped, err = r.sandbox.WrapCommand(ctx, inv)
		if err != nil {
			return nil, err
		}
	}
	if len(wrapped.Argv) == 0 {
		wrapped = inv
	}
	cmd := exec.Command(wrapped.Argv[0], wrapped.Argv[1:]...)
	cmd.Dir = wrapped.Cwd
	cmd.Env = append(os.Environ(), wrapped.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, nil
}

func disallowedAutoBackground(command string) bool {
	analysis := analyzeCommand(command)
	if analysis.Kind != analysisSimple || len(analysis.Commands) == 0 {
		return false
	}
	return cmdName(analysis.Commands[0]) == "sleep"
}

func openOutputFile(path string) (*os.File, error) {
	flags := os.O_CREATE | os.O_EXCL | os.O_WRONLY
	if nofollow := noFollowFlag(); nofollow != 0 {
		flags |= nofollow
	}
	return os.OpenFile(path, flags, 0o600)
}

func noFollowFlag() int {
	return syscall.O_NOFOLLOW
}

func readOutput(path string, max int64) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", false, err
	}
	truncated := info.Size() > max
	if truncated {
		if _, err := file.Seek(-max, io.SeekEnd); err != nil {
			return "", false, err
		}
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, file); err != nil {
		return "", false, err
	}
	return buf.String(), truncated, nil
}

func readCwdFile(path, fallback string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	cwd := string(bytes.TrimSpace(data))
	if cwd == "" {
		return fallback
	}
	return cwd
}

func envList(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func exitCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			return status.ExitStatus()
		}
	}
	return 1
}
