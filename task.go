package bashruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type taskManager struct {
	cfg   Config
	mu    sync.Mutex
	tasks map[string]*task
}

type task struct {
	id         string
	outputPath string
	cmd        *os.Process
	cwdFile    string
	started    time.Time

	mu         sync.Mutex
	running    bool
	exitCode   *int
	err        error
	needsInput bool
	reason     string
	status     TaskStatus
}

func newTaskManager(cfg Config) *taskManager {
	return &taskManager{cfg: cfg, tasks: map[string]*task{}}
}

func (tm *taskManager) start(ctx context.Context, r *Runtime, req Request, sandboxUsed bool) (*task, error) {
	id := newID("task")
	outputPath := filepath.Join(r.outputDir, id+".log")
	file, err := openOutputFile(outputPath)
	if err != nil {
		return nil, err
	}
	cwdFile := filepath.Join(r.outputDir, id+".cwd")
	cmd, err := r.command(ctx, req, cwdFile, sandboxUsed)
	if err != nil {
		file.Close()
		return nil, err
	}
	cmd.Stdout = file
	cmd.Stderr = file
	if err := cmd.Start(); err != nil {
		file.Close()
		return nil, err
	}
	t := &task{
		id:         id,
		outputPath: outputPath,
		cmd:        cmd.Process,
		cwdFile:    cwdFile,
		started:    time.Now(),
		running:    true,
		status:     TaskStatusRunning,
	}
	tm.mu.Lock()
	tm.tasks[id] = t
	tm.mu.Unlock()

	go func() {
		defer file.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var waitErr error
		for {
			select {
			case waitErr = <-done:
				code := exitCodeFromError(waitErr)
				t.mu.Lock()
				t.running = false
				t.exitCode = &code
				t.err = waitErr
				if t.status == TaskStatusRunning || t.status == "" {
					t.status = TaskStatusCompleted
				}
				t.mu.Unlock()
				_ = r.sandbox.CleanupAfterCommand(context.Background(), SandboxCleanup{Cwd: req.Cwd, OriginalCwd: r.originalCwd})
				r.setCwd(readCwdFile(cwdFile, req.Cwd))
				return
			case <-ticker.C:
				if tooLarge(outputPath, r.cfg.ResourceLimits.MaxTaskOutputBytes) {
					killProcess(t.cmd)
					code := 137
					t.mu.Lock()
					t.running = false
					t.exitCode = &code
					t.needsInput = false
					t.reason = "task output exceeded limit"
					t.status = TaskStatusOutputLimitExceeded
					t.mu.Unlock()
				}
				markLikelyPrompt(t, r.cfg.BackgroundTasks.StallAfter)
			}
		}
	}()
	_ = sandboxUsed
	return t, nil
}

func (tm *taskManager) adopt(r *Runtime, req Request, process *os.Process, file *os.File, outputPath, cwdFile string, done <-chan error) *task {
	id := newID("task")
	t := &task{
		id:         id,
		outputPath: outputPath,
		cmd:        process,
		cwdFile:    cwdFile,
		started:    time.Now(),
		running:    true,
		status:     TaskStatusRunning,
	}
	tm.mu.Lock()
	tm.tasks[id] = t
	tm.mu.Unlock()
	go func() {
		defer file.Close()
		err := <-done
		code := exitCodeFromError(err)
		t.mu.Lock()
		t.running = false
		t.exitCode = &code
		t.err = err
		if t.status == TaskStatusRunning || t.status == "" {
			t.status = TaskStatusCompleted
		}
		t.mu.Unlock()
		_ = r.sandbox.CleanupAfterCommand(context.Background(), SandboxCleanup{Cwd: req.Cwd, OriginalCwd: r.originalCwd})
		r.setCwd(readCwdFile(cwdFile, req.Cwd))
	}()
	return t
}

func (tm *taskManager) read(ctx context.Context, id string, opts ReadOptions) (TaskOutput, error) {
	t, err := tm.get(id)
	if err != nil {
		return TaskOutput{}, err
	}
	output, truncated, err := readTaskFile(t.outputPath, opts)
	if err != nil {
		return TaskOutput{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return TaskOutput{
		TaskID:     id,
		Status:     t.statusOrDefault(),
		Output:     output,
		OutputPath: t.outputPath,
		ExitCode:   t.exitCode,
		Running:    t.running,
		Truncated:  truncated,
		NeedsInput: t.needsInput,
		Reason:     t.reason,
	}, nil
}

func (tm *taskManager) kill(ctx context.Context, id string) error {
	t, err := tm.get(id)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.running {
		return nil
	}
	if err := killProcess(t.cmd); err != nil {
		return err
	}
	code := 137
	t.exitCode = &code
	t.running = false
	t.reason = "killed"
	t.status = TaskStatusKilled
	return nil
}

func (tm *taskManager) get(id string) (*task, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	t := tm.tasks[id]
	if t == nil {
		return nil, ErrTaskNotFound
	}
	return t, nil
}

func readTaskFile(path string, opts ReadOptions) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", false, err
	}
	var start int64
	var limit int64
	if opts.TailBytes > 0 && info.Size() > opts.TailBytes {
		start = info.Size() - opts.TailBytes
		limit = opts.TailBytes
	} else {
		start = opts.Offset
		limit = opts.Limit
	}
	if start > 0 {
		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return "", false, err
		}
	}
	var reader io.Reader = file
	if limit > 0 {
		reader = io.LimitReader(file, limit)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return "", false, err
	}
	return buf.String(), start > 0, nil
}

func killProcessTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = killProcess(cmd.Process)
}

func killProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return p.Kill()
}

func tooLarge(path string, max int64) bool {
	if max <= 0 {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Size() > max
}

func markLikelyPrompt(t *task, stallAfter time.Duration) {
	t.mu.Lock()
	running := t.running
	t.mu.Unlock()
	if !running || time.Since(t.started) < stallAfter {
		return
	}
	out, _, err := readTaskFile(t.outputPath, ReadOptions{TailBytes: 512})
	if err != nil {
		return
	}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "(y/n)") || strings.Contains(lower, "press enter") || strings.Contains(lower, "password:") {
		t.mu.Lock()
		t.needsInput = true
		t.reason = "likely interactive prompt"
		t.status = TaskStatusNeedsInput
		t.mu.Unlock()
	}
}

func (t *task) statusOrDefault() TaskStatus {
	if t.status != "" {
		return t.status
	}
	if t.running {
		return TaskStatusRunning
	}
	return TaskStatusCompleted
}

func newID(prefix string) string {
	return prefix + "-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "-")
}

func scrubBareRepoFiles(dir string) {
	if dir == "" {
		return
	}
	for _, name := range []string{"HEAD", "objects", "refs", "hooks", "config"} {
		path := filepath.Join(dir, name)
		_ = os.RemoveAll(path)
	}
}

var _ = errors.Is
