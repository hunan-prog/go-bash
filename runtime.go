package bashruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Runtime struct {
	cfg          Config
	sandbox      SandboxProvider
	tasks        *taskManager
	mu           sync.Mutex
	cwd          string
	originalCwd  string
	outputDir    string
	snapshotPath string
	shellPath    string
}

type Option func(*Runtime)

func WithSandboxProvider(provider SandboxProvider) Option {
	return func(r *Runtime) {
		r.sandbox = provider
	}
}

func WithShellSnapshot(path string) Option {
	return func(r *Runtime) {
		r.snapshotPath = path
	}
}

func DefaultConfig() Config {
	var cfg Config
	applyDefaults(&cfg)
	cfg.defaultsApplied = true
	return cfg
}

func New(cfg Config, opts ...Option) (*Runtime, error) {
	if !cfg.defaultsApplied {
		applyDefaults(&cfg)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	outDir := cfg.Output.Dir
	if outDir == "" {
		outDir = filepath.Join(os.TempDir(), "go-bash-runtime")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	r := &Runtime{
		cfg:         cfg,
		sandbox:     systemSandboxProvider{cfg: cfg, outputDir: outDir},
		tasks:       newTaskManager(cfg),
		cwd:         cwd,
		originalCwd: cwd,
		outputDir:   outDir,
		shellPath:   cfg.Shell.Path,
	}
	if r.shellPath == "" {
		r.shellPath = "/bin/bash"
	}
	r.snapshotPath = cfg.Shell.SnapshotPath
	if r.snapshotPath == "" && !cfg.Shell.SkipSnapshot {
		r.snapshotPath = filepath.Join(outDir, "shell-snapshot.bash")
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.snapshotPath != "" {
		_ = ensureSnapshot(r.snapshotPath, r.shellPath)
	}
	return r, nil
}

func applyDefaults(cfg *Config) {
	if cfg.ResourceLimits.DefaultTimeout == 0 {
		cfg.ResourceLimits.DefaultTimeout = 2 * time.Minute
	}
	if cfg.ResourceLimits.MaxInlineBytes == 0 {
		cfg.ResourceLimits.MaxInlineBytes = 30 * 1024
	}
	if cfg.ResourceLimits.MaxMemoryBufferBytes == 0 {
		cfg.ResourceLimits.MaxMemoryBufferBytes = 8 * 1024 * 1024
	}
	if cfg.ResourceLimits.MaxPersistedBytes == 0 {
		cfg.ResourceLimits.MaxPersistedBytes = 64 * 1024 * 1024
	}
	if cfg.ResourceLimits.MaxTaskOutputBytes == 0 {
		cfg.ResourceLimits.MaxTaskOutputBytes = 5 * 1024 * 1024 * 1024
	}
	defaultBackgroundTasks(&cfg.BackgroundTasks)
	defaultSandbox(&cfg.Sandbox)
}

func defaultBackgroundTasks(cfg *BackgroundTasksConfig) {
	if cfg.StallAfter == 0 {
		cfg.StallAfter = 45 * time.Second
	}
	if cfg.ProgressTailBytes == 0 {
		cfg.ProgressTailBytes = 4096
	}
	cfg.Enabled = true
	cfg.AutoBackgroundOnTimeout = true
}

func defaultSandbox(cfg *SandboxConfig) {
	cfg.AutoAllowBashIfSandboxed = true
	cfg.AllowUnsandboxedCommands = true
}

func (r *Runtime) Run(ctx context.Context, req Request) (Result, error) {
	if req.Command == "" {
		return Result{Decision: deny("empty command")}, nil
	}
	decision, sandboxUsed, err := r.check(ctx, req)
	if err != nil {
		return Result{}, err
	}
	if decision.Behavior != BehaviorAllow {
		return Result{Decision: decision, Cwd: r.currentCwd(req.Cwd)}, nil
	}
	req.Cwd = r.currentCwd(req.Cwd)
	if req.RunInBackground {
		if !r.cfg.BackgroundTasks.Enabled {
			return Result{Decision: ask("background tasks are disabled"), Cwd: req.Cwd}, nil
		}
		task, err := r.tasks.start(ctx, r, req, sandboxUsed)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Decision:    decision,
			TaskID:      task.id,
			OutputPath:  task.outputPath,
			Cwd:         req.Cwd,
			SandboxUsed: sandboxUsed,
		}, nil
	}
	return r.runForeground(ctx, req, decision, sandboxUsed)
}

func (r *Runtime) Check(ctx context.Context, req Request) (PermissionDecision, error) {
	decision, _, err := r.check(ctx, req)
	return decision, err
}

func (r *Runtime) DiagnoseSandbox(ctx context.Context) SandboxDiagnostics {
	return r.sandbox.CheckDependencies(ctx)
}

func (r *Runtime) ReadTask(ctx context.Context, id string, opts ReadOptions) (TaskOutput, error) {
	return r.tasks.read(ctx, id, opts)
}

func (r *Runtime) KillTask(ctx context.Context, id string) error {
	return r.tasks.kill(ctx, id)
}

func (r *Runtime) check(ctx context.Context, req Request) (PermissionDecision, bool, error) {
	analysis := analyzeCommand(req.Command)
	if analysis.Kind == analysisTooComplex {
		return ask("too-complex: " + analysis.Reason), false, nil
	}
	if analysis.Kind == analysisParseError {
		return ask("parse-unavailable: " + analysis.Reason), false, nil
	}

	sandboxUsed, sandboxReason := r.shouldUseSandbox(ctx, req)
	if strings.HasPrefix(sandboxReason, "sandbox required but unavailable:") {
		return deny(sandboxReason), false, nil
	}
	policy := evaluatePolicy(req, analysis, r.cfg.Permissions, sandboxUsed && r.cfg.Sandbox.AutoAllowBashIfSandboxed)
	if policy.Behavior == BehaviorAllow && sandboxReason != "" {
		policy.Reason = policy.Reason + "; " + sandboxReason
	}
	return policy, sandboxUsed, nil
}

func (r *Runtime) shouldUseSandbox(ctx context.Context, req Request) (bool, string) {
	if !r.cfg.Sandbox.Enabled {
		return false, ""
	}
	if req.DangerouslyDisableSandbox && r.cfg.Sandbox.AllowUnsandboxedCommands {
		return false, "sandbox override: dangerouslyDisableSandbox"
	}
	if containsExcludedCommand(req.Command, r.cfg.Sandbox.ExcludedCommands) {
		return false, "sandbox override: excludedCommand"
	}
	diag := r.sandbox.CheckDependencies(ctx)
	if diag.Available {
		return true, ""
	}
	if r.cfg.Sandbox.FailIfUnavailable {
		return false, "sandbox required but unavailable: " + diag.Reason
	}
	return false, "sandbox degraded: " + diag.Reason
}

func (r *Runtime) currentCwd(reqCwd string) string {
	if reqCwd != "" {
		if abs, err := filepath.Abs(reqCwd); err == nil {
			return abs
		}
		return reqCwd
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cwd
}

func (r *Runtime) setCwd(cwd string) {
	if cwd == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cwd = cwd
}

func supportedPlatform() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}

var ErrTaskNotFound = errors.New("task not found")
