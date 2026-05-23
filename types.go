package bashruntime

import "time"

type Behavior string

const (
	BehaviorAllow       Behavior = "allow"
	BehaviorAsk         Behavior = "ask"
	BehaviorDeny        Behavior = "deny"
	BehaviorPassthrough Behavior = "passthrough"
)

type TaskStatus string

const (
	TaskStatusRunning             TaskStatus = "running"
	TaskStatusCompleted           TaskStatus = "completed"
	TaskStatusKilled              TaskStatus = "killed"
	TaskStatusTimedOut            TaskStatus = "timed_out"
	TaskStatusOutputLimitExceeded TaskStatus = "output_limit_exceeded"
	TaskStatusNeedsInput          TaskStatus = "needs_input"
)

type Request struct {
	Command                   string
	Timeout                   time.Duration
	Description               string
	RunInBackground           bool
	DangerouslyDisableSandbox bool
	Cwd                       string
	Env                       map[string]string
}

type SessionEnv map[string]string

type Result struct {
	Decision    PermissionDecision
	ExitCode    int
	Stdout      string
	Stderr      string
	Cwd         string
	TaskID      string
	OutputPath  string
	Truncated   bool
	SandboxUsed bool
}

type PermissionDecision struct {
	Behavior       Behavior
	Reason         string
	Suggestions    []PermissionSuggestion
	BlockedPath    string
	UpdatedRequest *Request
}

type PermissionSuggestion struct {
	Behavior Behavior
	Rule     string
}

type Config struct {
	Sandbox         SandboxConfig
	Permissions     PermissionsConfig
	ResourceLimits  ResourceLimitsConfig
	Output          OutputConfig
	Shell           ShellConfig
	BackgroundTasks BackgroundTasksConfig

	defaultsApplied bool
}

type PermissionsConfig struct {
	Allow []string
	Ask   []string
	Deny  []string
}

type SandboxConfig struct {
	Enabled                  bool
	FailIfUnavailable        bool
	AutoAllowBashIfSandboxed bool
	AllowUnsandboxedCommands bool
	ExcludedCommands         []string
	Filesystem               FilesystemSandboxConfig
	Network                  NetworkSandboxConfig
}

type FilesystemSandboxConfig struct {
	AllowRead  []string
	DenyRead   []string
	AllowWrite []string
	DenyWrite  []string
}

type NetworkSandboxConfig struct {
	AllowedDomains    []string
	DeniedDomains     []string
	AllowUnixSockets  bool
	AllowLocalBinding bool
}

type ResourceLimitsConfig struct {
	DefaultTimeout       time.Duration
	MaxInlineBytes       int64
	MaxMemoryBufferBytes int64
	MaxTaskOutputBytes   int64
	MaxPersistedBytes    int64
}

type OutputConfig struct {
	Dir string
}

type ShellConfig struct {
	Path         string
	SnapshotPath string
	SkipSnapshot bool
	SessionEnv   SessionEnv
}

type BackgroundTasksConfig struct {
	Enabled                 bool
	StallAfter              time.Duration
	ProgressTailBytes       int64
	AutoBackgroundOnTimeout bool
}

type ReadOptions struct {
	TailBytes int64
	Offset    int64
	Limit     int64
}

type TaskOutput struct {
	TaskID     string
	Status     TaskStatus
	Output     string
	OutputPath string
	ExitCode   *int
	Running    bool
	Truncated  bool
	NeedsInput bool
	Reason     string
}
