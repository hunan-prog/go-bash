// Package bashruntime provides a local Bash execution runtime for coding
// agents.
//
// The runtime layers static Bash analysis, permission rules, optional OS
// sandboxing, resource limits, cwd tracking, no-follow output files, and
// background task management. Permission prompts are returned as structured
// decisions instead of being handled by the package.
package bashruntime
