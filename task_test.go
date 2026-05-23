package bashruntime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMarkLikelyPromptUsesConfiguredStallAfter(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "task.log")
	if err := os.WriteFile(output, []byte("Continue? (y/n)"), 0o600); err != nil {
		t.Fatal(err)
	}
	tk := &task{
		outputPath: output,
		started:    time.Now().Add(-time.Second),
		running:    true,
	}

	markLikelyPrompt(tk, 10*time.Second)
	if tk.needsInput {
		t.Fatal("needsInput before stall threshold")
	}

	markLikelyPrompt(tk, time.Millisecond)
	if !tk.needsInput {
		t.Fatal("needsInput = false after stall threshold")
	}
	if tk.status != TaskStatusNeedsInput {
		t.Fatalf("status = %s, want needs_input", tk.status)
	}
}
