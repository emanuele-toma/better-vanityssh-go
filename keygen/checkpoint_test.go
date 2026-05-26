package keygen

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadCheckpoint_RoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "cp.json")
	const want int64 = 123456

	if err := SaveCheckpoint(path, want); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	got, err := LoadCheckpoint(path)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if got != want {
		t.Errorf("LoadCheckpoint = %d, want %d", got, want)
	}
}

func TestLoadCheckpoint_NotExist(t *testing.T) {
	t.Parallel()

	got, err := LoadCheckpoint(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d, want 0 for missing file", got)
	}
}

func TestLoadCheckpoint_CorruptJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "cp.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadCheckpoint(path)
	if err == nil {
		t.Fatal("want error for corrupt JSON, got nil")
	}
}

func TestLoadCheckpoint_WrongVersion(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "cp.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"keys_checked":0}`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadCheckpoint(path)
	if err == nil {
		t.Fatal("want error for wrong version, got nil")
	}
}

func TestLoadCheckpoint_NegativeKeys(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "cp.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"keys_checked":-1}`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadCheckpoint(path)
	if err == nil {
		t.Fatal("want error for negative keys_checked, got nil")
	}
}

func TestSaveCheckpoint_AtomicWrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")

	if err := SaveCheckpoint(path, 42); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file should be removed after successful save")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("checkpoint file should exist: %v", err)
	}
}

func TestRunCheckpointSaver_SavesOnCancel(t *testing.T) {
	// Not parallel: modifies deterministicIndex.
	const wantIndex int64 = 2048
	deterministicIndex.Store(wantIndex)
	t.Cleanup(func() { ResetCounters() })

	path := filepath.Join(t.TempDir(), "cp.json")
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- RunCheckpointSaver(ctx, path)
	}()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunCheckpointSaver: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunCheckpointSaver did not return after cancel")
	}

	got, err := LoadCheckpoint(path)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if got != wantIndex {
		t.Errorf("checkpoint = %d, want %d", got, wantIndex)
	}
}
