package keygen

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const checkpointVersion = 1

// checkpointSaveInterval is how often RunCheckpointSaver writes state to disk.
const checkpointSaveInterval = 5 * time.Minute

// checkpointState is the JSON-serializable checkpoint data.
type checkpointState struct {
	Version     int   `json:"version"`
	KeysChecked int64 `json:"keys_checked"`
}

// SaveCheckpoint atomically writes the current deterministic key index to path.
// It writes to a .tmp file then renames to prevent partial writes.
func SaveCheckpoint(path string, keysChecked int64) error {
	state := checkpointState{
		Version:     checkpointVersion,
		KeysChecked: keysChecked,
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write checkpoint temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename checkpoint file: %w", err)
	}
	return nil
}

// LoadCheckpoint reads the checkpoint at path and returns the keys_checked value.
// Returns 0 and nil if the file does not exist (fresh start).
func LoadCheckpoint(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read checkpoint file: %w", err)
	}
	var state checkpointState
	if err := json.Unmarshal(data, &state); err != nil {
		return 0, fmt.Errorf("parse checkpoint file: %w", err)
	}
	if state.Version != checkpointVersion {
		return 0, fmt.Errorf("unsupported checkpoint version %d (want %d)", state.Version, checkpointVersion)
	}
	if state.KeysChecked < 0 {
		return 0, fmt.Errorf("invalid checkpoint: keys_checked %d is negative", state.KeysChecked)
	}
	return state.KeysChecked, nil
}

// RunCheckpointSaver is a goroutine function for use with errgroup. It saves
// the current deterministicIndex to path every checkpointSaveInterval, and
// saves a final checkpoint when ctx is cancelled.
func RunCheckpointSaver(ctx context.Context, path string) error {
	ticker := time.NewTicker(checkpointSaveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := SaveCheckpoint(path, deterministicIndex.Load()); err != nil {
				return fmt.Errorf("periodic checkpoint save: %w", err)
			}
		case <-ctx.Done():
			if err := SaveCheckpoint(path, deterministicIndex.Load()); err != nil {
				return fmt.Errorf("final checkpoint save: %w", err)
			}
			return nil
		}
	}
}
