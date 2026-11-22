package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var diskError = errors.New("fixture disk failure")

type faultFile struct {
	temporaryFile
	stage string
}

func (f faultFile) Write(data []byte) (int, error) {
	if f.stage == "write" {
		return 0, diskError
	}
	return f.temporaryFile.Write(data)
}

func (f faultFile) Sync() error {
	if f.stage == "sync" {
		return diskError
	}
	return f.temporaryFile.Sync()
}

func (f faultFile) Close() error {
	err := f.temporaryFile.Close()
	if f.stage == "close" {
		return diskError
	}
	return err
}

func TestLedgerAtomicWriteFailures(t *testing.T) {
	for _, stage := range []string{"create", "write", "sync", "close", "open-directory"} {
		t.Run(stage, func(t *testing.T) {
			dir := testConfig(t).StateDir
			l, err := openLedger(dir, "account")
			if err != nil {
				t.Fatal(err)
			}
			defer l.lock.Close()
			l.files.createTemp = func(dir, pattern string) (temporaryFile, error) {
				if stage == "create" {
					return nil, diskError
				}
				file, err := localAtomicFiles.createTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				return faultFile{file, stage}, nil
			}
			if stage == "open-directory" {
				l.files.openDirectory = func(string) (syncCloser, error) { return nil, diskError }
			}
			if err := l.save(); !errors.Is(err, diskError) || !l.failed {
				t.Fatalf("failure in %s did not stop ledger: %v", stage, err)
			}
			matches, err := filepath.Glob(filepath.Join(dir, ".submissions-*"))
			if err != nil || len(matches) != 0 {
				t.Fatal("transaction left a temporary file")
			}
			if _, err := os.ReadFile(filepath.Join(dir, "submissions.json")); err != nil {
				t.Fatal("transaction lost the visible ledger")
			}
		})
	}
}

func TestLedgerInitializationFailures(t *testing.T) {
	locked := testConfig(t).StateDir
	if err := os.Mkdir(filepath.Join(locked, "lock"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := openLedger(locked, "a"); err == nil || !strings.Contains(err.Error(), "cannot open state lock") {
		t.Fatalf("unexpected lock failure: %v", err)
	}
	empty := testConfig(t).StateDir
	files := localAtomicFiles
	files.createTemp = func(string, string) (temporaryFile, error) { return nil, diskError }
	if _, err := openLedgerWithFiles(empty, "a", files); err == nil || !strings.Contains(err.Error(), "cannot initialize") {
		t.Fatalf("unexpected initializer failure: %v", err)
	}
	l, err := openLedger(empty, "a")
	if err != nil {
		t.Fatalf("initializer failure leaked its lock: %v", err)
	}
	l.lock.Close()
}
