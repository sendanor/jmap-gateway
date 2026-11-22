package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type submissionRecord struct {
	ID              string
	EmailID         string
	ThreadID        string `json:",omitempty"`
	IdentityID      string
	From            string
	To              string             `json:",omitempty"`
	Recipients      []string           `json:",omitempty"`
	DSN             *dsnOptions        `json:",omitempty"`
	AcceptedReplies map[string]string  `json:",omitempty"`
	ReportKey       string             `json:",omitempty"`
	DeliveryReports []submissionReport `json:",omitempty"`
	SendAt          time.Time
	Status          string
}

func (entry submissionRecord) recipients() []string {
	if entry.Recipients != nil {
		return entry.Recipients
	}
	return []string{entry.To}
}

type ledger struct {
	dir     string
	lock    *os.File
	account string
	records map[string]submissionRecord
	files   atomicFiles
	failed  bool
}

type syncCloser interface {
	Sync() error
	Close() error
}

type temporaryFile interface {
	syncCloser
	io.Writer
	Name() string
}

// These operations define the durability boundary for an atomic replacement.
type atomicFiles struct {
	createTemp    func(dir, pattern string) (temporaryFile, error)
	rename        func(source, destination string) error
	remove        func(path string) error
	openDirectory func(path string) (syncCloser, error)
}

var localAtomicFiles = atomicFiles{
	createTemp:    func(dir, pattern string) (temporaryFile, error) { return os.CreateTemp(dir, pattern) },
	rename:        os.Rename,
	remove:        os.Remove,
	openDirectory: func(path string) (syncCloser, error) { return os.Open(path) },
}

func openLedger(dir, account string) (*ledger, error) {
	return openLedgerWithFiles(dir, account, localAtomicFiles)
}

func openLedgerWithFiles(dir, account string, files atomicFiles) (*ledger, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("cannot create state directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be private")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("cannot open state lock")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("state directory is already in use")
	}
	l := &ledger{dir: dir, lock: lock, account: account, records: make(map[string]submissionRecord), files: files}
	data, err := os.ReadFile(filepath.Join(dir, "submissions.json"))
	if os.IsNotExist(err) {
		if l.save() != nil {
			lock.Close()
			return nil, errors.New("cannot initialize state directory")
		}
		return l, nil
	}
	var saved struct {
		Account string
		Records map[string]submissionRecord
	}
	if err != nil || json.Unmarshal(data, &saved) != nil || saved.Account != account || saved.Records == nil {
		lock.Close()
		return nil, errors.New("invalid state file or account mismatch")
	}
	for key, entry := range saved.Records {
		if !jmapID.MatchString(key) || !jmapID.MatchString(entry.ID) ||
			!jmapID.MatchString(entry.EmailID) || !jmapID.MatchString(entry.IdentityID) ||
			(entry.ThreadID != "" && !jmapID.MatchString(entry.ThreadID)) ||
			(!validAddress(entry.From) || validateRecipients(entry.recipients()) != nil) ||
			(entry.DSN != nil && len(entry.DSN.Recipients) != len(entry.recipients())) ||
			(entry.ReportKey != "" && (entry.DSN == nil || !jmapID.MatchString(entry.ReportKey))) ||
			entry.SendAt.IsZero() || (entry.Status != "pending" && entry.Status != "accepted" && entry.Status != "destroyed") {
			lock.Close()
			return nil, errors.New("invalid submission record")
		}
	}
	l.records = saved.Records
	return l, nil
}

func (l *ledger) save() error {
	_, err := l.persist()
	return err
}

func (l *ledger) persist() (bool, error) {
	if l.failed {
		return false, errors.New("submission ledger requires recovery")
	}
	saved := struct {
		Account string
		Records map[string]submissionRecord
	}{l.account, l.records}
	replaced, err := l.files.replaceWithVisibility(l.dir, "submissions.json", ".submissions-*", func(w io.Writer) error {
		return json.NewEncoder(w).Encode(saved)
	})
	if err != nil {
		l.failed = true
		return replaced, fmt.Errorf("submission ledger write failed: %w", err)
	}
	return replaced, nil
}

func (files atomicFiles) replace(dir, name, pattern string, write func(io.Writer) error) error {
	_, err := files.replaceWithVisibility(dir, name, pattern, write)
	return err
}

// The rename makes the replacement visible. The directory sync makes it durable.
func (files atomicFiles) replaceWithVisibility(dir, name, pattern string, write func(io.Writer) error) (bool, error) {
	file, err := files.createTemp(dir, pattern)
	if err != nil {
		return false, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := write(file); err != nil {
		return false, err
	}
	if err := file.Sync(); err != nil {
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	if err := files.rename(file.Name(), filepath.Join(dir, name)); err != nil {
		return false, err
	}
	directory, err := files.openDirectory(dir)
	if err != nil {
		return true, err
	}
	defer directory.Close()
	return true, directory.Sync()
}
