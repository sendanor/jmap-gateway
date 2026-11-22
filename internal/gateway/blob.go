package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxUploadBytes        = 2 << 20
	maxConcurrentUploads  = 1
	unreferencedBlobQuota = 32 << 20
	maxUnreferencedBlobs  = 4096
)

const uploadFilePrefix = "upload-"

var errBlobQuota = errors.New("unreferenced blob quota exceeded")

type blobStore struct {
	dir   string
	quota int64
	files atomicFiles
}

func (s blobStore) read(id string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, uploadFilePrefix+id))
}

func (s blobStore) put(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	id := "u-" + base64.RawURLEncoding.EncodeToString(hash[:])
	name := uploadFilePrefix + id
	if int64(len(data)) > s.quota {
		return "", errBlobQuota
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return "", err
	}
	if err := evictUploads(entries, name, s.quota-int64(len(data)), maxUnreferencedBlobs-1, func(name string) error {
		return s.files.remove(filepath.Join(s.dir, name))
	}); err != nil {
		return "", err
	}
	err = s.files.replace(s.dir, name, ".upload-*", func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

type storedUpload struct {
	name     string
	size     int64
	uploaded time.Time
}

func evictUploads(entries []os.DirEntry, replacement string, remaining int64, maxCount int, remove func(string) error) error {
	var uploads []storedUpload
	var used int64
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, uploadFilePrefix) || !entry.Type().IsRegular() || name == replacement {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		used += info.Size()
		uploads = append(uploads, storedUpload{name, info.Size(), info.ModTime()})
	}
	if used <= remaining && len(uploads) <= maxCount {
		return nil
	}
	sort.SliceStable(uploads, func(i, j int) bool { return uploads[i].uploaded.Before(uploads[j].uploaded) })
	for i, oldest := range uploads {
		if err := remove(oldest.name); err != nil {
			return err
		}
		used -= oldest.size
		if used <= remaining && len(uploads)-i-1 <= maxCount {
			break
		}
	}
	return nil
}

func (g *Gateway) serveUpload(w http.ResponseWriter, r *http.Request) {
	_, end, ok := g.start(w, r)
	if !ok {
		return
	}
	defer end()
	defer r.Body.Close()
	kind := r.Header.Get("Content-Type")
	if kind == "" {
		kind = "application/octet-stream"
	}
	if mediaType, _, err := mime.ParseMediaType(kind); err != nil || !strings.Contains(mediaType, "/") {
		http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxUploadBytes))
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			problem(w, http.StatusRequestEntityTooLarge, "limit", "maxSizeUpload")
		} else {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
		}
		return
	}
	id, err := g.uploads.put(data)
	switch {
	case errors.Is(err, errBlobQuota):
		http.Error(w, "Upload quota exceeded", http.StatusInsufficientStorage)
	case err != nil:
		http.Error(w, "Upload unavailable", http.StatusServiceUnavailable)
	default:
		writeJSON(w, http.StatusCreated, object{
			"accountId": g.config.AccountID, "blobId": id, "type": kind, "size": len(data),
		})
	}
}
