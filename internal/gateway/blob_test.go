package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func uploadRequest(g *Gateway, token, kind string, body io.Reader) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/upload/"+g.config.AccountID, body)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if kind != "" {
		request.Header.Set("Content-Type", kind)
	}
	response := httptest.NewRecorder()
	g.ServeHTTP(response, request)
	return response
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	config := testConfig(t)
	handler, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{0, 13, 255, 128, 0}
	upload := func(kind string) object {
		t.Helper()
		response := uploadRequest(handler, config.Token, kind, bytes.NewReader(data))
		var result object
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &result) != nil {
			t.Fatalf("upload HTTP %d: %s", response.Code, response.Body)
		}
		return result
	}
	session := gatewayRequest(handler, http.MethodGet, "/.well-known/jmap", config.Token, nil)
	var details struct {
		Capabilities map[string]object `json:"capabilities"`
	}
	if err := json.Unmarshal(session.Body.Bytes(), &details); err != nil ||
		details.Capabilities[core]["maxSizeUpload"] != float64(maxUploadBytes) ||
		details.Capabilities[core]["maxConcurrentUpload"] != float64(1) {
		t.Fatalf("unexpected Core limits: %v", details.Capabilities[core])
	}
	result := upload("image/jpeg")
	blobID := result["blobId"].(string)
	if result["accountId"] != config.AccountID || result["type"] != "image/jpeg" || result["size"] != float64(len(data)) {
		t.Fatalf("invalid upload response: %v", result)
	}
	duplicate := upload("")
	if duplicate["blobId"] != blobID || duplicate["type"] != "application/octet-stream" {
		t.Fatalf("unexpected duplicate response: %v", duplicate)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	handler, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	target := "/download/" + config.AccountID + "/" + blobID + "/tiedosto-%C3%A4.dat"
	for _, test := range []struct{ query, kind string }{
		{"?type=application%2Fx-test", "application/x-test"},
		{"?type=invalid", "application/octet-stream"},
	} {
		response := gatewayRequest(handler, http.MethodGet, target+test.query, config.Token, nil)
		disposition, parameters, err := mime.ParseMediaType(response.Header().Get("Content-Disposition"))
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), data) ||
			response.Header().Get("Content-Type") != test.kind || err != nil ||
			disposition != "attachment" || parameters["filename"] != "tiedosto-ä.dat" {
			t.Fatalf("download HTTP %d, headers %v, bytes %x", response.Code, response.Header(), response.Body.Bytes())
		}
	}
	if result := gatewayRequest(handler, http.MethodGet, target, "foreign", nil); result.Code != http.StatusUnauthorized {
		t.Fatal("download accepted wrong credentials")
	}
	if result := gatewayRequest(handler, http.MethodGet, strings.Replace(target, config.AccountID, "other", 1), config.Token, nil); result.Code != http.StatusNotFound {
		t.Fatal("blob leaked across an account boundary")
	}
	if response := gatewayRequest(handler, http.MethodGet, "/download/"+config.AccountID+"/u-"+strings.Repeat("z", 43)+"/file", config.Token, nil); response.Code != http.StatusNotFound {
		t.Fatal("missing upload did not return HTTP 404")
	}
	if err := os.Remove(filepath.Join(handler.uploads.dir, uploadFilePrefix+blobID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(handler.uploads.dir, uploadFilePrefix+blobID), 0700); err != nil {
		t.Fatal(err)
	}
	if response := gatewayRequest(handler, http.MethodGet, target, config.Token, nil); response.Code != http.StatusServiceUnavailable {
		t.Fatal("failed blob read did not return HTTP 503")
	}
}

func TestUploadFailures(t *testing.T) {
	config := testConfig(t)
	handler, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	if response := uploadRequest(handler, "", "image/jpeg", strings.NewReader("bytes")); response.Code != http.StatusUnauthorized {
		t.Fatal("upload accepted unauthenticated request")
	}
	if response := uploadRequest(handler, config.Token, "invalid", strings.NewReader("bytes")); response.Code != http.StatusUnsupportedMediaType {
		t.Fatal("upload accepted invalid media type")
	}
	if response := uploadRequest(handler, config.Token, "image/jpeg", failingReader{}); response.Code != http.StatusBadRequest {
		t.Fatal("upload accepted interrupted body")
	}
	tooLarge := strings.NewReader(strings.Repeat("x", maxUploadBytes+1))
	checkProblem(t, uploadRequest(handler, config.Token, "", tooLarge), 413, "limit", "maxSizeUpload")
	for range maxConcurrent {
		handler.admitted <- struct{}{}
	}
	checkProblem(t, uploadRequest(handler, config.Token, "", nil), 503, "limit", "maxConcurrentRequests")
	for range maxConcurrent {
		<-handler.admitted
	}
	handler.uploads.quota = 1
	if response := uploadRequest(handler, config.Token, "image/jpeg", strings.NewReader("bytes")); response.Code != http.StatusInsufficientStorage {
		t.Fatal("upload accepted input above account quota")
	}
	handler.uploads.quota = unreferencedBlobQuota
	handler.uploads.dir = filepath.Join(config.StateDir, "absent")
	if response := uploadRequest(handler, config.Token, "image/jpeg", strings.NewReader("bytes")); response.Code != http.StatusServiceUnavailable {
		t.Fatal("upload did not report unavailable state directory")
	}
	handler.uploads.dir = config.StateDir
	handler.uploads.files.rename = func(string, string) error { return diskError }
	if response := uploadRequest(handler, config.Token, "image/jpeg", strings.NewReader("bytes")); response.Code != http.StatusServiceUnavailable {
		t.Fatal("upload did not report failed file commit")
	}
}

type badUploadEntry struct{ os.DirEntry }

func (badUploadEntry) Info() (os.FileInfo, error) { return nil, diskError }

func TestBlobQuotaEvictsOldest(t *testing.T) {
	store := blobStore{dir: t.TempDir(), quota: 6, files: localAtomicFiles}
	put := func(raw string) string {
		t.Helper()
		id, err := store.put([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := put("aa")
	second := put("bb")
	third := put("cc")
	now := time.Now()
	for i, id := range []string{first, second, third} {
		stamp := now.Add(time.Duration(i-3) * time.Minute)
		if err := os.Chtimes(filepath.Join(store.dir, uploadFilePrefix+id), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if ref := put("aa"); ref != first {
		t.Fatal("duplicate content changed its blob ID")
	}
	d := put("dddd")
	for _, id := range []string{second, third} {
		if _, err := store.read(id); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("old blob %q remained after eviction: %v", id, err)
		}
	}
	for id, want := range map[string]string{first: "aa", d: "dddd"} {
		data, err := store.read(id)
		if err != nil || string(data) != want {
			t.Fatalf("retained blob %q returned %q %v", id, data, err)
		}
	}
	if err := os.Mkdir(filepath.Join(store.dir, uploadFilePrefix+"folder"), 0700); err != nil {
		t.Fatal(err)
	}
	store.quota = 32
	put("nonregular entry is ignored") // Within quota after evicting the earlier files.
}

func TestBlobEvictionFailures(t *testing.T) {
	store := blobStore{dir: t.TempDir(), quota: 1, files: localAtomicFiles}
	if _, err := store.put([]byte("a")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(store.dir)
	if err != nil {
		t.Fatal(err)
	}
	failRemove := func(string) error { return diskError }
	if err := evictUploads(entries, "", 0, maxUnreferencedBlobs, failRemove); !errors.Is(err, diskError) {
		t.Fatalf("incorrect remove error: %v", err)
	}
	if err := evictUploads([]os.DirEntry{badUploadEntry{entries[0]}}, "", 0, maxUnreferencedBlobs, failRemove); !errors.Is(err, diskError) {
		t.Fatalf("incorrect stat error: %v", err)
	}
	store.files.remove = failRemove
	if _, err := store.put([]byte("b")); !errors.Is(err, diskError) {
		t.Fatalf("store ignored removal failure: %v", err)
	}
	var removed int
	if err := evictUploads(entries, "", 100, 0, func(string) error { removed++; return nil }); err != nil || removed != 1 {
		t.Fatal("file count did not trigger eviction")
	}
}
