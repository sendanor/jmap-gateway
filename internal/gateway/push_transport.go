package gateway

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	pushTTL          = 60
	pushRecordSize   = 4096
	pushRequestLimit = 2 * time.Second
)

type pushKeys struct {
	Public string `json:"p256dh"`
	Auth   string `json:"auth"`
}

func (keys pushKeys) decode() (*ecdh.PublicKey, []byte, bool) {
	point, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(keys.Public, "="))
	public, pointErr := ecdh.P256().NewPublicKey(point)
	auth, authErr := base64.RawURLEncoding.DecodeString(strings.TrimRight(keys.Auth, "="))
	return public, auth, err == nil && pointErr == nil && authErr == nil && len(auth) == 16
}

func encryptPush(data []byte, keys *pushKeys) ([]byte, error) {
	public, auth, ok := keys.decode()
	if !ok {
		return nil, errors.New("invalid push keys")
	}
	if len(data)+103 > pushRecordSize {
		return nil, errors.New("push message exceeds record limit")
	}
	// The system random reader is the entropy source for the salt and key.
	private, _ := ecdh.P256().GenerateKey(rand.Reader)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return sealPush(data, public, auth, private, salt)
}

func sealPush(data []byte, browser *ecdh.PublicKey, auth []byte, ephemeral *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	shared, err := ephemeral.ECDH(browser)
	if err != nil {
		return nil, err
	}
	public := ephemeral.PublicKey().Bytes()
	info := "WebPush: info\x00" + string(browser.Bytes()) + string(public)
	// The fixed output sizes are within the HKDF and AES limits.
	ikm, _ := hkdf.Key(sha256.New, shared, auth, info, 32)
	key, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	header := append(make([]byte, 0, 21+len(public)+pushRecordSize), salt...)
	header = binary.BigEndian.AppendUint32(header, pushRecordSize)
	header = append(header, byte(len(public)))
	header = append(header, public...)
	plain := append(bytes.Clone(data), 2)
	return gcm.Seal(header, nonce, plain, nil), nil
}

func pushURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || !strings.HasPrefix(raw, "https://") ||
		u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, false
	}
	return u, true
}

func pushOrigin(u *url.URL) string {
	host := strings.ToLower(u.Host)
	return "https://" + strings.TrimSuffix(host, ":443")
}

func (p *pushStore) allows(raw string) bool {
	u, ok := pushURL(raw)
	return ok && p.origins[pushOrigin(u)]
}

func (p *pushStore) post(ctx context.Context, subscription pushSubscription, data object) (int, string) {
	if !p.allows(subscription.URL) || !time.Now().Before(subscription.Expires) {
		return 0, ""
	}
	payload, _ := json.Marshal(data)
	var encoding string
	if subscription.Keys != nil {
		var err error
		payload, err = encryptPush(payload, subscription.Keys)
		if err != nil {
			return 0, ""
		}
		encoding = "aes128gcm"
	}
	ctx, cancel := context.WithDeadline(ctx, subscription.Expires)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, subscription.URL, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("TTL", strconv.Itoa(pushTTL))
	if encoding != "" {
		request.Header.Set("Content-Encoding", encoding)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return 0, ""
	}
	_ = response.Body.Close()
	return response.StatusCode, response.Header.Get("Retry-After")
}

func pushRetry(now time.Time, raw string) time.Time {
	minimum := now.Add(15 * time.Second)
	if seconds, err := strconv.ParseUint(raw, 10, 32); err == nil {
		return now.Add(time.Duration(max(15, seconds)) * time.Second)
	}
	if date, err := http.ParseTime(raw); err == nil && date.After(minimum) {
		return date
	}
	return minimum
}
