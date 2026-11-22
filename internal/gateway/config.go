package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	Listen                    string
	PublicOrigin              string
	TLSCert                   string
	TLSKey                    string
	StateDir                  string
	AccountID                 string
	Token                     string
	IdentityName              string
	IdentityEmail             string
	IdentityAliases           []string
	DraftsMailbox             string
	MailboxMetadataVendor     string
	IMAP                      Upstream
	SMTP                      Upstream
	SMTPDeliveryNotifications bool
	ManageSieve               *Upstream
	CalDAV                    *CalDAVConfig
	PushOrigins               []string
	PushCAFile                string
	AdditionalAccounts        []AccountConfig
}

type AccountConfig struct {
	AccountID                 string
	StateDir                  string
	IdentityName              string
	IdentityEmail             string
	IdentityAliases           []string
	DraftsMailbox             string
	MailboxMetadataVendor     string
	IMAP                      Upstream
	SMTP                      Upstream
	SMTPDeliveryNotifications bool
	ManageSieve               *Upstream
	CalDAV                    *CalDAVConfig
}

type Upstream struct {
	Address  string
	Username string
	Password string
	Mode     string
	CAFile   string
}

var jmapID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
var metadataVendor = regexp.MustCompile(`(?i)^vendor\.[a-z0-9_-]{1,64}$`)
var bearer = regexp.MustCompile(`^[A-Za-z0-9._~+/-]{32,256}$`)

func LoadConfig(path string) (Config, error) {
	var config Config
	f, err := os.Open(path)
	if err != nil {
		return config, errors.New("cannot open configuration")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return config, errors.New("configuration must be a private regular file of at most 64 KiB")
	}
	dec := json.NewDecoder(io.LimitReader(f, 65537))
	dec.DisallowUnknownFields()
	if dec.Decode(&config) != nil || dec.Decode(new(any)) != io.EOF {
		return Config{}, errors.New("invalid JSON configuration")
	}
	return config, nil
}

func (c Config) validate() error {
	origin, err := url.Parse(c.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil ||
		origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" {
		return errors.New("PublicOrigin must be an HTTPS origin without a path")
	}
	if c.Listen == "" || c.TLSCert == "" || c.TLSKey == "" || c.StateDir == "" ||
		!jmapID.MatchString(c.AccountID) || !bearer.MatchString(c.Token) ||
		!validIdentityAddress(c.IdentityEmail) || strings.ContainsAny(c.IdentityName, "\r\n\x00") ||
		strings.ContainsAny(c.DraftsMailbox, "\r\n\x00") {
		return errors.New("invalid listener, state, account, token, identity, or drafts configuration")
	}
	if c.MailboxMetadataVendor != "" && !metadataVendor.MatchString(c.MailboxMetadataVendor) {
		return errors.New("invalid MailboxMetadataVendor token")
	}
	if len(c.IdentityAliases) >= maxIdentities {
		return errors.New("too many identity aliases")
	}
	seen := map[string]bool{c.IdentityEmail: true}
	for _, alias := range c.IdentityAliases {
		if !validIdentityAddress(alias) || seen[alias] {
			return errors.New("invalid or duplicate identity alias")
		}
		seen[alias] = true
	}
	upstreams := map[string]Upstream{"IMAP": c.IMAP, "SMTP": c.SMTP}
	if c.ManageSieve != nil {
		if c.ManageSieve.Mode != "starttls" {
			return errors.New("ManageSieve requires starttls")
		}
		upstreams["ManageSieve"] = *c.ManageSieve
	}
	for label, upstream := range upstreams {
		host, port, err := net.SplitHostPort(upstream.Address)
		if err != nil || host == "" || port == "" || upstream.Username == "" || upstream.Password == "" ||
			strings.ContainsAny(upstream.Username+upstream.Password, "\r\n\x00") {
			return errors.New("invalid " + label + " address or credentials")
		}
	}
	if c.IMAP.Mode != "tls" || (c.SMTP.Mode != "tls" && c.SMTP.Mode != "starttls") {
		return errors.New("IMAP requires tls and SMTP requires tls or starttls")
	}
	return nil
}

func ServerTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func upstreamTLS(config Upstream) (*tls.Config, error) {
	tlsConfig := ServerTLS()
	tlsConfig.ServerName, _, _ = net.SplitHostPort(config.Address)
	if config.CAFile != "" {
		rootPEM, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, errors.New("cannot read upstream CA")
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootPEM) {
			return nil, errors.New("invalid upstream CA")
		}
	}
	return tlsConfig, nil
}

// The IMAP client sets per-command deadlines. Clamp them to the API request deadline.
type boundedConn struct {
	net.Conn
	deadline time.Time
}

func (c boundedConn) clamp(t time.Time) time.Time {
	if t.IsZero() || t.After(c.deadline) {
		return c.deadline
	}
	return t
}

func (c boundedConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(c.clamp(t)) }
func (c boundedConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(c.clamp(t)) }
func (c boundedConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(c.clamp(t)) }

func dial(ctx context.Context, address string) (net.Conn, func(), error) {
	deadline := time.Now().Add(15 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, func() {}, err
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return boundedConn{conn, deadline}, func() {
		stop()
		_ = conn.Close()
	}, nil
}
