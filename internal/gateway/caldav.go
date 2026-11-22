package gateway

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

const calendarPreview = "https://github.com/sendanor/jmap-gateway/capabilities/calendars-preview"
const maxDAVResponse = 4 << 20

type CalDAVConfig struct {
	URL      string
	Username string
	Password string
	CAFile   string
}

type calDAV struct {
	base     *url.URL
	username string
	password string
	client   *http.Client
}

func newCalDAV(config *CalDAVConfig) (*calDAV, error) {
	if config == nil {
		return nil, nil
	}
	base, err := url.Parse(config.URL)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || !safeDAVURL(base) ||
		config.Username == "" || config.Password == "" || strings.Contains(config.Username, ":") ||
		strings.ContainsAny(config.Username+config.Password, "\r\n\x00") {
		return nil, errors.New("invalid CalDAV URL or credentials")
	}
	tlsConfig, err := upstreamTLS(Upstream{Address: net.JoinHostPort(base.Hostname(), "443"), CAFile: config.CAFile})
	if err != nil {
		return nil, err
	}
	return &calDAV{
		base: base, username: config.Username, password: config.Password,
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true},
			Timeout:   15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func safeDAVURL(u *url.URL) bool {
	p := u.Path
	return u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" &&
		!strings.ContainsAny(p, "\\\x00\r\n") && !strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") && p != ".." && !strings.HasPrefix(p, "../") &&
		(p == "" || p == "/" || path.Clean(p) == strings.TrimSuffix(p, "/"))
}

func (dav *calDAV) resolve(base *url.URL, href string) *url.URL {
	href = strings.TrimSpace(href)
	ref, err := url.Parse(href)
	if err != nil || href == "" || !safeDAVURL(ref) {
		return nil
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != dav.base.Scheme || !strings.EqualFold(resolved.Host, dav.base.Host) {
		return nil
	}
	return resolved
}

type davHref struct {
	Href string `xml:"DAV: href"`
}

type davProperties struct {
	ResourceType struct {
		Collection *struct{} `xml:"DAV: collection"`
		Calendar   *struct{} `xml:"urn:ietf:params:xml:ns:caldav calendar"`
	} `xml:"DAV: resourcetype"`
	Principal   davHref `xml:"DAV: current-user-principal"`
	Home        davHref `xml:"urn:ietf:params:xml:ns:caldav calendar-home-set"`
	Name        string  `xml:"DAV: displayname"`
	Description string  `xml:"urn:ietf:params:xml:ns:caldav calendar-description"`
}

type davResponse struct {
	Href     string `xml:"DAV: href"`
	Propstat []struct {
		Status string        `xml:"DAV: status"`
		Props  davProperties `xml:"DAV: prop"`
	} `xml:"DAV: propstat"`
}

func (dav *calDAV) propfind(ctx context.Context, target *url.URL, depth, props string) ([]davResponse, string) {
	body := `<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop>` + props + `</D:prop></D:propfind>`
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", target.String(), strings.NewReader(body))
	if err != nil {
		return nil, "serverUnavailable"
	}
	req.Header.Set("Depth", depth)
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.SetBasicAuth(dav.username, dav.password)
	resp, err := dav.client.Do(req)
	if err != nil {
		return nil, "serverUnavailable"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus {
		return nil, "serverUnavailable"
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDAVResponse+1))
	if err != nil || len(data) > maxDAVResponse {
		return nil, "serverUnavailable"
	}
	var result struct {
		XMLName   xml.Name      `xml:"DAV: multistatus"`
		Responses []davResponse `xml:"DAV: response"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&result) != nil {
		return nil, "serverUnavailable"
	}
	return result.Responses, ""
}

func sameDAVCollection(left, right *url.URL) bool {
	return strings.TrimSuffix(left.Path, "/") == strings.TrimSuffix(right.Path, "/")
}

func goodDAVStatus(status string) bool {
	parts := strings.Fields(status)
	return len(parts) >= 2 && parts[1] == "200"
}

func (dav *calDAV) discover(ctx context.Context, target *url.URL, property string, href func(davProperties) string) (*url.URL, string) {
	responses, failure := dav.propfind(ctx, target, "0", property)
	if failure != "" {
		return nil, failure
	}
	for _, response := range responses {
		actual := dav.resolve(target, response.Href)
		if actual == nil || !sameDAVCollection(actual, target) {
			continue
		}
		for _, entry := range response.Propstat {
			if goodDAVStatus(entry.Status) {
				if result := dav.resolve(target, href(entry.Props)); result != nil {
					return result, ""
				}
			}
		}
	}
	return nil, "serverUnavailable"
}

func (dav *calDAV) calendars(ctx context.Context, accountID string) (map[string]object, string) {
	principal, failure := dav.discover(ctx, dav.base, "<D:current-user-principal/>", func(p davProperties) string {
		return p.Principal.Href
	})
	if failure != "" {
		return nil, failure
	}
	home, failure := dav.discover(ctx, principal, "<C:calendar-home-set/>", func(p davProperties) string {
		return p.Home.Href
	})
	if failure != "" {
		return nil, failure
	}
	// Define the href resolution base as a directory even if the server omitted its trailing slash.
	home.Path = strings.TrimSuffix(home.Path, "/") + "/"
	home.RawPath = ""
	responses, failure := dav.propfind(ctx, home, "1", "<D:resourcetype/><D:displayname/><C:calendar-description/>")
	if failure != "" {
		return nil, failure
	}
	records := make(map[string]object)
	validHome := false
	for _, response := range responses {
		collection := dav.resolve(home, response.Href)
		if collection == nil {
			continue
		}
		var isCalendar, isCollection bool
		var name, description string
		for _, entry := range response.Propstat {
			if !goodDAVStatus(entry.Status) {
				continue
			}
			props := entry.Props
			isCollection = isCollection || props.ResourceType.Collection != nil
			isCalendar = isCalendar || props.ResourceType.Calendar != nil
			if props.Name != "" {
				name = props.Name
			}
			if props.Description != "" {
				description = props.Description
			}
		}
		if sameDAVCollection(collection, home) {
			validHome = validHome || isCollection
			continue
		}
		canonical := strings.TrimSuffix(collection.Path, "/")
		child, ok := strings.CutPrefix(canonical, home.Path)
		if !ok || child == "" || strings.Contains(child, "/") {
			continue
		}
		if !isCalendar {
			continue
		}
		if name == "" {
			name = child
		}
		for len(name) > 255 {
			_, size := utf8.DecodeLastRuneInString(name)
			name = name[:len(name)-size]
		}
		id := "cal_" + digest([3]string{accountID, strings.ToLower(dav.base.Host), canonical})
		records[id] = object{
			"id": id, "name": name, "description": nullable(description), "color": nil,
			"sortOrder": 0, "isVisible": true,
		}
	}
	if !validHome {
		return nil, "serverUnavailable"
	}
	return records, ""
}

func (op *operation) loadCalendars() string {
	if op.calendars == nil && op.calendarFailure == "" {
		op.calendars, op.calendarFailure = op.g.caldav.calendars(op.ctx, op.g.config.AccountID)
	}
	return op.calendarFailure
}
