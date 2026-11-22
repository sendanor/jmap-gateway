package gateway

import (
	"bufio"
	"bytes"
	"mime"
	"regexp"
	"slices"
	"strings"

	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/textproto"
)

const maxThreadHeaders = 8 << 10

var threadHeaders = []string{"Message-Id", "In-Reply-To", "References", "Subject"}

var messageIDToken = regexp.MustCompile(`<([^<>\s]+@[^<>\s]+)>`)
var subjectPrefix = regexp.MustCompile(`(?i)^(?:(?:re|fw|fwd)(?:\[\d+\])?\s*:|\[[^\[\]]+\])\s*`)

// A fixed reference root makes membership independent of scan order and of
// whether the original message is currently present. We do not merge groups
// retroactively, since an Email's threadId is immutable.
func threadForMessage(account string, raw []byte) string {
	headers, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return ""
	}
	size := 2 // The terminating blank line in the IMAP header section.
	fields := headers.Fields()
	for fields.Next() {
		if slices.Contains(threadHeaders, fields.Key()) {
			line, _ := fields.Raw()
			size += len(line)
		}
	}
	if size >= maxThreadHeaders {
		return ""
	}
	for _, key := range []string{"References", "In-Reply-To", "Message-ID"} {
		root := messageIDToken.FindStringSubmatch(headers.Get(key))
		if root == nil {
			continue
		}
		subject := headers.Get("Subject")
		if decoded, err := (&mime.WordDecoder{CharsetReader: charset.Reader}).DecodeHeader(subject); err == nil {
			subject = decoded
		}
		subject = strings.TrimSpace(subject)
		for width := subjectPrefix.FindStringIndex(subject); width != nil; width = subjectPrefix.FindStringIndex(subject) {
			subject = subject[width[1]:]
		}
		subject = strings.ToLower(strings.Join(strings.Fields(subject), " "))
		return "t-" + digest([]string{account, root[1], subject})
	}
	return ""
}

func threadID(emailID, assigned string) string {
	if assigned != "" {
		return assigned
	}
	return "t-" + strings.TrimPrefix(emailID, "e-")
}

func (s *snapshot) threads() map[string][]string {
	members := make(map[string][]*emailMeta)
	for _, email := range s.emails {
		id := threadID(email.ID, email.ThreadID)
		members[id] = append(members[id], email)
	}
	threads := make(map[string][]string, len(members))
	for id, emails := range members {
		slices.SortFunc(emails, func(a, b *emailMeta) int {
			if cmp := a.Received.Compare(b.Received); cmp != 0 {
				return cmp
			}
			return strings.Compare(a.ID, b.ID)
		})
		ids := make([]string, 0, len(emails))
		for _, email := range emails {
			ids = append(ids, email.ID)
		}
		threads[id] = ids
	}
	return threads
}

func (s *snapshot) countMailboxes() {
	type counts struct {
		box     *box
		threads map[string]bool
	}
	byID := make(map[string]counts, len(s.boxes))
	unread := [2]map[string]bool{make(map[string]bool), make(map[string]bool)}
	for _, b := range s.boxes {
		b.Total, b.Unread = 0, 0
		byID[b.ID] = counts{b, make(map[string]bool)}
	}
	for _, email := range s.emails {
		c, ok := byID[email.MailboxID]
		if !ok {
			continue
		}
		id := threadID(email.ID, email.ThreadID)
		c.box.Total++
		c.threads[id] = true
		if unreadEmail(email.Keywords) {
			c.box.Unread++
			unread[trashGroup(c.box)][id] = true
		}
	}
	for _, c := range byID {
		c.box.TotalThreads, c.box.UnreadThreads = len(c.threads), 0
		for id := range c.threads {
			if unread[trashGroup(c.box)][id] {
				c.box.UnreadThreads++
			}
		}
	}
}

func trashGroup(b *box) int {
	if b.Role == "trash" {
		return 1
	}
	return 0
}
