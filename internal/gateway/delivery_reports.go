package gateway

import (
	"bufio"
	"bytes"
	"cmp"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"regexp"
	"slices"
	"strings"
	"time"
)

const maxDeliveryReportsPerScan = 32

var dsnStatus = regexp.MustCompile(`^[245]\.[0-9]{1,3}\.[0-9]{1,3}$`)
var diagnosticReply = regexp.MustCompile(`^[245][0-9]{2}(?: |$)`)

type submissionReport struct {
	BlobID   string
	Received time.Time
	Outcomes map[string]reportOutcome
}

type reportOutcome struct {
	Delivered string
	Reply     string
}

func (entry submissionRecord) effectiveDSN() *dsnOptions {
	if entry.ReportKey == "" {
		return entry.DSN
	}
	// Report keys are generated only for explicit DSN submissions.
	options := *entry.DSN
	options.Sender = make(map[string]string, len(entry.DSN.Sender)+1)
	maps.Copy(options.Sender, entry.DSN.Sender)
	options.Sender["ENVID"] = entry.ReportKey
	return &options
}

func (op *operation) refreshDeliveryReports() {
	path, ledger := op.g.config.SMTPDeliveryReportMailbox, op.g.ledger
	if path == "" || op.deliveryReportsScanned || ledger.failed {
		return
	}
	op.deliveryReportsScanned = true
	keys := make(map[string]string)
	stored := make(map[string]bool)
	for key, entry := range ledger.records {
		if entry.Status == "accepted" && entry.ReportKey != "" {
			keys[entry.ReportKey] = key
			for _, report := range entry.DeliveryReports {
				stored[report.BlobID] = true
			}
		}
	}
	if len(keys) == 0 || op.loadMail() != "" {
		return
	}
	var folder *box
	for _, candidate := range op.snapshot.boxes {
		if candidate.Path == path {
			folder = candidate
			break
		}
	}
	if folder == nil || !folder.mayReadItems() || folder.Writable || folder.CanChangePath {
		return
	}
	checked := op.g.checkedDeliveryReports
	if checked == nil || len(checked) >= maxMessages {
		checked = make(map[string]bool)
		op.g.checkedDeliveryReports = checked
	}
	var candidates []*emailMeta
	for _, email := range op.snapshot.emails {
		if email.MailboxID == folder.ID && !checked[email.ID] && !stored["b-"+email.ID[2:]] && email.Size <= maxRaw {
			candidates = append(candidates, email)
		}
	}
	slices.SortFunc(candidates, func(a, b *emailMeta) int {
		if order := a.Received.Compare(b.Received); order != 0 {
			return order
		}
		return cmp.Compare(a.UID, b.UID)
	})
	var next map[string]submissionRecord
	for _, email := range candidates[:min(len(candidates), maxDeliveryReportsPerScan)] {
		data, failure := op.readRaw(email)
		if failure != "" {
			continue
		}
		checked[email.ID] = true
		envid, reported := parseDeliveryReport(data)
		key := keys[envid]
		if key == "" {
			continue
		}
		entry := ledger.records[key]
		if next != nil {
			entry = next[key]
		}
		outcomes := make(map[string]reportOutcome)
		for _, recipient := range entry.recipients() {
			address, _ := smtpAddressKey(recipient)
			if outcome, found := reported[address]; found {
				outcomes[recipient] = outcome
			}
		}
		if len(outcomes) == 0 {
			continue
		}
		if next == nil {
			next = maps.Clone(ledger.records)
		}
		entry.DeliveryReports = append(slices.Clone(entry.DeliveryReports), submissionReport{
			BlobID: "b-" + email.ID[2:], Received: email.Received, Outcomes: outcomes,
		})
		slices.SortStableFunc(entry.DeliveryReports, func(a, b submissionReport) int {
			return a.Received.Compare(b.Received)
		})
		next[key] = entry
	}
	if next != nil {
		previous := ledger.records
		ledger.records = next
		if visible, err := ledger.persist(); err != nil && !visible {
			ledger.records = previous
		}
	}
}

func parseDeliveryReport(raw []byte) (string, map[string]reportOutcome) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", nil
	}
	kind, args, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/report" || !strings.EqualFold(args["report-type"], "delivery-status") {
		return "", nil
	}
	parts := multipart.NewReader(message.Body, args["boundary"])
	for {
		part, err := parts.NextPart()
		if err != nil {
			return "", nil
		}
		kind, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if kind != "message/delivery-status" {
			continue
		}
		body, err := io.ReadAll(part)
		if err != nil {
			return "", nil
		}
		return parseDeliveryFields(bytes.TrimRight(body, "\r\n"))
	}
}

func parseDeliveryFields(body []byte) (string, map[string]reportOutcome) {
	input := textproto.NewReader(bufio.NewReader(io.MultiReader(bytes.NewReader(body), strings.NewReader("\r\n\r\n"))))
	first, err := input.ReadMIMEHeader()
	envid := first.Get("Original-Envelope-Id")
	if err != nil || envid == "" || first.Get("Reporting-MTA") == "" {
		return "", nil
	}
	outcomes := make(map[string]reportOutcome)
	for {
		fields, err := input.ReadMIMEHeader()
		if len(fields) == 0 && err == io.EOF {
			return envid, outcomes
		}
		if err != nil {
			return "", nil
		}
		address := fields.Get("Original-Recipient")
		if address == "" {
			address = fields.Get("Final-Recipient")
		}
		kind, address, ok := strings.Cut(address, ";")
		key, valid := smtpAddressKey(strings.TrimSpace(address))
		status := fields.Get("Status")
		if !ok || !valid || !strings.EqualFold(strings.TrimSpace(kind), "rfc822") || !dsnStatus.MatchString(status) {
			continue
		}
		var outcome reportOutcome
		switch strings.ToLower(fields.Get("Action")) {
		case "delivered":
			if status[0] == '2' {
				outcome.Delivered = "yes"
			}
		case "failed":
			if status[0] == '5' {
				outcome.Delivered = "no"
			}
		case "delayed", "relayed", "expanded":
			outcomes[key] = outcome
			continue
		}
		if outcome.Delivered == "" {
			continue
		}
		protocol, reply, _ := strings.Cut(fields.Get("Diagnostic-Code"), ";")
		reply = strings.TrimSpace(reply)
		if strings.EqualFold(strings.TrimSpace(protocol), "smtp") && diagnosticReply.MatchString(reply) && reply[0] == status[0] {
			outcome.Reply = strings.ToValidUTF8(reply, "\uFFFD")
		}
		outcomes[key] = outcome
	}
}
