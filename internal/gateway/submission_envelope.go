package gateway

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/mail"
	"regexp"
	"slices"
	"strings"

	"github.com/emersion/go-message/textproto"
)

const maxSubmissionRecipients = 32

var gatewayMessageID = regexp.MustCompile(`^<([0-9a-f]{32})@jmap.invalid>$`)

type envelopeAddress struct {
	Email      string             `json:"email"`
	Parameters map[string]*string `json:"parameters"`
}

type smtpEnvelope struct {
	From envelopeAddress   `json:"mailFrom"`
	To   []envelopeAddress `json:"rcptTo"`
}

func (envelope *smtpEnvelope) recipients(identity string) ([]string, object) {
	if !validAddress(envelope.From.Email) {
		return nil, invalidEnvelope()
	}
	if envelope.From.Email != identity {
		return nil, object{"type": "forbiddenMailFrom"}
	}
	if len(envelope.From.Parameters) != 0 {
		return nil, invalidEnvelope()
	}
	recipients := make([]string, 0, len(envelope.To))
	for _, recipient := range envelope.To {
		if len(recipient.Parameters) != 0 {
			return nil, invalidEnvelope()
		}
		recipients = append(recipients, recipient.Email)
	}
	return recipients, validateRecipients(recipients)
}

func invalidEnvelope() object {
	return object{"type": "invalidProperties", "properties": []string{"envelope"}}
}

func validateRecipients(recipients []string) object {
	if len(recipients) == 0 {
		return object{"type": "noRecipients"}
	}
	if len(recipients) > maxSubmissionRecipients {
		return object{"type": "tooManyRecipients", "maxRecipients": maxSubmissionRecipients}
	}
	var invalid []string
	for _, email := range recipients {
		if !validAddress(email) {
			invalid = append(invalid, email)
		}
	}
	if len(invalid) != 0 {
		return object{"type": "invalidRecipients", "invalidRecipients": invalid}
	}
	return nil
}

type preparedSubmission struct {
	key        string
	legacyKey  string
	recipients []string
	wire       []byte
	transport  smtpTransport
}

func prepareSubmission(raw []byte, identity string, explicit []string) (preparedSubmission, object) {
	invalid := object{"type": "invalidEmail"}
	reader := bufio.NewReader(bytes.NewReader(raw))
	rawHeader, err := textproto.ReadHeader(reader)
	if err != nil || bytes.IndexByte(raw, 0) >= 0 {
		return preparedSubmission{}, invalid
	}
	header := make(mail.Header)
	for fields := rawHeader.Fields(); fields.Next(); {
		key := fields.Key()
		header[key] = append(header[key], fields.Value())
	}
	if len(header["Resent-From"])+len(header["Resent-Sender"])+len(header["Resent-To"])+len(header["Resent-Cc"])+len(header["Resent-Bcc"]) != 0 {
		return preparedSubmission{}, invalid
	}
	from := addresses(header, "From")
	if len(from) != 1 {
		return preparedSubmission{}, object{"type": "invalidEmail", "properties": []string{"from"}}
	}
	if from[0].Email != identity {
		return preparedSubmission{}, object{"type": "forbiddenFrom"}
	}
	if sender := header["Sender"]; len(sender) > 0 && (len(sender) != 1 || len(addresses(header, "Sender")) != 1) {
		return preparedSubmission{}, invalid
	}
	contentType := "text/plain"
	if value := header.Get("Content-Type"); value != "" {
		contentType, _, err = mime.ParseMediaType(value)
	}
	if err != nil || len(header["Message-Id"]) > 1 || len(header["From"]) != 1 || len(header["Content-Type"]) > 1 {
		return preparedSubmission{}, invalid
	}
	if contentType != "text/plain" {
		if header.Get("MIME-Version") != "1.0" || len(header["Mime-Version"]) != 1 {
			return preparedSubmission{}, invalid
		}
	}
	recipients, failure := headerRecipients(header)
	if failure != nil {
		return preparedSubmission{}, failure
	}
	if explicit != nil {
		recipients = explicit
	}
	if failure := validateRecipients(recipients); failure != nil {
		return preparedSubmission{}, failure
	}
	digest := sha256.Sum256(raw)
	prepared := preparedSubmission{key: "c-" + hex.EncodeToString(digest[:]), recipients: recipients, wire: raw}
	// Read reservations written before the ledger used complete message bytes.
	if match := gatewayMessageID.FindStringSubmatch(header.Get("Message-Id")); match != nil {
		prepared.legacyKey = match[1]
	}
	if len(header["Bcc"]) != 0 {
		prepared.wire = withoutBcc(rawHeader, reader)
	}
	budget := 4 * maxRaw
	_, transport, valid := inspectSMTPMessage(prepared.wire, 0, &budget)
	if !valid {
		return preparedSubmission{}, invalid
	}
	transport.utf8 = transport.utf8 || containsEightBit([]byte(identity))
	for _, recipient := range recipients {
		transport.utf8 = transport.utf8 || containsEightBit([]byte(recipient))
	}
	prepared.transport = transport
	return prepared, nil
}

func headerRecipients(header mail.Header) ([]string, object) {
	var recipients []string
	seen := make(map[string]bool)
	for _, field := range []string{"To", "Cc", "Bcc"} {
		for _, value := range header[field] {
			if field == "Bcc" && strings.TrimSpace(value) == "" {
				continue
			}
			addresses, err := mail.ParseAddressList(value)
			if err != nil {
				return nil, object{"type": "invalidEmail", "properties": []string{strings.ToLower(field)}}
			}
			for _, recipient := range addresses {
				key, valid := smtpAddressKey(recipient.Address)
				if !valid {
					// Keep invalid addresses for validateRecipients to report.
					key = recipient.Address
				}
				if !seen[key] {
					seen[key] = true
					recipients = append(recipients, recipient.Address)
				}
			}
		}
	}
	return recipients, nil
}

func withoutBcc(header textproto.Header, reader *bufio.Reader) []byte {
	header.Del("Bcc")
	var wire bytes.Buffer
	// ReadHeader retains original header lines. The output buffer cannot fail.
	_ = textproto.WriteHeader(&wire, header)
	_, _ = wire.ReadFrom(reader)
	return wire.Bytes()
}

func replaySubmission(entry submissionRecord, identity string, explicit []string) (string, object) {
	if entry.Status == "destroyed" {
		return "", object{"type": "forbiddenToSend", "description": "This message was already accepted by SMTP"}
	}
	if entry.Status != "accepted" {
		return "", object{"type": "serverFail", "description": "SMTP acceptance is unknown. This message is blocked from resubmission"}
	}
	if entry.IdentityID != identity {
		return "", invalidProperty("identityId")
	}
	if explicit != nil && !slices.Equal(explicit, entry.recipients()) {
		return "", invalidEnvelope()
	}
	return entry.ID, nil
}
