package gateway

import "bytes"

type smtpTransport struct {
	eightBit bool
	utf8     bool
}

func containsEightBit(raw []byte) bool {
	for _, b := range raw {
		if b >= 128 {
			return true
		}
	}
	return false
}

// MIME parts are opaque to JMAP's bodyStructure, but SMTP transport must
// account for the headers inside attached messages, including encoded ones.
func inspectSMTPMessage(raw []byte, depth int, budget *int) (*mimeMessage, smtpTransport, bool) {
	*budget -= len(raw)
	if depth > maxMIMEDepth || *budget < 0 {
		return nil, smtpTransport{}, false
	}
	message, failure := parseMIME(raw, "e-transport")
	if failure != "" || message.invalidHeaderUTF8 {
		return nil, smtpTransport{}, false
	}
	transport := smtpTransport{eightBit: containsEightBit(raw), utf8: message.headerUTF8}
	for _, part := range message.attachments {
		kind := part.Data["type"]
		if kind != "message/rfc822" && kind != "message/global" {
			continue
		}
		if part.Problem {
			return nil, smtpTransport{}, false
		}
		_, nested, ok := inspectSMTPMessage(part.Octets, depth+1, budget)
		if !ok {
			return nil, smtpTransport{}, false
		}
		transport.utf8 = transport.utf8 || nested.utf8
	}
	return message, transport, true
}

// SMTP DATA preserves canonical lines. A bare CR, NUL, overlong line or
// missing terminal CRLF could change the bytes of an encapsulated message.
func embeddedMessageTransport(raw []byte) (smtpTransport, bool) {
	if !bytes.HasSuffix(raw, []byte("\r\n")) {
		return smtpTransport{}, false
	}
	for line := range bytes.SplitSeq(raw, []byte("\r\n")) {
		if len(line) > 998 || bytes.ContainsAny(line, "\x00\r\n") {
			return smtpTransport{}, false
		}
	}
	head, _, separated := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !separated || len(head)+4 > maxMIMEHeader {
		return smtpTransport{}, false
	}
	budget := 4 * maxRaw
	message, transport, ok := inspectSMTPMessage(raw, 0, &budget)
	if !ok {
		return smtpTransport{}, false
	}
	header := message.rawHeader.Header
	return transport, header.Has("From") || header.Has("Subject") || header.Has("Date")
}
