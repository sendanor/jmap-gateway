package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
)

type sendOutcome struct {
	failure         string
	description     string
	uncertain       bool
	rejected        []string
	maxSize         int64
	acceptedReplies map[string]string
}

func smtpFailure(err error, rejected string) string {
	var reply *textproto.Error
	if errors.As(err, &reply) && reply.Code >= 500 && reply.Code <= 599 {
		return rejected
	}
	return "serverUnavailable"
}

func sendSMTP(ctx context.Context, config Upstream, tlsConfig *tls.Config, from string, to []string, raw []byte, transport smtpTransport, dsn *dsnOptions) sendOutcome {
	conn, closeConn, err := dial(ctx, config.Address)
	if err != nil {
		return sendOutcome{failure: "serverUnavailable"}
	}
	defer closeConn()
	if config.Mode == "tls" {
		secured := tls.Client(conn, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			return sendOutcome{failure: "serverUnavailable"}
		}
		conn = secured
	}
	client, err := smtp.NewClient(conn, tlsConfig.ServerName)
	if err != nil {
		return sendOutcome{failure: "serverUnavailable"}
	}
	if config.Mode == "starttls" {
		if err := client.StartTLS(tlsConfig); err != nil {
			return sendOutcome{failure: "serverUnavailable"}
		}
	}
	if err := client.Auth(smtp.PlainAuth("", config.Username, config.Password, tlsConfig.ServerName)); err != nil {
		return sendOutcome{failure: smtpFailure(err, "forbiddenToSend")}
	}
	if supported, parameter := client.Extension("SIZE"); supported {
		if size, err := strconv.ParseInt(parameter, 10, 64); err == nil && size > 0 && int64(len(raw)) > size {
			return sendOutcome{failure: "tooLarge", maxSize: size}
		}
	}
	var parameters string
	if transport.utf8 {
		if supported, _ := client.Extension("SMTPUTF8"); !supported {
			return sendOutcome{failure: "forbiddenToSend", description: "SMTP relay does not support SMTPUTF8"}
		}
		parameters += " SMTPUTF8"
	}
	if transport.eightBit || transport.utf8 {
		if supported, _ := client.Extension("8BITMIME"); !supported {
			return sendOutcome{failure: "forbiddenToSend", description: "SMTP relay does not support 8BITMIME"}
		}
	}
	if transport.eightBit {
		parameters += " BODY=8BITMIME"
	}
	if dsn != nil {
		if supported, _ := client.Extension("DSN"); !supported {
			return sendOutcome{failure: "forbiddenToSend", description: "SMTP relay does not support DSN"}
		}
		parameters += smtpDSNParameters(dsn.sender())
	}
	if err := smtpMail(client, from, parameters); err != nil {
		return sendOutcome{failure: smtpFailure(err, "forbiddenMailFrom")}
	}
	var rejected []string
	replies := make(map[string]string, len(to))
	for index, recipient := range to {
		code, message, err := smtpCommand(client, 25, "RCPT TO:<%s>%s", recipient, smtpDSNParameters(dsn.recipient(index)))
		if err != nil {
			if failure := smtpFailure(err, "invalidRecipients"); failure != "invalidRecipients" {
				return sendOutcome{failure: failure}
			}
			rejected = append(rejected, recipient)
			continue
		}
		replies[recipient] = formatSMTPReply(code, message)
	}
	if len(rejected) != 0 {
		// Closing before DATA keeps every recipient eligible for a safe retry.
		return sendOutcome{failure: "invalidRecipients", rejected: rejected}
	}
	writer, err := client.Data()
	if err != nil {
		return sendOutcome{failure: smtpFailure(err, "forbiddenToSend")}
	}
	if _, err := writer.Write(raw); err != nil {
		return sendOutcome{failure: "serverUnavailable"}
	}
	if err := writer.Close(); err != nil {
		var reply *textproto.Error
		if errors.As(err, &reply) && reply.Code >= 400 && reply.Code <= 599 {
			return sendOutcome{failure: smtpFailure(err, "forbiddenToSend")}
		}
		return sendOutcome{failure: "serverFail", uncertain: true}
	}
	return sendOutcome{acceptedReplies: replies}
}

func formatSMTPReply(code int, message string) string {
	lines := strings.Split(strings.ToValidUTF8(message, "\uFFFD"), "\n")
	first := strings.Fields(lines[0])
	fields := append([]string{strconv.Itoa(code)}, first...)
	for _, line := range lines[1:] {
		next := strings.Fields(line)
		common := 0
		for common < min(len(first), len(next)) && first[common] == next[common] {
			common++
		}
		fields = append(fields, next[common:]...)
	}
	return strings.Join(fields, " ")
}

func smtpMail(client *smtp.Client, from, parameters string) error {
	if strings.ContainsAny(from, "\r\n") {
		return errors.New("invalid SMTP sender")
	}
	_, _, err := smtpCommand(client, 250, "MAIL FROM:<%s>%s", from, parameters)
	return err
}

func smtpCommand(client *smtp.Client, expected int, format string, args ...any) (int, string, error) {
	id, err := client.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	client.Text.StartResponse(id)
	defer client.Text.EndResponse(id)
	return client.Text.ReadResponse(expected)
}
