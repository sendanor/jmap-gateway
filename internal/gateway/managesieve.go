package gateway

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	vacationScriptName = "jmap-vacation"
	maxVacationScript  = 128 << 10
)

type sieveClient struct {
	reader *bufio.Reader
	writer io.Writer
}

func (op *operation) vacationClient() (*sieveClient, func(), string) {
	config := op.g.config.ManageSieve
	conn, closeConn, err := dial(op.ctx, config.Address)
	if err != nil {
		return nil, nil, "serverUnavailable"
	}
	ok := false
	defer func() {
		if !ok {
			closeConn()
		}
	}()
	client := &sieveClient{reader: bufio.NewReaderSize(conn, 8192), writer: conn}
	if failure := client.greeting(); failure != "" {
		return nil, nil, failure
	}
	if failure := client.command("STARTTLS\r\n"); failure != "" {
		return nil, nil, failure
	}
	secure := tls.Client(conn, op.g.sieveTLS)
	if err := secure.HandshakeContext(op.ctx); err != nil {
		return nil, nil, "serverUnavailable"
	}
	client = &sieveClient{reader: bufio.NewReaderSize(secure, 8192), writer: secure}
	if failure := client.greeting(); failure != "" {
		return nil, nil, failure
	}
	auth := base64.StdEncoding.EncodeToString([]byte("\x00" + config.Username + "\x00" + config.Password))
	if failure := client.command("AUTHENTICATE \"PLAIN\" \"" + auth + "\"\r\n"); failure != "" {
		return nil, nil, failure
	}
	ok = true
	return client, closeConn, ""
}

func (c *sieveClient) line() (string, string) {
	line, err := c.reader.ReadSlice('\n')
	if err != nil || len(line) < 2 || line[len(line)-2] != '\r' {
		return "", "serverUnavailable"
	}
	return string(line[:len(line)-2]), ""
}

func (c *sieveClient) greeting() string {
	for range 32 {
		line, failure := c.line()
		if failure != "" {
			return failure
		}
		if !strings.HasPrefix(line, "\"") {
			return sieveStatus(line)
		}
	}
	return "serverFail"
}

func sieveStatus(line string) string {
	word, _, _ := strings.Cut(line, " ")
	switch strings.ToUpper(word) {
	case "OK":
		return ""
	case "BYE":
		return "serverUnavailable"
	default:
		return "serverFail"
	}
}

func (c *sieveClient) command(command string) string {
	if _, err := io.WriteString(c.writer, command); err != nil {
		return "serverUnavailable"
	}
	line, failure := c.line()
	if failure != "" {
		return failure
	}
	return sieveStatus(line)
}

func (c *sieveClient) getVacation() (vacationResponse, string) {
	var settings vacationResponse
	if _, err := io.WriteString(c.writer, "GETSCRIPT \""+vacationScriptName+"\"\r\n"); err != nil {
		return settings, "serverUnavailable"
	}
	line, failure := c.line()
	if failure != "" {
		return settings, failure
	}
	switch status := strings.ToUpper(line); {
	case status == "NO (NONEXISTENT)" || strings.HasPrefix(status, "NO (NONEXISTENT) "):
		return settings, ""
	case !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}"):
		return settings, "serverFail"
	}
	size, err := strconv.ParseUint(line[1:len(line)-1], 10, 32)
	if err != nil || size > maxVacationScript {
		return settings, "serverFail"
	}
	script := make([]byte, size+2)
	if _, err := io.ReadFull(c.reader, script); err != nil {
		return settings, "serverUnavailable"
	}
	line, failure = c.line()
	if failure != "" {
		return settings, failure
	}
	if string(script[size:]) != "\r\n" || sieveStatus(line) != "" || !decodeVacationScript(script[:size], &settings) {
		return vacationResponse{}, "serverFail"
	}
	return settings, ""
}

func (c *sieveClient) putVacation(script []byte) string {
	return c.command(fmt.Sprintf("PUTSCRIPT \"%s\" {%d+}\r\n%s\r\n", vacationScriptName, len(script), script))
}
