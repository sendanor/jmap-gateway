package gateway

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSMTPTransportFailures(t *testing.T) {
	cert, ca := testTLS(t)
	for _, test := range []struct{ name, fault string }{
		{"dial", ""},
		{"untrusted certificate", ""},
		{"disconnect before sending the body", "disconnect-during-data"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig(t).SMTP
			config.CAFile = ca
			var fixture *smtpFixture
			switch test.name {
			case "dial":
				listener := listenTCP(t)
				config.Address = listener.Addr().String()
				_ = listener.Close()
			case "untrusted certificate":
				config.CAFile = ""
				config.Address, _ = serveTestSMTP(t, config, cert, test.fault)
			default:
				config.Address, fixture = serveTestSMTP(t, config, cert, test.fault)
			}
			clientTLS, err := upstreamTLS(config)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte("Subject: interrupted\r\n\r\n" + strings.Repeat("x", 12*maxRaw))
			result := sendSMTP(context.Background(), config, clientTLS, "sender@example.test", []string{"recipient@example.test"}, raw, smtpTransport{}, nil)
			if result.failure != "serverUnavailable" || result.uncertain || len(result.rejected) != 0 {
				t.Fatalf("incorrect transport failure: %+v", result)
			}
			if fixture != nil {
				select {
				case err := <-fixture.done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("SMTP fixture did not finish")
				}
			}
		})
	}
}
