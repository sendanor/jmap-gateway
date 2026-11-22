package gateway

import (
	"maps"
	"slices"
	"strings"
)

type dsnOptions struct {
	Sender     map[string]string
	Recipients []map[string]string
}

func (d *dsnOptions) sender() map[string]string {
	if d == nil {
		return nil
	}
	return d.Sender
}

func (d *dsnOptions) recipient(index int) map[string]string {
	if d == nil {
		return nil
	}
	return d.Recipients[index]
}

func equalDSN(a, b *dsnOptions) bool {
	if a == nil || b == nil {
		return a == b
	}
	return maps.Equal(a.Sender, b.Sender) && slices.EqualFunc(a.Recipients, b.Recipients, maps.Equal[map[string]string, map[string]string])
}

// DSN values in JMAP are decoded strings, not pre-encoded SMTP arguments.
func dsnParameters(input map[string]*string, recipient string) (map[string]string, bool) {
	if len(input) == 0 {
		return nil, true
	}
	params := make(map[string]string, len(input))
	for supplied, text := range input {
		name := strings.ToUpper(supplied)
		if text == nil || containsEightBit([]byte(supplied)) || containsEightBit([]byte(*text)) || params[name] != "" {
			return nil, false
		}
		value := *text
		switch name {
		case "RET":
			value = strings.ToUpper(value)
			if recipient != "" || value != "FULL" && value != "HDRS" {
				return nil, false
			}
		case "ENVID":
			if recipient != "" || value == "" || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r > 126 }) >= 0 ||
				len(encodeXtext(value)) > 100 {
				return nil, false
			}
		case "NOTIFY":
			value = normalizeNotify(value)
			if recipient == "" || value == "" {
				return nil, false
			}
		case "ORCPT":
			kind, address, ok := strings.Cut(value, ";")
			if recipient == "" || !ok || !strings.EqualFold(kind, "rfc822") || address != recipient {
				return nil, false
			}
			value = "rfc822;" + address
		default:
			return nil, false
		}
		params[name] = value
	}
	return params, true
}

func normalizeNotify(value string) string {
	value = strings.ToUpper(value)
	if value == "NEVER" {
		return value
	}
	allowed := []string{"SUCCESS", "FAILURE", "DELAY"}
	set := make(map[string]bool, len(allowed))
	for _, flag := range strings.Split(value, ",") {
		if !contains(allowed, flag) || set[flag] {
			return ""
		}
		set[flag] = true
	}
	canonical := make([]string, 0, len(set))
	for _, flag := range allowed {
		if set[flag] {
			canonical = append(canonical, flag)
		}
	}
	return strings.Join(canonical, ",")
}

func encodeXtext(value string) string {
	const hex = "0123456789ABCDEF"
	var encoded strings.Builder
	for i := range len(value) {
		b := value[i]
		if b < 33 || b > 126 || b == '+' || b == '=' {
			encoded.WriteByte('+')
			encoded.WriteByte(hex[b>>4])
			encoded.WriteByte(hex[b&15])
		} else {
			encoded.WriteByte(b)
		}
	}
	return encoded.String()
}

func smtpDSNParameters(params map[string]string) string {
	var out strings.Builder
	for _, key := range sortedKeys(params) {
		value := params[key]
		if key == "ENVID" || key == "ORCPT" {
			value = encodeXtext(value)
		}
		out.WriteString(" " + key + "=" + value)
	}
	return out.String()
}
