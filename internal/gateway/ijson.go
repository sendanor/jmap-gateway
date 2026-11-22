package gateway

import (
	"encoding/json"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// encoding/json alone permits duplicate keys and replaces lone surrogates.
func validIJSON(data []byte) bool {
	if !utf8.Valid(data) || !json.Valid(data) {
		return false
	}
	type container struct {
		names   map[string]struct{}
		wantKey bool
	}
	var stack []container
	for i := 0; i < len(data); {
		switch data[i] {
		case '{':
			stack = append(stack, container{names: make(map[string]struct{}), wantKey: true})
		case '[':
			stack = append(stack, container{})
		case '}', ']':
			stack = stack[:len(stack)-1]
		case ',':
			current := &stack[len(stack)-1]
			current.wantKey = current.names != nil
		case '"':
			end, ok := iJSONStringEnd(data, i+1)
			if !ok {
				return false
			}
			if len(stack) != 0 {
				current := &stack[len(stack)-1]
				if current.wantKey {
					var key string
					_ = json.Unmarshal(data[i:end], &key)
					if _, exists := current.names[key]; exists {
						return false
					}
					current.names[key] = struct{}{}
					current.wantKey = false
				}
			}
			i = end
			continue
		}
		i++
	}
	return true
}

// The input has already passed JSON syntax and UTF-8 validation.
func iJSONStringEnd(data []byte, i int) (int, bool) {
	for data[i] != '"' {
		var r rune
		if data[i] == '\\' {
			if data[i+1] != 'u' {
				i += 2
				continue
			}
			r = escapedCodeUnit(data[i+2 : i+6])
			i += 6
			if utf16.IsSurrogate(r) {
				if r >= 0xdc00 || data[i] != '\\' || data[i+1] != 'u' {
					return 0, false
				}
				trailing := escapedCodeUnit(data[i+2 : i+6])
				if trailing < 0xdc00 || trailing > 0xdfff {
					return 0, false
				}
				r = utf16.DecodeRune(r, trailing)
				i += 6
			}
		} else {
			var size int
			r, size = utf8.DecodeRune(data[i:])
			i += size
		}
		if r >= 0xfdd0 && r <= 0xfdef || r&0xffff >= 0xfffe {
			return 0, false
		}
	}
	return i + 1, true
}

func escapedCodeUnit(hex []byte) rune {
	value, _ := strconv.ParseUint(string(hex), 16, 16)
	return rune(value)
}
