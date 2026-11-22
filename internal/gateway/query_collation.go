package gateway

import (
	"cmp"
	"strings"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

const asciiCasemap = "i;ascii-casemap"
const octetCollation = "i;octet"

var queryCollationAlgorithms = []string{asciiCasemap, octetCollation}

func supportedQueryCollation(algorithm string) bool {
	return algorithm == "" || algorithm == asciiCasemap || algorithm == octetCollation
}

func queryStringComparator(algorithm string) func(string, string) int {
	switch algorithm {
	case "":
		// The collator belongs to this query. Its scratch buffers are mutable.
		return collate.New(language.Und, collate.IgnoreCase).CompareString
	case asciiCasemap:
		return compareASCII
	default:
		return strings.Compare
	}
}

func compareASCII(a, b string) int {
	for i := range min(len(a), len(b)) {
		if result := cmp.Compare(asciiUpper(a[i]), asciiUpper(b[i])); result != 0 {
			return result
		}
	}
	return cmp.Compare(len(a), len(b))
}

func asciiUpper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 'a' + 'A'
	}
	return b
}
