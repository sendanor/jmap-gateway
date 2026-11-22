#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -gt 0 && ( $# -ne 1 || $1 != --report ) ]]; then
  echo "Usage: $0 [--report]" >&2
  exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/data"
profile=${COVERPROFILE:-.local/coverage.out}

# Run each package's test binary with the same instrumentation as the gateway.
go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... > "$work/test-packages"
while IFS= read -r package; do
  if [[ -n "$package" ]]; then
    go test -c -covermode=atomic -coverpkg=./... -o "$work/package.test" "$package"
    package_dir=$(go list -f '{{.Dir}}' "$package")
    (cd "$package_dir" && "$work/package.test" -test.gocoverdir="$work/data")
  fi
done < "$work/test-packages"

go build -buildvcs=false -cover -covermode=atomic -coverpkg=./... -o "$work/jmap-gateway" ./cmd/jmap-gateway
GOCOVERDIR="$work/data" "$work/jmap-gateway" -h >/dev/null 2>&1

inputs="$work/data"
if [[ -n "${JMAP_COVERAGE_DATA:-}" ]]; then
  inputs+=",$JMAP_COVERAGE_DATA"
fi
mkdir -p "$(dirname "$profile")"
go tool covdata textfmt -i="$inputs" -o="$profile"
go tool covdata pkglist -i="$inputs" | sort -u > "$work/covered"
go list ./... | sort -u > "$work/expected"
if ! diff -u "$work/expected" "$work/covered"; then
  echo "Coverage data does not match the module's Go packages." >&2
  exit 1
fi

# Check counts directly. A rounded 100.0% may still hide uncovered statements.
awk -v report="${1:-}" '
  NR == 1 { next }
  { total += $2 }
  $3 > 0 { covered += $2 }
  $3 == 0 && $2 > 0 { print "Uncovered:", $1, "(" $2 " statements)" }
  END {
    printf "Covered %d of %d Go statements (%.1f%%)\n", covered, total, total ? covered*100/total : 0;
    if (!total || (report != "--report" && covered != total)) exit 1;
  }
' "$profile"
