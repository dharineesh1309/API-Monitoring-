#!/usr/bin/env bash
set -Eeuo pipefail

# OWASP ASTF Security Scan Trigger Script
# Downloads the scanner if missing, and runs it against the target.

TARGET_URL=${1:-"http://127.0.0.1:8000"}
TOKEN=${2:-""}

ASTF_JAR="/app/astf-v2.0.1.jar"
REPORT_DIR="/app/reports"
# Optional report path override (the router passes ASTF_REPORT_PATH so the
# report the API validates is always the one ASTF actually wrote).
REPORT_PATH="${3:-$REPORT_DIR/security-report.html}"
mkdir -p "$REPORT_DIR"

if [ ! -f "$ASTF_JAR" ]; then
    echo "Downloading OWASP ASTF..."
    tmp_jar="${ASTF_JAR}.tmp"
    curl --fail --show-error --silent --location --retry 3 \
        "https://github.com/OWASP/www-project-api-security-testing-framework/releases/download/v2.0.1/astf-v2.0.1.jar" \
        --output "$tmp_jar"
    test -s "$tmp_jar"
    mv "$tmp_jar" "$ASTF_JAR"
fi
test -s "$ASTF_JAR"

rm -f "$REPORT_PATH"
echo "Running ASTF security scan against $TARGET_URL..."

if [ -n "$TOKEN" ]; then
    set +e
    java -jar "$ASTF_JAR" -u "$TARGET_URL" --token "$TOKEN" -f HTML -o "$REPORT_PATH"
    astf_exit=$?
    set -e
else
    set +e
    java -jar "$ASTF_JAR" -u "$TARGET_URL" -f HTML -o "$REPORT_PATH"
    astf_exit=$?
    set -e
fi

if [ "$astf_exit" -gt 1 ]; then
    echo "ASTF scan failed with exit code $astf_exit" >&2
    exit "$astf_exit"
fi
test -s "$REPORT_PATH"
report_bytes=$(wc -c < "$REPORT_PATH")
if [ "$astf_exit" -eq 1 ]; then
    echo "ASTF scan complete with findings. Report generated at $REPORT_PATH (${report_bytes} bytes)"
else
    echo "ASTF scan complete with no findings. Report generated at $REPORT_PATH (${report_bytes} bytes)"
fi
exit "$astf_exit"
