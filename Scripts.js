.pragma library

// POSIX sh snippets, run as ["sh", "-c", script, "sh", arg1, arg2, ...].
//
// Untrusted values (paths, URLs, JSON) only ever arrive as positional
// parameters, never spliced into the script text. The VTAI token only exists
// inside `register`, where it stays in shell variables and is written with the
// printf builtin, so it never shows up in any process argv.
//
// tests/scripts.test.js runs every snippet against a fake curl.

// $1 config dir, $2 state dir, $3 credential file, $4 user-dirs.dirs
var startup = [
  "umask 077",
  "mkdir -p \"$1\" \"$2\" 2>/dev/null",
  "missing=",
  "for tool in curl sha256sum stat date; do",
  "  command -v \"$tool\" >/dev/null 2>&1 || missing=\"$missing $tool\"",
  "done",
  "printf 'missing=%s\\n' \"${missing# }\"",
  "if [ -s \"$3\" ]; then echo auth=present; else echo auth=missing; fi",
  "dl=",
  "if [ -r \"$4\" ]; then",
  "  dl=$(sed -n 's/^[[:space:]]*XDG_DOWNLOAD_DIR[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*$/\\1/p' \"$4\" | tail -n 1)",
  "fi",
  "printf 'downloads=%s\\n' \"$dl\""
].join("\n")

// $1 credential file. Exit 0 when it exists and is not empty.
var credentialCheck = "[ -s \"$1\" ]"

// $1 directory. Exit 0 when it exists and can be listed.
var dirCheck = "[ -d \"$1\" ] && [ -r \"$1\" ] && [ -x \"$1\" ]"

// $1 file to delete (the credential file on disconnect).
var removeFile = "rm -f -- \"$1\""

// Open a VirusTotal report in the browser.
// $1 URL (already restricted to https://*.virustotal.com/), $2 Omarchy path (optional)
var openUrl = [
  "base=${2:-${OMARCHY_PATH:-$HOME/.local/share/omarchy}}",
  "PATH=\"$PATH:$base/bin\"",
  "if command -v omarchy-launch-browser >/dev/null 2>&1; then exec omarchy-launch-browser \"$1\"; fi",
  "exec xdg-open \"$1\""
].join("\n")

// One-time VTAI agent registration.
// $1 credential dir, $2 credential file, $3 JSON body, $4 register URL, $5 user agent
// stdout: "created" | "exists"; on HTTP errors "http <code>\n<body>".
// Exit: 10 mkdir, 11 network, 12 HTTP error, 13 no token, 14 write failed.
// Never overwrites an existing credential file (set -C + ln).
var register = [
  "umask 077",
  "dir=$1 file=$2 body=$3 url=$4 ua=$5",
  "if [ -s \"$file\" ]; then echo exists; exit 0; fi",
  "[ -d \"$dir\" ] || mkdir -p \"$dir\" || exit 10",
  "out=$(curl -sS --proto =https --connect-timeout 10 --max-time 30 -A \"$ua\" -H 'Accept: application/json' -H 'Content-Type: application/json' --data-raw \"$body\" -w '\\n%{http_code}' \"$url\") || exit 11",
  "code=$(printf '%s\\n' \"$out\" | tail -n 1)",
  "resp=$(printf '%s\\n' \"$out\" | sed '$d')",
  "case $code in",
  "  2??) ;;",
  "  *) printf 'http %s\\n%s\\n' \"$code\" \"$resp\"; exit 12 ;;",
  "esac",
  "token=$(printf '%s' \"$resp\" | tr -d '\\r\\n' | sed -n 's/.*\"agent_token\"[[:space:]]*:[[:space:]]*\"\\(vtai_[A-Za-z0-9_-]*\\)\".*/\\1/p')",
  "[ -n \"$token\" ] || exit 13",
  "tmp=\"$file.tmp.$$\"",
  "(set -C; printf 'Authorization: Bearer %s\\n' \"$token\" > \"$tmp\") 2>/dev/null || exit 14",
  "if ln \"$tmp\" \"$file\" 2>/dev/null; then rm -f \"$tmp\"; echo created; exit 0; fi",
  "rm -f \"$tmp\"",
  "if [ -s \"$file\" ]; then echo exists; exit 0; fi",
  "exit 14"
].join("\n")

// SHA-256 of a regular file.
// $1 path, $2 quiet seconds (file must be unmodified that long, 0 = off),
// $3 max bytes (0 = unlimited). stdout: "<size> <sha256>".
// Exit: 3 not a file, 4 unreadable, 5 error, 6 still changing, 7 empty, 8 too large.
var hash = [
  "f=$1 quiet=${2:-0} max=${3:-0}",
  "[ -f \"$f\" ] || exit 3",
  "[ -r \"$f\" ] || exit 4",
  "s1=$(stat -Lc '%s %Y' -- \"$f\") || exit 5",
  "size=${s1%% *} mtime=${s1##* }",
  "[ \"$size\" -gt 0 ] 2>/dev/null || exit 7",
  "if [ \"$max\" -gt 0 ] && [ \"$size\" -gt \"$max\" ]; then exit 8; fi",
  "if [ \"$quiet\" -gt 0 ]; then",
  "  now=$(date +%s) || exit 5",
  "  [ $((now - mtime)) -ge \"$quiet\" ] || exit 6",
  "fi",
  "sum=$(sha256sum < \"$f\") || exit 5",
  "s2=$(stat -Lc '%s %Y' -- \"$f\") || exit 5",
  "[ \"$s1\" = \"$s2\" ] || exit 6",
  "printf '%s %s\\n' \"$size\" \"${sum%% *}\""
].join("\n")

// Desktop notification; clicking it opens the panel.
// $1 urgency, $2 glyph, $3 title, $4 body, $5 plugin id, $6 Omarchy path (optional)
var notify = [
  "base=${6:-${OMARCHY_PATH:-$HOME/.local/share/omarchy}}",
  "PATH=\"$PATH:$base/bin\"",
  "if command -v omarchy-notification-send >/dev/null 2>&1; then",
  "  exec omarchy-notification-send --app-name VirusTotal -u \"$1\" -g \"$2\" \"$3\" \"$4\" --exec omarchy-shell shell summon \"$5\" '{}'",
  "fi",
  "if command -v notify-send >/dev/null 2>&1; then",
  "  exec notify-send -a VirusTotal -u \"$1\" -- \"$3\" \"$4\"",
  "fi",
  "exit 0"
].join("\n")
