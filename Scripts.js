.pragma library

// POSIX sh snippets, run as ["sh", "-c", script, "sh", arg1, arg2, ...].
//
// Untrusted values (paths, URLs, JSON) only ever arrive as positional
// parameters, never spliced into the script text. The VTAI token only exists
// inside `register`, where it stays in shell variables and is written with the
// printf builtin, so it never shows up in any process argv.
//
// tests/scripts.test.js runs every snippet against a fake curl.

// $1 config dir, $2 state dir, $3 credential file, $4 user-dirs.dirs,
// $5 VirusTotal API key header file (optional)
var startup = [
  "umask 077",
  "mkdir -p \"$1\" \"$2\" 2>/dev/null",
  "missing=",
  "for tool in curl sha256sum stat date; do",
  "  command -v \"$tool\" >/dev/null 2>&1 || missing=\"$missing $tool\"",
  "done",
  "printf 'missing=%s\\n' \"${missing# }\"",
  "scanmissing=",
  "for tool in find awk head; do",
  "  command -v \"$tool\" >/dev/null 2>&1 || scanmissing=\"$scanmissing $tool\"",
  "done",
  "printf 'scanmissing=%s\\n' \"${scanmissing# }\"",
  "if [ -s \"$3\" ]; then echo auth=present; else echo auth=missing; fi",
  "if [ -n \"$5\" ] && [ -s \"$5\" ]; then echo apikey=present; else echo apikey=missing; fi",
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

// --- installed-plugin scanner ------------------------------------------------

// One line per plugin folder in $1 (normally ~/.config/omarchy/plugins):
// "dir\thead\tcount size mtime\tversion\tname\tlink|dir". head is the git
// commit or "-". The count/size/mtime stamp changes whenever any file is
// added, removed or rewritten, so the scanner only rehashes changed plugins.
// Folders whose names contain tabs or newlines are skipped.
var probePlugins = [
  "cd \"$1\" 2>/dev/null || exit 3",
  "tab=$(printf '\\t')",
  "nl='",
  "'",
  "for d in *; do",
  "  [ -d \"$d\" ] || continue",
  "  case $d in *\"$tab\"*|*\"$nl\"*) continue ;; esac",
  "  kind=dir",
  "  [ -L \"$d\" ] && kind=link",
  "  head=-",
  "  if [ -e \"$d/.git\" ] && command -v git >/dev/null 2>&1; then",
  "    head=$(git -C \"$d\" rev-parse HEAD 2>/dev/null) || head=-",
  "  fi",
  "  stamp=$(find \"$d/\" -name .git -prune -o -type f -printf '%T@ %s\\n' 2>/dev/null | awk '{ n++; s += $2; if ($1 > m) m = $1 } END { printf \"%d %d %d\", n, s, m }')",
  "  ver= name=",
  "  if [ -f \"$d/manifest.json\" ]; then",
  "    ver=$(sed -n 's/^[[:space:]]*\"version\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' \"$d/manifest.json\" | head -n 1)",
  "    name=$(sed -n 's/^[[:space:]]*\"name\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' \"$d/manifest.json\" | head -n 1)",
  "  fi",
  "  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$d\" \"$head\" \"$stamp\" \"$ver\" \"$name\" \"$kind\"",
  "done"
].join("\n")

// SHA-256 of every regular, non-empty file in plugin folder $1, skipping
// .git/, symlinks, files over 1 GB and paths containing a newline.
// $2 max files. stdout: "#\t<total>\t<skipped>" then "sha256\tsize\trelpath".
var hashPlugin = [
  "cd \"$1/\" 2>/dev/null || exit 3",
  "max=${2:-2000}",
  "nl='",
  "'",
  "total=$(find . -name .git -prune -o -type f -size +0 ! -path \"*$nl*\" -print 2>/dev/null | wc -l)",
  "skipped=$(find . -name .git -prune -o -type f -path \"*$nl*\" -printf x 2>/dev/null | wc -c)",
  "printf '#\\t%s\\t%s\\n' \"$((total))\" \"$((skipped))\"",
  "find . -name .git -prune -o -type f -size +0 -size -1000M ! -path \"*$nl*\" -print 2>/dev/null | head -n \"$max\" |",
  "while IFS= read -r f; do",
  "  size=$(stat -c %s -- \"$f\" 2>/dev/null) || continue",
  "  sum=$(sha256sum < \"$f\" 2>/dev/null) || continue",
  "  printf '%s\\t%s\\t%s\\n' \"${sum%% *}\" \"$size\" \"${f#./}\"",
  "done"
].join("\n")

// Save a VirusTotal API key read from STDIN (never argv) as a curl header
// file with mode 600. $1 config dir, $2 key file.
// Exit: 2 invalid key, 10 mkdir failed, 14 write failed.
var saveApiKey = [
  "umask 077",
  "key=",
  "IFS= read -r key || [ -n \"$key\" ] || exit 2",
  "key=$(printf '%s' \"$key\" | tr -d ' \\t\\r')",
  "case $key in ''|*[!A-Za-z0-9]*) exit 2 ;; esac",
  "[ ${#key} -eq 64 ] || exit 2",
  "[ -d \"$1\" ] || mkdir -p \"$1\" || exit 10",
  "tmp=\"$2.tmp.$$\"",
  "rm -f \"$tmp\"",
  "(set -C; printf 'x-apikey: %s\\n' \"$key\" > \"$tmp\") 2>/dev/null || exit 14",
  "mv -f \"$tmp\" \"$2\" || { rm -f \"$tmp\"; exit 14; }"
].join("\n")

// Standard (public) upload to the classic VirusTotal API: POST /files.
// $1 file, $2 API key header file, $3 URL, $4 user agent, $5 max seconds.
// The file travels on stdin so curl -F never parses the local path (';' ',').
var classicUpload = [
  "[ -f \"$1\" ] && [ -r \"$1\" ] || exit 3",
  "exec curl -sS --proto =https --connect-timeout 10 --max-time \"${5:-130}\" -A \"$4\" -H \"@$2\" -H 'Accept: application/json' -w '\\n%{http_code}' -F 'file=@-;filename=sample' \"$3\" < \"$1\""
].join("\n")
