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
  "exec curl -sS --proto =https --connect-timeout 10 --max-time \"${5:-130}\" -A \"$4\" -H \"@$2\" -H 'Accept: application/json' -w '\\n%{http_code}\\nretry-after:%header{retry-after}' -F 'file=@-;filename=sample' \"$3\" < \"$1\""
].join("\n")

// --- coding agents (AgentsManager.qml) ----------------------------------------
//
// Agents.js builds every argument. Agent commands are allow-listed here as
// well, and an agent only ever runs when agent_state says it is installed:
// running Omarchy's mise launcher stub of a missing agent would install it.

// Shared prelude; $1 is the Omarchy path. agent_state follows Omarchy's own
// rule (bin/omarchy-default-agent): a symlink or a non-stub executable in
// ~/.local/bin is the user's install, and a stub only counts when mise has
// the package. Any other executable first on PATH counts too, except a stub
// or a mise shim whose tool mise does not have.
// agent_state <command> <mise package> -> installed | stub | absent
var agentPrelude = [
  "base=${1:-${OMARCHY_PATH:-$HOME/.local/share/omarchy}}",
  "shims=${MISE_DATA_DIR:-$HOME/.local/share/mise}",
  "shims=${shims%/}/shims",
  "lbin=$HOME/.local/bin",
  "PATH=\"$PATH:$shims:$lbin:$base/bin\"",
  "is_stub() { [ -f \"$1\" ] && grep -q '^mise use -g' \"$1\" 2>/dev/null; }",
  "agent_state() {",
  "  f=$lbin/$1 stub=",
  "  if [ -f \"$f\" ] && [ -x \"$f\" ]; then",
  "    if [ -L \"$f\" ] || ! is_stub \"$f\"; then echo installed; return; fi",
  "    stub=1",
  "  fi",
  "  p=$(command -v \"$1\" 2>/dev/null) || p=",
  "  d=${p%/*}",
  "  while [ \"${d%/}\" != \"$d\" ]; do d=${d%/}; done",
  "  case $p in",
  "    /*) if [ \"$d\" != \"$shims\" ] && ! is_stub \"$p\"; then echo installed; return; fi ;;",
  "  esac",
  "  if [ -n \"$2\" ] && { [ -n \"$stub\" ] || [ -e \"$shims/$1\" ]; } && command -v mise >/dev/null 2>&1 && mise where \"$2\" >/dev/null 2>&1; then",
  "    echo installed",
  "    return",
  "  fi",
  "  if [ -n \"$stub\" ]; then echo stub; else echo absent; fi",
  "}"
].join("\n")

// $1 Omarchy path, $2 \"all\" | \"default\" (only the default agent), then
// pairs: command, mise package. stdout:
//   default\t<agent in ~/.config/omarchy/defaults/agent, empty when unset>
//   agent\t<command>\tinstalled|stub|absent
//   defaultstate\t<the default agent's state, also when it is not in the
//   pairs (checked without a mise package); empty when unset>
//   claudehome\t<account>\t<config dir>\t<1 active | 0>  (all; only when
//   Omarchy's Claude account registry exists)
var probeAgents = agentPrelude + "\n" + [
  "mode=$2",
  "shift 2",
  "tab=$(printf '\\t')",
  "def=",
  "if [ -r \"$HOME/.config/omarchy/defaults/agent\" ]; then IFS= read -r def < \"$HOME/.config/omarchy/defaults/agent\" || :; fi",
  "case $def in -*|*[!A-Za-z0-9._-]*) def= ;; esac",
  "printf 'default\\t%s\\n' \"$def\"",
  "dstate=",
  "while [ $# -ge 2 ]; do",
  "  cmd=$1 pkg=$2",
  "  shift 2",
  "  case $cmd in ''|-*|*[!A-Za-z0-9._-]*) continue ;; esac",
  "  if [ \"$mode\" = default ] && [ \"$cmd\" != \"$def\" ]; then continue; fi",
  "  st=$(agent_state \"$cmd\" \"$pkg\")",
  "  if [ \"$cmd\" = \"$def\" ]; then dstate=$st; fi",
  "  printf 'agent\\t%s\\t%s\\n' \"$cmd\" \"$st\"",
  "done",
  "if [ -n \"$def\" ] && [ -z \"$dstate\" ]; then dstate=$(agent_state \"$def\" \"\"); fi",
  "printf 'defaultstate\\t%s\\n' \"$dstate\"",
  "[ \"$mode\" = all ] || exit 0",
  "state=${XDG_STATE_HOME:-$HOME/.local/state}",
  "case $state in /*) ;; *) state=$HOME/.local/state ;; esac",
  "if [ -f \"$state/omarchy/agents/accounts/claude.json\" ] && command -v omarchy-agent-account-state >/dev/null 2>&1; then",
  "  omarchy-agent-account-state homes claude 2>/dev/null | while IFS=\"$tab\" read -r id dir active; do",
  "    if [ -n \"$id\" ]; then printf 'claudehome\\t%s\\t%s\\t%s\\n' \"$id\" \"$dir\" \"$active\"; fi",
  "  done",
  "fi",
  "exit 0"
].join("\n")

// jq program for probeMcp: one JSON config -> \"<state>\\t<names>\". A
// VirusTotal entry is any object under $key whose URL mentions
// virustotal.com or whose command runs vt-mcp, plus whatever holds the name
// $name. \"ours\" = $name with exactly $url and no headers.
var mcpJq = [
  "def urls: [.url, .serverUrl, .httpUrl, .endpoint] | map(select(type == \"string\"));",
  "def cmds: [.command, ((.args // []) | if type == \"array\" then .[] else empty end)] | map(select(type == \"string\"));",
  "def vt: type == \"object\" and ((urls | any(test(\"virustotal\\\\.com\"; \"i\"))) or (cmds | any(test(\"vt-mcp|virustotal\"; \"i\"))));",
  "def ours: type == \"object\" and ((.url // .serverUrl // .httpUrl) == $url)",
  "  and (((.headers // {}) | if type == \"object\" then length else 1 end) == 0);",
  "if type != \"object\" then \"error\\t\"",
  "else (.[$key] // {}) as $m",
  "  | if ($m | type) != \"object\" then \"error\\t\"",
  "    else [$m | to_entries[] | select(.key == $name or (.value | vt)) | .key | gsub(\"[\\t\\r\\n,]\"; \" \")] as $names",
  "      | (if ($m[$name] | ours) then \"ours\" elif ($names | length) > 0 then \"other\" else \"none\" end) + \"\\t\" + ($names | join(\",\"))",
  "    end",
  "end"
].join("\n")

// awk program for probeMcp: the same answer for a TOML config with
// [mcp_servers.<name>] tables (Codex, Grok). Any *header*, bearer or token
// key, or a .http_headers sub-table, means the entry carries credentials.
// Entries written another way (inline tables under [mcp_servers], dotted
// top-level keys) are not parsed: if they mention VirusTotal, the config
// counts as having the user's own entry ("other", name \"mcp_servers\").
var mcpAwk = [
  "function clean(s) { gsub(/[\\t\\r\\n,]/, \" \", s); return s }",
  "function unquote(v,   q, i) {",
  "  sub(/^[ \\t]+/, \"\", v)",
  "  q = substr(v, 1, 1)",
  "  if (q == \"\\\"\" || q == \"'\") { v = substr(v, 2); i = index(v, q); return i > 0 ? substr(v, 1, i - 1) : v }",
  "  sub(/[ \\t]*(#.*)?$/, \"\", v)",
  "  return v",
  "}",
  "BEGIN { top = 1 }",
  "{ line = $0; sub(/\\r$/, \"\", line) }",
  "line ~ /^[ \\t]*\\[/ {",
  "  h = line",
  "  sub(/^[ \\t]*\\[+[ \\t]*/, \"\", h)",
  "  sub(/[ \\t]*\\]+[ \\t]*(#.*)?$/, \"\", h)",
  "  sel = \"\"; nested = 0; top = 0; root = (h == \"mcp_servers\")",
  "  if (substr(h, 1, 12) != \"mcp_servers.\") next",
  "  rest = substr(h, 13)",
  "  if (substr(rest, 1, 1) == \"\\\"\") {",
  "    rest = substr(rest, 2); i = index(rest, \"\\\"\")",
  "    if (i == 0) next",
  "    nm = substr(rest, 1, i - 1); tail = substr(rest, i + 1)",
  "  } else {",
  "    i = index(rest, \".\")",
  "    if (i > 0) { nm = substr(rest, 1, i - 1); tail = substr(rest, i) } else { nm = rest; tail = \"\" }",
  "  }",
  "  gsub(/^[ \\t]+|[ \\t]+$/, \"\", nm)",
  "  if (nm == \"\") next",
  "  if (!(nm in seen)) { seen[nm] = 1; order[++n] = nm }",
  "  sel = nm",
  "  if (tail != \"\") { nested = 1; if (tail ~ /header/) auth[nm] = 1 }",
  "  next",
  "}",
  "(root || (top && line ~ /^[ \\t]*\\\"?mcp_servers\\\"?[ \\t]*[.=]/)) && tolower(line) ~ /virustotal|vt-mcp/ { loose = 1; next }",
  "sel != \"\" && !nested {",
  "  body[sel] = body[sel] \" \" line",
  "  if (line !~ /^[ \\t]*[\"A-Za-z0-9_-]+[ \\t]*=/) next",
  "  k = line; sub(/=.*/, \"\", k); gsub(/[ \\t\"]/, \"\", k)",
  "  v = line; sub(/^[^=]*=/, \"\", v)",
  "  if (k == \"url\") url[sel] = unquote(v)",
  "  else if (k ~ /header|bearer|token/) auth[sel] = 1",
  "}",
  "END {",
  "  names = \"\"; ours = 0",
  "  for (j = 1; j <= n; j++) {",
  "    nm = order[j]",
  "    vt = tolower(url[nm]) ~ /virustotal\\.com/ || tolower(body[nm]) ~ /vt-mcp/",
  "    if (nm != want && !vt) continue",
  "    names = names (names == \"\" ? \"\" : \",\") clean(nm)",
  "    if (nm == want && url[nm] == target && !(nm in auth)) ours = 1",
  "  }",
  "  if (loose) names = names (names == \"\" ? \"\" : \",\") \"mcp_servers\"",
  "  if (ours) print \"ours\\t\" names",
  "  else if (names != \"\") print \"other\\t\" names",
  "  else print \"none\\t\"",
  "}"
].join("\n")

// Read-only look at the agents' MCP configs. $1 MCP URL, $2 entry name,
// $3 Scripts.mcpJq, $4 Scripts.mcpAwk, then quadruples: label, format
// (json | toml | exists), path, key (\"-\" = none).
// stdout per target: \"label\\tstate\\tnames\" with state nofile | error |
// none | ours | other, or found | nofile for \"exists\".
var probeMcp = [
  "url=$1 name=$2 jqprog=$3 awkprog=$4",
  "shift 4",
  "tab=$(printf '\\t')",
  "while [ $# -ge 4 ]; do",
  "  label=$1 format=$2 f=$3 key=$4",
  "  shift 4",
  "  case $label in ''|*\"$tab\"*) continue ;; esac",
  "  if [ \"$format\" = exists ]; then",
  "    if [ -e \"$f\" ] || [ -L \"$f\" ]; then printf '%s\\tfound\\t\\n' \"$label\"; else printf '%s\\tnofile\\t\\n' \"$label\"; fi",
  "    continue",
  "  fi",
  "  if [ ! -e \"$f\" ] && [ ! -L \"$f\" ]; then printf '%s\\tnofile\\t\\n' \"$label\"; continue; fi",
  "  out=",
  "  if [ -f \"$f\" ] && [ -r \"$f\" ]; then",
  "    case $format in",
  "      json) if command -v jq >/dev/null 2>&1; then out=$(jq -r --arg key \"$key\" --arg name \"$name\" --arg url \"$url\" \"$jqprog\" \"$f\" 2>/dev/null | head -n 1); fi ;;",
  "      toml) out=$(awk -v want=\"$name\" -v target=\"$url\" \"$awkprog\" \"$f\" 2>/dev/null | head -n 1) ;;",
  "    esac",
  "  fi",
  "  case $out in",
  "    none\"$tab\"*|ours\"$tab\"*|other\"$tab\"*|error\"$tab\"*) printf '%s\\t%s\\n' \"$label\" \"$out\" ;;",
  "    *) printf '%s\\terror\\t\\n' \"$label\" ;;",
  "  esac",
  "done"
].join("\n")

// The virustotal skill in the folders Omarchy links its own skills into
// (bin/omarchy-provision-user), including every Hermes profile.
// $1 link | unlink | status, $2 this plugin's skill folder, $3 skill name,
// $4 path tail of this plugin's skill in any location (older copies).
// stdout per folder: \"<folder>/<name>\\t<state>\":
//   ours    symlink to $2          stale  symlink to an older copy ($4)
//   user    a real file or folder  other  someone else's symlink
//   missing nothing there          failed the change did not work
// link only creates missing links and repoints stale ones; unlink only
// removes ours and stale. Real folders and other symlinks are never touched.
var skillLinks = [
  "mode=$1 src=$2 name=$3 marker=$4",
  "case $mode in link|unlink|status) ;; *) exit 2 ;; esac",
  "case $name in ''|.|..|*/*) exit 2 ;; esac",
  "case $src in /*) ;; *) exit 2 ;; esac",
  "[ -n \"$marker\" ] || exit 2",
  "if [ \"$mode\" = link ] && [ ! -f \"$src/SKILL.md\" ]; then exit 3; fi",
  "tab=$(printf '\\t')",
  "nl='",
  "'",
  "one() {",
  "  case $1 in *\"$tab\"*|*\"$nl\"*) return 0 ;; esac",
  "  p=$1/$name",
  "  if [ -L \"$p\" ]; then",
  "    t=$(readlink -- \"$p\")",
  "    if [ \"$t\" = \"$src\" ] || [ \"$t\" = \"$src/\" ]; then st=ours",
  "    else",
  "      case $t in *\"$marker\"|*\"$marker/\") st=stale ;; *) st=other ;; esac",
  "    fi",
  "  elif [ -e \"$p\" ]; then st=user",
  "  else st=missing",
  "  fi",
  "  case $mode:$st in",
  "    link:missing) if mkdir -p -- \"$1\" 2>/dev/null && ln -s -- \"$src\" \"$p\" 2>/dev/null; then st=ours; else st=failed; fi ;;",
  "    link:stale) if ln -sfn -- \"$src\" \"$p\" 2>/dev/null; then st=ours; else st=failed; fi ;;",
  "    unlink:ours|unlink:stale) if rm -f -- \"$p\" 2>/dev/null; then st=missing; else st=failed; fi ;;",
  "  esac",
  "  printf '%s\\t%s\\n' \"$p\" \"$st\"",
  "}",
  "for rel in .agents/skills .claude/skills .codex/skills .pi/agent/skills .gemini/config/skills .hermes/skills; do",
  "  one \"$HOME/$rel\"",
  "done",
  "if [ -d \"$HOME/.hermes/profiles\" ]; then",
  "  for prof in \"$HOME\"/.hermes/profiles/*/; do",
  "    [ -d \"$prof\" ] || continue",
  "    one \"${prof%/}/skills\"",
  "  done",
  "fi",
  "exit 0"
].join("\n")

// An agent's own `mcp add` / `mcp remove` (Agents.cliArgs).
// $1 Omarchy path, $2 Claude config dir (\"\" = the default one), $3 mise
// package, then the command and its arguments. Exit 2 refused, 3 not
// installed, 124 timed out (90 s); otherwise the agent's exit code.
var agentCli = agentPrelude + "\n" + [
  "home=$2 pkg=$3",
  "shift 3",
  "case ${1:-} in claude|codex|agy|copilot|grok) ;; *) exit 2 ;; esac",
  "case $home in ''|/*) ;; *) exit 2 ;; esac",
  "if [ -n \"$home\" ] && [ \"$1\" != claude ]; then exit 2; fi",
  "[ \"$(agent_state \"$1\" \"$pkg\")\" = installed ] || exit 3",
  "if [ -n \"$home\" ]; then CLAUDE_CONFIG_DIR=$home; export CLAUDE_CONFIG_DIR; else unset CLAUDE_CONFIG_DIR; fi",
  "cd \"$HOME\" 2>/dev/null || cd /",
  "if command -v timeout >/dev/null 2>&1; then exec timeout 90 \"$@\" </dev/null; fi",
  "exec \"$@\" </dev/null"
].join("\n")

// One entry in an agent's JSON config, edited with jq (Agents.jsonArgs).
// $1 add | remove, $2 file, $3 key, $4 entry name, $5 entry JSON, $6 JSON
// for a new file, $7 refuse when this path exists (\"\" = never), $8 MCP URL.
// add never replaces an entry; remove only deletes an entry that still holds
// exactly $8 and no headers. The previous file is kept as
// <file>.bak-omarchy-virustotal-<time> and replaced atomically with its mode.
// Symlinks and files jq cannot parse (JSONC comments) are refused.
// stdout: \"exists\" | \"changed\" | \"none\" | \"done\\t<backup, empty for a new file>\".
// Exit: 2 bad arguments, 20 no jq, 21 not a regular file, 22 not a JSON
// object, 23 mkdir, 24 backup, 25 jq, 26 replace, 27 refused.
var jsonMcp = [
  "umask 077",
  "mode=$1 f=$2 key=$3 name=$4 entry=$5 tmpl=$6 refuse=$7 url=$8",
  "[ -n \"$entry\" ] || entry=null",
  "[ -n \"$tmpl\" ] || tmpl='{}'",
  "case $mode in add|remove) ;; *) exit 2 ;; esac",
  "case $f in /*) ;; *) exit 2 ;; esac",
  "if [ -z \"$key\" ] || [ -z \"$name\" ]; then exit 2; fi",
  "command -v jq >/dev/null 2>&1 || exit 20",
  "if [ -n \"$refuse\" ] && { [ -e \"$refuse\" ] || [ -L \"$refuse\" ]; }; then exit 27; fi",
  "cur=",
  "if [ -e \"$f\" ] || [ -L \"$f\" ]; then",
  "  if [ -L \"$f\" ] || [ ! -f \"$f\" ]; then exit 21; fi",
  "  jq -e --arg k \"$key\" 'type == \"object\" and ((.[$k] // {}) | type == \"object\")' \"$f\" >/dev/null 2>&1 || exit 22",
  "  cur=$(jq -c --arg k \"$key\" --arg n \"$name\" '(.[$k] // {}) | if has($n) then .[$n] else empty end' \"$f\" 2>/dev/null) || exit 22",
  "elif [ \"$mode\" = remove ]; then",
  "  echo none",
  "  exit 0",
  "fi",
  "if [ \"$mode\" = add ]; then",
  "  if [ -n \"$cur\" ]; then echo exists; exit 0; fi",
  "  prog='.[$k] = ((.[$k] // {}) + {($n): $e})'",
  "else",
  "  if [ -z \"$cur\" ]; then echo none; exit 0; fi",
  "  printf '%s' \"$cur\" | jq -e --arg u \"$url\" 'type == \"object\" and ((.url // .serverUrl // .httpUrl) == $u) and (((.headers // {}) | if type == \"object\" then length else 1 end) == 0)' >/dev/null 2>&1 || { echo changed; exit 0; }",
  "  prog='del(.[$k][$n])'",
  "fi",
  "tmp=\"$f.tmp-omarchy-virustotal.$$\"",
  "bak=",
  "if [ -f \"$f\" ]; then",
  "  bak=\"$f.bak-omarchy-virustotal-$(date +%Y%m%d%H%M%S)\"",
  "  if [ -e \"$bak\" ] || [ -L \"$bak\" ]; then bak=\"$bak-$$\"; fi",
  "  cp -p -- \"$f\" \"$bak\" || exit 24",
  "  jq --arg k \"$key\" --arg n \"$name\" --argjson e \"$entry\" \"$prog\" \"$f\" > \"$tmp\" 2>/dev/null || { rm -f -- \"$tmp\"; exit 25; }",
  "  chmod --reference=\"$f\" -- \"$tmp\" 2>/dev/null || :",
  "else",
  "  mkdir -p -- \"$(dirname -- \"$f\")\" || exit 23",
  "  printf '%s' \"$tmpl\" | jq --arg k \"$key\" --arg n \"$name\" --argjson e \"$entry\" \"$prog\" > \"$tmp\" 2>/dev/null || { rm -f -- \"$tmp\"; exit 25; }",
  "fi",
  "mv -f -- \"$tmp\" \"$f\" || { rm -f -- \"$tmp\"; exit 26; }",
  "printf 'done\\t%s\\n' \"$bak\""
].join("\n")

// Open an agent so the user can sign in to VirusTotal (Agents.signInPlan).
// $1 Omarchy path, $2 login | session, $3 Claude config dir (\"\" = default),
// $4 mise package, then the command and its arguments.
//   login:   a floating Omarchy terminal runs the command; that launcher
//            takes one bash string, so each argument is single-quoted and
//            arguments containing a quote are refused
//   session: the agent's TUI in a terminal (omarchy-launch-tui)
var launchAgent = agentPrelude + "\n" + [
  "mode=$2 home=$3 pkg=$4",
  "shift 4",
  "case ${1:-} in claude|codex|agy|copilot|grok|opencode|cursor-agent) ;; *) exit 2 ;; esac",
  "case $home in ''|/*) ;; *) exit 2 ;; esac",
  "if [ -n \"$home\" ] && [ \"$1\" != claude ]; then exit 2; fi",
  "[ \"$(agent_state \"$1\" \"$pkg\")\" = installed ] || exit 3",
  "[ -n \"$home\" ] || unset CLAUDE_CONFIG_DIR",
  "cd \"$HOME/Work\" 2>/dev/null || cd \"$HOME\" 2>/dev/null || cd /",
  "case $mode in",
  "  login)",
  "    line=",
  "    for a in \"$@\"; do",
  "      case $a in *\"'\"*) exit 2 ;; esac",
  "      line=\"$line '$a'\"",
  "    done",
  "    if [ -n \"$home\" ]; then",
  "      case $home in *\"'\"*) exit 2 ;; esac",
  "      line=\"CLAUDE_CONFIG_DIR='$home'$line\"",
  "    else",
  "      line=${line# }",
  "    fi",
  "    exec omarchy-launch-floating-terminal-with-presentation \"$line\"",
  "    ;;",
  "  session)",
  "    if [ -n \"$home\" ]; then exec omarchy-launch-tui --app-id=org.omarchy.agent env CLAUDE_CONFIG_DIR=\"$home\" \"$@\"; fi",
  "    exec omarchy-launch-tui --app-id=org.omarchy.agent \"$@\"",
  "    ;;",
  "esac",
  "exit 2"
].join("\n")

// \"Ask <agent>\": `omarchy agent prompt` opens the default agent in a
// terminal with the prompt. $1 Omarchy path, $2 prompt (one argument).
var agentPrompt = [
  "base=${1:-${OMARCHY_PATH:-$HOME/.local/share/omarchy}}",
  "shims=${MISE_DATA_DIR:-$HOME/.local/share/mise}",
  "PATH=\"$PATH:${shims%/}/shims:$HOME/.local/bin:$base/bin\"",
  "cd \"$HOME\" 2>/dev/null || cd /",
  "exec omarchy-agent-prompt \"$2\""
].join("\n")

// Omarchy's default-agent picker. $1 Omarchy path.
var agentMenu = [
  "base=${1:-${OMARCHY_PATH:-$HOME/.local/share/omarchy}}",
  "PATH=\"$PATH:$base/bin\"",
  "exec omarchy-menu summon setup.default.agent"
].join("\n")

// Copy $1 to the Wayland clipboard. wl-copy keeps serving the selection from
// a forked child; its output goes to /dev/null so that child does not hold
// the job's pipes open. Exit 127 without wl-copy.
var copyText = [
  "command -v wl-copy >/dev/null 2>&1 || exit 127",
  "printf '%s' \"$1\" | wl-copy >/dev/null 2>&1"
].join("\n")
