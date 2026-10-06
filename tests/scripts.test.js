// Executes the shell snippets from Scripts.js against fake tools.
// Run with: node tests/scripts.test.js
"use strict"

const assert = require("assert")
const childProcess = require("child_process")
const crypto = require("crypto")
const fs = require("fs")
const os = require("os")
const path = require("path")
const vm = require("vm")

const source = fs.readFileSync(path.join(__dirname, "..", "Scripts.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "")
const S = vm.createContext({})
vm.runInContext(source, S, { filename: "Scripts.js" })

const shells = ["sh", "bash", "dash"].filter(shell => childProcess.spawnSync(shell, ["-c", "exit 0"]).status === 0)
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "omarchy-vt-test-"))
const bin = path.join(tmp, "bin")
fs.mkdirSync(bin)

// Fake curl: records its argv, then answers according to FAKE_CURL_MODE.
fs.writeFileSync(path.join(bin, "curl"), [
  "#!/bin/sh",
  "printf '%s\\n' \"$@\" > \"$FAKE_LOG\"",
  "case $FAKE_CURL_MODE in",
  "  ok) printf '{\"agent_id\":\"agt_1\",\"agent_token\":\"vtai_TEST-tok_123\",\"public_handle\":\"x#1\"}\\n200' ;;",
  "  pretty) printf '{\\n  \"agent_id\": \"agt_1\",\\n  \"agent_token\": \"vtai_Pretty_456\"\\n}\\n200' ;;",
  "  limited) printf '{\"detail\":{\"error\":\"too many\",\"status_code\":429,\"retry_after\":\"3600\"}}\\n429' ;;",
  "  notoken) printf '{\"agent_id\":\"agt_1\"}\\n200' ;;",
  "  down) exit 7 ;;",
  "  upload) cat > \"$FAKE_STDIN\"; printf '{\"data\":{\"type\":\"analysis\",\"id\":\"YWJj\"}}\\n200' ;;",
  "esac"
].join("\n"), { mode: 0o755 })
fs.writeFileSync(path.join(bin, "omarchy-notification-send"),
  "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_LOG\"\n", { mode: 0o755 })

function run(shell, script, args, env) {
  const r = childProcess.spawnSync(shell, ["-c", script, "sh"].concat(args), {
    encoding: "utf8",
    env: Object.assign({ PATH: bin + ":" + process.env.PATH, HOME: tmp, FAKE_LOG: path.join(tmp, "log") }, env || {})
  })
  return { code: r.status, out: r.stdout, err: r.stderr }
}
function mode(p) { return (fs.statSync(p).mode & 0o777).toString(8) }

let passed = 0
let failed = 0
function test(name, fn) {
  for (const shell of shells) {
    try {
      fn(shell)
      passed++
    } catch (e) {
      failed++
      console.error("FAIL [" + shell + "] " + name + "\n  " + (e && e.stack ? e.stack.split("\n").slice(0, 3).join("\n  ") : e))
    }
  }
}

test("scripts parse", shell => {
  for (const name of ["startup", "credentialCheck", "dirCheck", "removeFile", "openUrl", "register", "hash", "notify",
                      "probePlugins", "hashPlugin", "saveApiKey", "classicUpload", "prepareUpload", "removeUpload",
                      "agentPrelude", "probeAgents", "probeMcp", "skillLinks", "agentCli", "jsonMcp", "launchAgent",
                      "agentPrompt", "agentMenu", "copyText"]) {
    assert.strictEqual(typeof S[name], "string", name)
    const r = childProcess.spawnSync(shell, ["-n", "-c", S[name]], { encoding: "utf8" })
    assert.strictEqual(r.status, 0, name + ": " + r.stderr)
  }
})

test("register creates a private credential file once", shell => {
  const dir = path.join(tmp, shell, "vtai")
  const file = path.join(dir, "auth.header")
  fs.rmSync(path.join(tmp, shell), { recursive: true, force: true })
  const args = [dir, file, "{\"agent_family\":\"omarchy\"}", "https://ai.virustotal.com/api/v3/agents/register", "omarchy-virustotal/1.0.0"]
  let r = run(shell, S.register, args, { FAKE_CURL_MODE: "ok" })
  assert.strictEqual(r.code, 0, r.err)
  assert.strictEqual(r.out.trim(), "created")
  assert.strictEqual(fs.readFileSync(file, "utf8"), "Authorization: Bearer vtai_TEST-tok_123\n")
  assert.strictEqual(mode(file), "600")
  assert.strictEqual(mode(dir), "700")
  const argv = fs.readFileSync(path.join(tmp, "log"), "utf8")
  assert.ok(!/vtai_/.test(argv), "token must not reach curl argv")
  assert.ok(/--proto\n=https/.test(argv))
  assert.deepStrictEqual(fs.readdirSync(dir), ["auth.header"])

  fs.unlinkSync(path.join(tmp, "log"))
  r = run(shell, S.register, args, { FAKE_CURL_MODE: "ok" })
  assert.strictEqual(r.code, 0)
  assert.strictEqual(r.out.trim(), "exists")
  assert.ok(!fs.existsSync(path.join(tmp, "log")), "must not call the API when a token exists")
})

test("register handles pretty-printed JSON", shell => {
  const dir = path.join(tmp, shell + "-pretty")
  const file = path.join(dir, "auth.header")
  const r = run(shell, S.register, [dir, file, "{}", "https://x/", "ua"], { FAKE_CURL_MODE: "pretty" })
  assert.strictEqual(r.code, 0, r.err)
  assert.strictEqual(fs.readFileSync(file, "utf8"), "Authorization: Bearer vtai_Pretty_456\n")
})

test("register reports failures without creating files", shell => {
  const dir = path.join(tmp, shell + "-fail")
  const file = path.join(dir, "auth.header")
  let r = run(shell, S.register, [dir, file, "{}", "https://x/", "ua"], { FAKE_CURL_MODE: "limited" })
  assert.strictEqual(r.code, 12)
  assert.ok(/^http 429\n/.test(r.out))
  r = run(shell, S.register, [dir, file, "{}", "https://x/", "ua"], { FAKE_CURL_MODE: "notoken" })
  assert.strictEqual(r.code, 13)
  r = run(shell, S.register, [dir, file, "{}", "https://x/", "ua"], { FAKE_CURL_MODE: "down" })
  assert.strictEqual(r.code, 11)
  assert.ok(!fs.existsSync(file))
  assert.deepStrictEqual(fs.readdirSync(dir), [])
})

test("hash reports size and sha256", shell => {
  const f = path.join(tmp, "hello file.txt")
  fs.writeFileSync(f, "hello\n")
  const old = new Date(Date.now() - 60000)
  fs.utimesSync(f, old, old)
  const sha = crypto.createHash("sha256").update("hello\n").digest("hex")
  let r = run(shell, S.hash, [f, "0", "0"])
  assert.strictEqual(r.code, 0, r.err)
  assert.strictEqual(r.out, "6 " + sha + "\n")
  r = run(shell, S.hash, [f, "4", "0"])
  assert.strictEqual(r.code, 0, r.err)
  r = run(shell, S.hash, [f, "0", "3"])
  assert.strictEqual(r.code, 8)
})

test("hash rejects unusable files", shell => {
  assert.strictEqual(run(shell, S.hash, [path.join(tmp, "missing"), "0", "0"]).code, 3)
  assert.strictEqual(run(shell, S.hash, [tmp, "0", "0"]).code, 3)
  const empty = path.join(tmp, "empty")
  fs.writeFileSync(empty, "")
  assert.strictEqual(run(shell, S.hash, [empty, "0", "0"]).code, 7)
  const fresh = path.join(tmp, "fresh")
  fs.writeFileSync(fresh, "data")
  assert.strictEqual(run(shell, S.hash, [fresh, "60", "0"]).code, 6)
  const dashed = path.join(tmp, "-n")
  fs.writeFileSync(dashed, "x")
  assert.strictEqual(run(shell, S.hash, [dashed, "0", "0"]).code, 0)
  if (process.getuid && process.getuid() !== 0) {
    const locked = path.join(tmp, "locked-" + shell)
    fs.writeFileSync(locked, "secret")
    fs.chmodSync(locked, 0o000)
    assert.strictEqual(run(shell, S.hash, [locked, "0", "0"]).code, 4)
  }
})

test("startup creates private dirs and reports state", shell => {
  const base = path.join(tmp, shell + "-startup")
  const cfg = path.join(base, "config", "omarchy-virustotal")
  const state = path.join(base, "state", "omarchy-virustotal")
  const auth = path.join(base, "auth.header")
  const dirs = path.join(base, "user-dirs.dirs")
  fs.mkdirSync(base, { recursive: true })
  fs.writeFileSync(dirs, "# comment\nXDG_DESKTOP_DIR=\"$HOME/Escritorio\"\nXDG_DOWNLOAD_DIR=\"$HOME/Descargas\"\n")
  let r = run(shell, S.startup, [cfg, state, auth, dirs])
  assert.strictEqual(r.code, 0, r.err)
  assert.ok(/^missing=$/m.test(r.out), r.out)
  assert.ok(/^auth=missing$/m.test(r.out))
  assert.ok(/^apikey=missing$/m.test(r.out))
  assert.ok(/^scanmissing=$/m.test(r.out), r.out)
  assert.ok(/^downloads=\$HOME\/Descargas$/m.test(r.out), r.out)
  assert.strictEqual(mode(cfg), "700")
  assert.strictEqual(mode(state), "700")
  fs.writeFileSync(auth, "Authorization: Bearer vtai_x\n")
  r = run(shell, S.startup, [cfg, state, auth, path.join(base, "nope")])
  assert.ok(/^auth=present$/m.test(r.out))
  assert.ok(/^downloads=$/m.test(r.out))
  const key = path.join(base, "vt-apikey.header")
  fs.writeFileSync(key, "x-apikey: k\n")
  r = run(shell, S.startup, [cfg, state, auth, dirs, key])
  assert.ok(/^apikey=present$/m.test(r.out))
})

test("credential check", shell => {
  const f = path.join(tmp, "cred")
  fs.writeFileSync(f, "x")
  assert.strictEqual(run(shell, S.credentialCheck, [f]).code, 0)
  assert.notStrictEqual(run(shell, S.credentialCheck, [path.join(tmp, "none")]).code, 0)
})

test("directory check", shell => {
  const d = path.join(tmp, shell + " dir with spaces")
  fs.mkdirSync(d, { recursive: true })
  assert.strictEqual(run(shell, S.dirCheck, [d]).code, 0)
  assert.notStrictEqual(run(shell, S.dirCheck, [path.join(tmp, "missing-dir")]).code, 0)
  const f = path.join(tmp, "plain-file")
  fs.writeFileSync(f, "x")
  assert.notStrictEqual(run(shell, S.dirCheck, [f]).code, 0)
})

test("removeFile deletes only the given path", shell => {
  const dir = path.join(tmp, shell + "-rm")
  fs.mkdirSync(dir, { recursive: true })
  const victim = path.join(dir, "-rf auth.header")
  const other = path.join(dir, "keep")
  fs.writeFileSync(victim, "x")
  fs.writeFileSync(other, "y")
  assert.strictEqual(run(shell, S.removeFile, [victim]).code, 0)
  assert.ok(!fs.existsSync(victim) && fs.existsSync(other))
  assert.strictEqual(run(shell, S.removeFile, [victim]).code, 0, "missing file is not an error")
})

test("openUrl prefers omarchy-launch-browser and passes the URL as one argument", shell => {
  const log = path.join(tmp, shell + "-browser.log")
  fs.writeFileSync(path.join(bin, "omarchy-launch-browser"),
    "#!/bin/sh\nprintf '%s\\n' \"$#\" \"$@\" > \"$BROWSER_LOG\"\n", { mode: 0o755 })
  const url = "https://www.virustotal.com/gui/search/a%20b;$(touch pwned)"
  const r = run(shell, S.openUrl, [url], { BROWSER_LOG: log })
  assert.strictEqual(r.code, 0, r.err)
  assert.deepStrictEqual(fs.readFileSync(log, "utf8").split("\n").slice(0, 2), ["1", url])
  assert.ok(!fs.existsSync(path.join(tmp, "pwned")))
  fs.unlinkSync(path.join(bin, "omarchy-launch-browser"))
})

test("notify passes untrusted text as plain arguments", shell => {
  const title = "Malicious download: $(touch pwned) `id` \"q\".exe"
  const r = run(shell, S.notify, ["critical", "G", title, "5 of 70", "io.github.dsecuma.virustotal"])
  assert.strictEqual(r.code, 0, r.err)
  const argv = fs.readFileSync(path.join(tmp, "log"), "utf8").split("\n")
  assert.deepStrictEqual(argv.slice(0, 13), [
    "--app-name", "VirusTotal", "-u", "critical", "-g", "G", title, "5 of 70",
    "--exec", "omarchy-shell", "shell", "summon", "io.github.dsecuma.virustotal"
  ])
  assert.strictEqual(argv[13], "{}")
  assert.ok(!fs.existsSync(path.join(process.cwd(), "pwned")) && !fs.existsSync(path.join(tmp, "pwned")))
})

test("notify finds the notifier under the injected Omarchy path", shell => {
  const omarchy = path.join(tmp, shell + "-omarchy")
  fs.mkdirSync(path.join(omarchy, "bin"), { recursive: true })
  const log = path.join(tmp, shell + "-omarchy.log")
  fs.writeFileSync(path.join(omarchy, "bin", "omarchy-notification-send"),
    "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$OMARCHY_TEST_LOG\"\n", { mode: 0o755 })
  const sysPath = process.env.PATH.split(":").filter(p => p !== bin).join(":")
  const r = run(shell, S.notify, ["low", "G", "t", "b", "io.github.dsecuma.virustotal", omarchy],
    { PATH: sysPath, OMARCHY_TEST_LOG: log, OMARCHY_PATH: "" })
  assert.strictEqual(r.code, 0, r.err)
  assert.ok(fs.existsSync(log), "notifier from $6 was not used")
  assert.strictEqual(fs.readFileSync(log, "utf8").split("\n")[3], "low")
})

// --- installed-plugin scanner ------------------------------------------------

const hasGit = childProcess.spawnSync("git", ["--version"]).status === 0
function sha256(text) { return crypto.createHash("sha256").update(text).digest("hex") }

function makePlugins(base) {
  fs.rmSync(base, { recursive: true, force: true })
  const clock = path.join(base, "io.github.x.clock")
  fs.mkdirSync(path.join(clock, "sub dir"), { recursive: true })
  fs.writeFileSync(path.join(clock, "manifest.json"), "{\n  \"id\": \"io.github.x.clock\",\n  \"name\": \"Clock\",\n  \"version\": \"1.2.0\",\n  \"barWidget\": { \"name\": \"nested\" }\n}\n")
  fs.writeFileSync(path.join(clock, "BarWidget.qml"), "Item {}\n")
  fs.writeFileSync(path.join(clock, "sub dir", "a b;c.js"), "var x = 1\n")
  fs.writeFileSync(path.join(clock, "empty"), "")
  fs.writeFileSync(path.join(clock, "bad\nname.sh"), "echo hi\n")
  fs.symlinkSync("/etc/passwd", path.join(clock, "link-to-passwd"))
  fs.mkdirSync(path.join(clock, ".git"))
  fs.writeFileSync(path.join(clock, ".git", "config"), "not scanned\n")
  const other = path.join(base, "plain plugin")
  fs.mkdirSync(other)
  fs.writeFileSync(path.join(other, "Panel.qml"), "Panel {}\n")
  fs.writeFileSync(path.join(base, "not-a-dir"), "x")
  const dev = path.join(base, "..", path.basename(base) + "-dev")
  fs.rmSync(dev, { recursive: true, force: true })
  fs.mkdirSync(dev)
  fs.writeFileSync(path.join(dev, "Service.qml"), "Item {}\n")
  fs.symlinkSync(dev, path.join(base, "dev.linked"))
  return { clock, other, dev }
}

test("probePlugins lists plugin folders with a change stamp", shell => {
  const base = path.join(tmp, shell + "-plugins")
  const p = makePlugins(base)
  let r = run(shell, S.probePlugins, [base])
  assert.strictEqual(r.code, 0, r.err)
  const rows = r.out.trim().split("\n").map(l => l.split("\t"))
  const byId = {}
  for (const row of rows) byId[row[0]] = row
  assert.deepStrictEqual(Object.keys(byId).sort(), ["dev.linked", "io.github.x.clock", "plain plugin"])
  const clock = byId["io.github.x.clock"]
  assert.strictEqual(clock[3], "1.2.0")
  assert.strictEqual(clock[4], "Clock", "top-level name, not the nested one")
  assert.strictEqual(clock[5], "dir")
  assert.ok(/^[a-f0-9]{64}$/.test(clock[2]), "metadata digest: " + clock[2])
  assert.strictEqual(byId["dev.linked"][5], "link")
  assert.ok(/^[a-f0-9]{64}$/.test(byId["dev.linked"][2]), "digest for the top-level symlink")
  const before = clock[2]
  fs.writeFileSync(path.join(p.clock, "BarWidget.qml"), "Item { id: changed }\n")
  r = run(shell, S.probePlugins, [base])
  const after = r.out.split("\n").find(l => l.startsWith("io.github.x.clock\t")).split("\t")[2]
  assert.notStrictEqual(after, before, "stamp changes when a file changes")
  assert.strictEqual(run(shell, S.probePlugins, [path.join(tmp, "no-such-dir")]).code, 3)
})

test("probePlugins reports the git commit", shell => {
  if (!hasGit) return
  const base = path.join(tmp, shell + "-gitplugins")
  fs.rmSync(base, { recursive: true, force: true })
  const repo = path.join(base, "io.github.x.git")
  fs.mkdirSync(repo, { recursive: true })
  fs.writeFileSync(path.join(repo, "manifest.json"), "{\"id\":\"io.github.x.git\"}\n")
  const g = args => childProcess.spawnSync("git", args, { cwd: repo, encoding: "utf8",
    env: Object.assign({}, process.env, { GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" }) })
  g(["init", "-q"]); g(["add", "."]); g(["commit", "-qm", "init"])
  const head = g(["rev-parse", "HEAD"]).stdout.trim()
  const r = run(shell, S.probePlugins, [base])
  assert.strictEqual(r.out.split("\t")[1], head)
})

test("hashPlugin hashes regular files only", shell => {
  const base = path.join(tmp, shell + "-hplugins")
  const p = makePlugins(base)
  const r = run(shell, S.hashPlugin, [p.clock, "100"])
  assert.strictEqual(r.code, 0, r.err)
  const lines = r.out.trim().split("\n")
  assert.strictEqual(lines[0], "#\t3\t1", "3 hashable files, 1 skipped for a newline in its name")
  const got = {}
  for (const l of lines.slice(1)) {
    const [h, size, rel] = l.split("\t")
    got[rel] = [h, Number(size)]
  }
  assert.deepStrictEqual(Object.keys(got).sort(), ["BarWidget.qml", "manifest.json", "sub dir/a b;c.js"])
  assert.deepStrictEqual(got["sub dir/a b;c.js"], [sha256("var x = 1\n"), 10])
  const capped = run(shell, S.hashPlugin, [p.clock, "1"]).out.trim().split("\n")
  assert.strictEqual(capped.length, 2, "header + max files")
  assert.strictEqual(run(shell, S.hashPlugin, [path.join(tmp, "missing-plugin"), "5"]).code, 3)
})

test("saveApiKey reads the key from stdin into a private header file", shell => {
  const dir = path.join(tmp, shell + "-key", "omarchy-virustotal")
  const file = path.join(dir, "vt-apikey.header")
  fs.rmSync(path.dirname(dir), { recursive: true, force: true })
  const key = "a1".repeat(32)
  const runIn = input => childProcess.spawnSync(shell, ["-c", S.saveApiKey, "sh", dir, file],
    { input: input, encoding: "utf8", env: { PATH: process.env.PATH } })
  let r = runIn(" " + key + " \r\n")
  assert.strictEqual(r.status, 0, r.stderr)
  assert.strictEqual(fs.readFileSync(file, "utf8"), "x-apikey: " + key + "\n")
  assert.strictEqual(mode(file), "600")
  assert.strictEqual(mode(dir), "700")
  r = runIn("b2".repeat(32))
  assert.strictEqual(r.status, 0, "replaces an existing key (no trailing newline)")
  assert.strictEqual(fs.readFileSync(file, "utf8"), "x-apikey: " + "b2".repeat(32) + "\n")
  for (const bad of ["", "short", "g".repeat(64) + "$(touch pwned)", "z".repeat(63) + ";", "a".repeat(65)]) {
    assert.strictEqual(runIn(bad + "\n").status, 2, "rejects " + JSON.stringify(bad))
  }
  assert.strictEqual(fs.readFileSync(file, "utf8"), "x-apikey: " + "b2".repeat(32) + "\n")
  assert.deepStrictEqual(fs.readdirSync(dir), ["vt-apikey.header"])
  assert.ok(!fs.existsSync(path.join(tmp, "pwned")))
})

test("classicUpload sends the file on stdin with the key header file", shell => {
  const f = path.join(tmp, shell + " sample;type=text,x.sh")
  fs.writeFileSync(f, "#!/bin/sh\necho payload\n")
  const stdinFile = path.join(tmp, shell + "-stdin")
  const r = run(shell, S.classicUpload, [f, "/cfg/vt-apikey.header", "https://www.virustotal.com/api/v3/files", "ua/1", "30"],
    { FAKE_CURL_MODE: "upload", FAKE_STDIN: stdinFile })
  assert.strictEqual(r.code, 0, r.err)
  assert.ok(/"id":"YWJj"}}\n200$/.test(r.out), r.out)
  assert.strictEqual(fs.readFileSync(stdinFile, "utf8"), "#!/bin/sh\necho payload\n")
  const argv = fs.readFileSync(path.join(tmp, "log"), "utf8").split("\n")
  assert.ok(argv.includes("@/cfg/vt-apikey.header"))
  assert.ok(argv.includes("file=@-;filename=sample"))
  assert.ok(!argv.some(a => a.indexOf("sample;type") >= 0), "local path never reaches curl argv")
  assert.strictEqual(argv[argv.indexOf("--max-time") + 1], "30")
  assert.strictEqual(run(shell, S.classicUpload, [path.join(tmp, "nope"), "h", "u", "a", "1"]).code, 3)
})

// --- coding agents --------------------------------------------------------------
//
// These run with an isolated PATH: a few system tools linked into sysbin plus
// fakes, so agents installed on the test machine (e.g. /usr/bin/codex) are
// invisible. Every test gets its own HOME.

const MCP = "https://ai.virustotal.com/mcp"
const SKILL_MARKER = "/io.github.dsecuma.virustotal/agents/skills/virustotal"
function makeSysbin(dir, skip) {
  fs.mkdirSync(dir)
  for (const t of ["sh", "bash", "dash", "awk", "cat", "chmod", "cp", "date", "dirname", "grep", "head", "jq",
                   "ln", "mkdir", "mv", "readlink", "rm", "sleep", "timeout"]) {
    if (t === skip) continue
    const r = childProcess.spawnSync("sh", ["-c", "command -v \"$1\"", "sh", t], { encoding: "utf8" })
    const p = (r.stdout || "").trim()
    if (r.status === 0 && p.charAt(0) === "/") fs.symlinkSync(p, path.join(dir, t))
  }
}
const sysbin = path.join(tmp, "sysbin")
const sysbinNoJq = path.join(tmp, "sysbin-nojq")
makeSysbin(sysbin, "")
makeSysbin(sysbinNoJq, "jq")
const abin = path.join(tmp, "abin")         // fake system tools: mise, wl-copy
const omarchy = path.join(tmp, "omarchy")   // fake Omarchy checkout ($1); its bin/ holds Omarchy's tools
fs.mkdirSync(abin)
fs.mkdirSync(path.join(omarchy, "bin"), { recursive: true })
function script(file, lines) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, ["#!/bin/sh"].concat(lines).join("\n") + "\n", { mode: 0o755 })
}
script(path.join(abin, "mise"), [
  "printf 'mise %s\\n' \"$*\" >> \"${FAKE_MISE_LOG:-/dev/null}\"",
  "if [ \"$1\" = where ]; then",
  "  for p in $FAKE_MISE_HAS; do if [ \"$p\" = \"$2\" ]; then echo \"/mise/installs/$2\"; exit 0; fi; done",
  "  exit 1",
  "fi"
])
script(path.join(abin, "wl-copy"), ["cat > \"$FAKE_CLIP\"", "sleep 4 &"])
script(path.join(omarchy, "bin", "omarchy-agent-account-state"), [
  "[ \"$1 $2\" = \"homes claude\" ] || exit 2",
  "printf '%s' \"$FAKE_ACCOUNTS\""
])
// Launchers log: their name, the working directory, then each argument (NUL-separated).
for (const name of ["omarchy-launch-floating-terminal-with-presentation", "omarchy-launch-tui", "omarchy-agent-prompt", "omarchy-menu"]) {
  script(path.join(omarchy, "bin", name), ["printf '%s\\000' \"${0##*/}\" \"$(pwd)\" \"$@\" > \"$FAKE_LOG\""])
}

function freshHome(name) {
  const h = path.join(tmp, "homes", name)
  fs.rmSync(h, { recursive: true, force: true })
  fs.mkdirSync(h, { recursive: true })
  return h
}
// An agent the user installed: logs name, cwd, CLAUDE_CONFIG_DIR, then its arguments.
function installAgent(home, cmd) {
  script(path.join(home, ".local", "bin", cmd), [
    "printf '%s\\000' \"${0##*/}\" \"$(pwd)\" \"${CLAUDE_CONFIG_DIR-<unset>}\" \"$@\" > \"$FAKE_LOG\"",
    "exit ${FAKE_EXIT:-0}"
  ])
}
// Omarchy's mise launcher stub (bin/omarchy-mise-install): running it installs the agent.
function stubAgent(home, cmd, pkg) {
  script(path.join(home, ".local", "bin", cmd), [
    ": > \"$HOME/stub-ran\"",
    "export MISE_MINIMUM_RELEASE_AGE=0",
    "mise use -g --quiet \"" + pkg + "\" || exit 1",
    "exec mise x \"" + pkg + "\" -- \"" + cmd + "\" \"$@\""
  ])
}
function runA(shell, snippet, args, home, env) {
  const r = childProcess.spawnSync(shell, ["-c", snippet, "sh"].concat(args), {
    encoding: "utf8",
    env: Object.assign({ PATH: abin + ":" + sysbin, HOME: home, FAKE_LOG: path.join(home, "log") }, env || {})
  })
  return { code: r.status, out: r.stdout, err: r.stderr }
}
function logged(home) {
  const f = path.join(home, "log")
  return fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\0").slice(0, -1) : null
}

test("agent_state follows Omarchy's installed rule and never runs a stub", shell => {
  const home = freshHome(shell + "-state")
  const shims = path.join(home, ".local", "share", "mise", "shims")
  const extra = path.join(home, "extra")
  stubAgent(home, "claude", "claude")                       // stub, mise lacks it
  stubAgent(home, "codex", "codex")                         // stub, mise has it
  script(path.join(home, "opt", "opencode"), ["exit 0"])
  fs.symlinkSync(path.join(home, "opt", "opencode"), path.join(home, ".local", "bin", "opencode"))  // user symlink
  installAgent(home, "grok")                                // the user's own executable
  script(path.join(shims, "copilot"), ["exit 0"])           // shim, mise lacks it
  script(path.join(shims, "agy"), ["exit 0"])               // shim, mise has it
  script(path.join(extra, "crush"), ["exit 0"])             // elsewhere on PATH
  script(path.join(extra, "pi"), ["mise use -g pi", "exit 0"])  // a stub elsewhere on PATH
  const miseLog = path.join(home, "mise.log")
  const r = runA(shell, S.probeAgents, [omarchy, "all", "claude", "claude", "codex", "codex", "opencode", "opencode",
    "grok", "grok", "copilot", "copilot", "agy", "antigravity-cli", "crush", "crush", "pi", "pi", "hermes", "",
    "-rf", "x", "a b", "x", "../x", "x"],
    home, { PATH: abin + ":" + sysbin + ":" + extra, FAKE_MISE_HAS: "codex antigravity-cli", FAKE_MISE_LOG: miseLog })
  assert.strictEqual(r.code, 0, r.err)
  const st = {}
  for (const l of r.out.trim().split("\n")) {
    const f = l.split("\t")
    if (f[0] === "agent") st[f[1]] = f[2]
  }
  assert.deepStrictEqual(st, { claude: "stub", codex: "installed", opencode: "installed", grok: "installed",
    copilot: "absent", agy: "installed", crush: "installed", pi: "absent", hermes: "absent" })
  assert.ok(/^default\t$/m.test(r.out), r.out)
  assert.ok(!/claudehome/.test(r.out))
  assert.ok(!fs.existsSync(path.join(home, "stub-ran")), "a stub must never run")
  assert.ok(!/use/.test(fs.readFileSync(miseLog, "utf8")), "never mise use")
  // Without mise a stub stays a stub.
  const r2 = runA(shell, S.probeAgents, [omarchy, "all", "codex", "codex"], home, { PATH: sysbin })
  assert.ok(/^agent\tcodex\tstub$/m.test(r2.out), r2.out + r2.err)
})

test("probeAgents reads the default agent and Omarchy's Claude accounts", shell => {
  const home = freshHome(shell + "-probe")
  installAgent(home, "claude")
  const def = path.join(home, ".config", "omarchy", "defaults", "agent")
  fs.mkdirSync(path.dirname(def), { recursive: true })
  fs.writeFileSync(def, "claude\n")
  const env = { FAKE_ACCOUNTS: "main\t" + home + "/.claude\t0\nwork\t" + home + "/.config/claude-work\t1\n" }
  let r = runA(shell, S.probeAgents, [omarchy, "default", "claude", "claude", "codex", "codex"], home, env)
  assert.strictEqual(r.code, 0, r.err)
  assert.strictEqual(r.out, "default\tclaude\nagent\tclaude\tinstalled\ndefaultstate\tinstalled\n")
  r = runA(shell, S.probeAgents, [omarchy, "all", "claude", "claude"], home, env)
  assert.ok(!/claudehome/.test(r.out), "no account registry, no account list")
  const reg = path.join(home, ".local", "state", "omarchy", "agents", "accounts", "claude.json")
  fs.mkdirSync(path.dirname(reg), { recursive: true })
  fs.writeFileSync(reg, "{}")
  r = runA(shell, S.probeAgents, [omarchy, "all", "claude", "claude"], home, env)
  assert.ok(r.out.endsWith("agent\tclaude\tinstalled\ndefaultstate\tinstalled\nclaudehome\tmain\t" + home + "/.claude\t0\nclaudehome\twork\t"
    + home + "/.config/claude-work\t1\n"), r.out)
  r = runA(shell, S.probeAgents, [omarchy, "all", "claude", "claude"], home, Object.assign({ XDG_STATE_HOME: path.join(home, "st") }, env))
  assert.ok(!/claudehome/.test(r.out), "the registry follows XDG_STATE_HOME")
  for (const bad of ["cl aude\n", "$(touch pwned)\n", "../x\n", "-v\n", ""]) {
    fs.writeFileSync(def, bad)
    r = runA(shell, S.probeAgents, [omarchy, "default", "claude", "claude"], home, env)
    assert.strictEqual(r.out, "default\t\ndefaultstate\t\n", JSON.stringify(bad))
  }
  fs.writeFileSync(def, "codex")
  r = runA(shell, S.probeAgents, [omarchy, "default", "claude", "claude"], home, env)
  assert.strictEqual(r.out, "default\tcodex\ndefaultstate\tabsent\n", "no trailing newline; not in the pairs")
  // An agent this plugin version does not know is still checked (without a mise package).
  fs.writeFileSync(def, "newagent\n")
  installAgent(home, "newagent")
  r = runA(shell, S.probeAgents, [omarchy, "default", "claude", "claude"], home, env)
  assert.strictEqual(r.out, "default\tnewagent\ndefaultstate\tinstalled\n")
  stubAgent(home, "newagent", "newagent")
  r = runA(shell, S.probeAgents, [omarchy, "default", "claude", "claude"], home, Object.assign({ FAKE_MISE_HAS: "newagent" }, env))
  assert.strictEqual(r.out, "default\tnewagent\ndefaultstate\tstub\n", "a stub without a known package stays a stub")
  assert.ok(!fs.existsSync(path.join(home, "pwned")) && !fs.existsSync(path.join(home, "stub-ran")))
})

function probeMcp(shell, home, targets) {
  const args = [MCP, "virustotal", S.mcpJq, S.mcpAwk]
  for (const t of targets) args.push(t[0], t[1], t[2], t[3] || "-")
  const r = runA(shell, S.probeMcp, args, home)
  assert.strictEqual(r.code, 0, r.err)
  const out = {}
  for (const l of r.out.split("\n")) {
    if (!l) continue
    const f = l.split("\t")
    assert.strictEqual(f.length, 3, l)
    out[f[0]] = f[1] + "|" + f[2]
  }
  return out
}

test("probeMcp classifies JSON MCP configs", shell => {
  const home = freshHome(shell + "-mcpjson")
  const files = {
    ours: { theme: "dark", mcpServers: { github: { url: "https://api.github.com/mcp" }, virustotal: { type: "http", url: MCP } } },
    agy: { mcpServers: { virustotal: { serverUrl: MCP } } },
    copilot: { mcpServers: { virustotal: { type: "http", url: MCP, headers: {}, tools: ["*"] } } },
    headers: { mcpServers: { virustotal: { type: "http", url: MCP, headers: { Authorization: "Bearer x" } } } },
    renamed: { mcpServers: { "vt\tai,x": { url: "https://www.VirusTotal.com/api/v3/mcp" } } },
    stdio: { mcpServers: { vt: { command: "npx", args: ["-y", "@x/vt-mcp"] } } },
    otherUrl: { mcpServers: { virustotal: { url: MCP + "/" } } },
    stdioOurs: { mcpServers: { virustotal: { command: "vt-mcp" } } },
    none: { mcpServers: { github: { url: "https://api.github.com/mcp" } } },
    nokey: { theme: "dark" },
    array: [],
    badkey: { mcpServers: [] }
  }
  const targets = []
  for (const k of Object.keys(files)) {
    fs.writeFileSync(path.join(home, k + ".json"), JSON.stringify(files[k], null, 2))
    targets.push([k, "json", path.join(home, k + ".json"), "mcpServers"])
  }
  fs.writeFileSync(path.join(home, "jsonc.json"), "{\n  // comment\n  \"mcpServers\": {}\n}\n")
  fs.writeFileSync(path.join(home, "oc.json"), JSON.stringify({ mcp: { virustotal: { type: "remote", url: MCP } } }))
  fs.writeFileSync(path.join(home, "opencode.jsonc"), "{}")
  targets.push(["jsonc", "json", path.join(home, "jsonc.json"), "mcpServers"],
               ["missing", "json", path.join(home, "missing.json"), "mcpServers"],
               ["dir", "json", home, "mcpServers"],
               ["opencode", "json", path.join(home, "oc.json"), "mcp"],
               ["refuse", "exists", path.join(home, "opencode.jsonc")],
               ["norefuse", "exists", path.join(home, "nope.jsonc")],
               ["tab\tlabel", "json", path.join(home, "ours.json"), "mcpServers"])
  assert.deepStrictEqual(probeMcp(shell, home, targets), {
    ours: "ours|virustotal", agy: "ours|virustotal", copilot: "ours|virustotal", headers: "other|virustotal",
    renamed: "other|vt ai x", stdio: "other|vt", otherUrl: "other|virustotal", stdioOurs: "other|virustotal",
    none: "none|", nokey: "none|", array: "error|", badkey: "error|", jsonc: "error|", missing: "nofile|",
    dir: "error|", opencode: "ours|virustotal", refuse: "found|", norefuse: "nofile|"
  })
})

test("probeMcp classifies TOML MCP configs", shell => {
  const home = freshHome(shell + "-mcptoml")
  const u = "\"" + MCP + "\""
  const files = {
    ours: "model = \"gpt-5\"\n\n[mcp_servers.virustotal]\nurl = " + u + "\n\n[mcp_servers.github]\nurl = \"https://api.github.com/mcp\"\n",
    comment: "[mcp_servers.virustotal] # vt\nurl = " + u + " # codex mcp login virustotal\nenabled = true\n",
    literal: "[mcp_servers.virustotal]\nurl = '" + MCP + "'\n",
    quoted: "[mcp_servers.\"virustotal\"]\nurl = " + u + "\n",
    crlf: "[mcp_servers.virustotal]\r\nurl = " + u + "\r\n",
    bearer: "[mcp_servers.virustotal]\nurl = " + u + "\nbearer_token_env_var = \"VT_TOKEN\"\n",
    headersTable: "[mcp_servers.virustotal]\nurl = " + u + "\n\n[mcp_servers.virustotal.http_headers]\nAuthorization = \"Bearer x\"\n",
    headersInline: "[mcp_servers.virustotal]\nurl = " + u + "\nhttp_headers = { \"x-apikey\" = \"k\" }\n",
    renamed: "[mcp_servers.vt]\nurl = " + u + "\n",
    spaced: "[mcp_servers.\"virus,total\"]\nurl = \"https://www.virustotal.com/x\"\n",
    stdio: "[mcp_servers.vtlocal]\ncommand = \"vt-mcp\"\nargs = [\"--stdio\"]\n",
    otherUrl: "[mcp_servers.virustotal]\nurl = \"https://example.com/mcp\"\n",
    none: "[mcp_servers.github]\nurl = \"https://api.github.com/mcp\"\n",
    empty: "",
    inline: "[mcp_servers]\nvirustotal = { url = " + u + " }\n",
    dotted: "mcp_servers.virustotal.url = " + u + "\n",
    unrelated: "[profiles.virustotal]\nurl = " + u + "\n[mcp_servers.github]\nurl = \"https://api.github.com/mcp\"\n"
  }
  const targets = []
  for (const k of Object.keys(files)) {
    fs.writeFileSync(path.join(home, k + ".toml"), files[k])
    targets.push([k, "toml", path.join(home, k + ".toml")])
  }
  assert.deepStrictEqual(probeMcp(shell, home, targets), {
    ours: "ours|virustotal", comment: "ours|virustotal", literal: "ours|virustotal", quoted: "ours|virustotal",
    crlf: "ours|virustotal", bearer: "other|virustotal", headersTable: "other|virustotal",
    headersInline: "other|virustotal", renamed: "other|vt", spaced: "other|virus total", stdio: "other|vtlocal",
    otherUrl: "other|virustotal", none: "none|", empty: "none|", inline: "other|mcp_servers",
    dotted: "other|mcp_servers", unrelated: "none|"
  })
})

test("skillLinks links only missing or outdated copies of the skill", shell => {
  const home = freshHome(shell + "-skill")
  const src = path.join(home, "plugins", "io.github.dsecuma.virustotal", "agents", "skills", "virustotal")
  script(path.join(src, "SKILL.md"), [])
  const at = rel => path.join(home, rel, "virustotal")
  fs.mkdirSync(at(".claude/skills"), { recursive: true })                                  // the user's own skill
  fs.mkdirSync(path.join(home, ".codex/skills"), { recursive: true })
  fs.symlinkSync("/old/plugins" + SKILL_MARKER + "/", at(".codex/skills"))                // an older copy
  fs.mkdirSync(path.join(home, ".pi/agent/skills"), { recursive: true })
  fs.symlinkSync("/opt/someone/virustotal", at(".pi/agent/skills"))                       // someone else's
  fs.mkdirSync(path.join(home, ".hermes/profiles/work"), { recursive: true })
  fs.mkdirSync(path.join(home, ".hermes/profiles/my profile"), { recursive: true })
  fs.writeFileSync(path.join(home, ".hermes/profiles/not-a-dir"), "")
  const states = r => {
    assert.strictEqual(r.code, 0, r.err)
    const o = {}
    for (const l of r.out.trim().split("\n")) {
      const f = l.split("\t")
      o[f[0].slice(home.length + 1)] = f[1]
    }
    return o
  }
  const rels = [".agents/skills", ".claude/skills", ".codex/skills", ".pi/agent/skills", ".gemini/config/skills",
                ".hermes/skills", ".hermes/profiles/my profile/skills", ".hermes/profiles/work/skills"]
  const expect = values => {
    const o = {}
    rels.forEach((rel, i) => { o[rel + "/virustotal"] = values[i] })
    return o
  }
  const args = mode => [mode, src, "virustotal", SKILL_MARKER]
  assert.deepStrictEqual(states(runA(shell, S.skillLinks, args("status"), home)),
    expect(["missing", "user", "stale", "other", "missing", "missing", "missing", "missing"]))
  assert.ok(!fs.existsSync(path.join(home, ".agents")), "status changes nothing")
  assert.deepStrictEqual(states(runA(shell, S.skillLinks, args("link"), home)),
    expect(["ours", "user", "ours", "other", "ours", "ours", "ours", "ours"]))
  for (const rel of [".agents/skills", ".codex/skills", ".gemini/config/skills", ".hermes/skills",
                     ".hermes/profiles/my profile/skills", ".hermes/profiles/work/skills"]) {
    assert.strictEqual(fs.readlinkSync(at(rel)), src, rel)
  }
  assert.ok(!fs.lstatSync(at(".claude/skills")).isSymbolicLink(), "a real folder is never touched")
  assert.strictEqual(fs.readlinkSync(at(".pi/agent/skills")), "/opt/someone/virustotal")
  assert.deepStrictEqual(states(runA(shell, S.skillLinks, args("status"), home)),
    expect(["ours", "user", "ours", "other", "ours", "ours", "ours", "ours"]))
  assert.deepStrictEqual(states(runA(shell, S.skillLinks, args("unlink"), home)),
    expect(["missing", "user", "missing", "other", "missing", "missing", "missing", "missing"]))
  assert.ok(fs.statSync(at(".claude/skills")).isDirectory())
  assert.strictEqual(fs.readlinkSync(at(".pi/agent/skills")), "/opt/someone/virustotal")
  assert.ok(fs.existsSync(path.join(src, "SKILL.md")), "unlink never deletes the skill itself")
  fs.unlinkSync(path.join(src, "SKILL.md"))
  assert.strictEqual(runA(shell, S.skillLinks, args("link"), home).code, 3)
  assert.ok(!fs.existsSync(at(".agents/skills")), "nothing linked without SKILL.md")
  for (const bad of [["copy", src, "virustotal", SKILL_MARKER], ["link", "rel/dir", "virustotal", SKILL_MARKER],
                     ["link", src, "../x", SKILL_MARKER], ["link", src, "..", SKILL_MARKER], ["link", src, "virustotal", ""]]) {
    assert.strictEqual(runA(shell, S.skillLinks, bad, home).code, 2, JSON.stringify(bad))
  }
})

test("agentCli runs only allow-listed agents that are installed", shell => {
  const home = freshHome(shell + "-cli")
  installAgent(home, "claude")
  stubAgent(home, "codex", "codex")
  let r = runA(shell, S.agentCli, [omarchy, "", "claude", "claude", "mcp", "add", "--scope", "user", "virustotal", MCP],
    home, { CLAUDE_CONFIG_DIR: "/inherited" })
  assert.strictEqual(r.code, 0, r.err)
  assert.deepStrictEqual(logged(home), ["claude", home, "<unset>", "mcp", "add", "--scope", "user", "virustotal", MCP])
  r = runA(shell, S.agentCli, [omarchy, "/accounts/work dir", "claude", "claude", "mcp", "list"], home)
  assert.deepStrictEqual(logged(home), ["claude", home, "/accounts/work dir", "mcp", "list"])
  assert.strictEqual(runA(shell, S.agentCli, [omarchy, "", "claude", "claude", "mcp"], home, { FAKE_EXIT: "5" }).code, 5)
  fs.unlinkSync(path.join(home, "log"))
  assert.strictEqual(runA(shell, S.agentCli, [omarchy, "", "codex", "codex", "mcp", "add"], home).code, 3)
  assert.ok(!fs.existsSync(path.join(home, "stub-ran")), "a stub must never run")
  for (const bad of [[omarchy, "", "", "rm", "-rf", "/"], [omarchy, "", "opencode", "opencode", "mcp"],
                     [omarchy, "rel/dir", "claude", "claude", "mcp"], [omarchy, "/x", "codex", "codex", "mcp"],
                     [omarchy, "", "x", "--help"], [omarchy, "", "claude"]]) {
    assert.strictEqual(runA(shell, S.agentCli, bad, home).code, 2, JSON.stringify(bad))
  }
  assert.strictEqual(logged(home), null, "nothing ran")
})

test("jsonMcp merges one entry with a backup and never replaces one", shell => {
  const home = freshHome(shell + "-json")
  const entry = JSON.stringify({ url: MCP })
  const add = (f, extra) => runA(shell, S.jsonMcp, ["add", f, "mcpServers", "virustotal", entry, "{}", "", MCP], home, extra)
  const remove = f => runA(shell, S.jsonMcp, ["remove", f, "mcpServers", "virustotal", "null", "{}", "", MCP], home)
  const read = f => JSON.parse(fs.readFileSync(f, "utf8"))
  // A new file (and folder) from the template, private.
  const cursor = path.join(home, ".cursor", "mcp.json")
  let r = add(cursor)
  assert.strictEqual(r.code, 0, r.err)
  assert.strictEqual(r.out, "done\t\n")
  assert.deepStrictEqual(read(cursor), { mcpServers: { virustotal: { url: MCP } } })
  assert.strictEqual(mode(cursor), "600")
  assert.strictEqual(add(cursor).out, "exists\n")
  assert.deepStrictEqual(fs.readdirSync(path.dirname(cursor)), ["mcp.json"], "no backup for a new file")
  // Merge into an existing file: other keys stay, mode stays, backup kept.
  const cfg = path.join(home, "cfg.json")
  const before = JSON.stringify({ theme: "dark", mcpServers: { github: { url: "https://api.github.com/mcp" } } }, null, 2) + "\n"
  fs.writeFileSync(cfg, before)
  fs.chmodSync(cfg, 0o640)
  r = add(cfg)
  assert.strictEqual(r.code, 0, r.err)
  const m = /^done\t(.+)\n$/.exec(r.out)
  assert.ok(m && m[1].startsWith(cfg + ".bak-omarchy-virustotal-"), r.out)
  assert.strictEqual(fs.readFileSync(m[1], "utf8"), before)
  assert.strictEqual(mode(cfg), "640")
  assert.deepStrictEqual(read(cfg), { theme: "dark", mcpServers: { github: { url: "https://api.github.com/mcp" }, virustotal: { url: MCP } } })
  assert.strictEqual(add(cfg).out, "exists\n")
  // Remove only the entry, only while it is still exactly ours.
  r = remove(cfg)
  assert.strictEqual(r.code, 0, r.err)
  assert.ok(/^done\t.+\.bak-omarchy-virustotal-/.test(r.out), r.out)
  assert.deepStrictEqual(read(cfg), { theme: "dark", mcpServers: { github: { url: "https://api.github.com/mcp" } } })
  assert.strictEqual(remove(cfg).out, "none\n")
  assert.strictEqual(remove(path.join(home, "missing.json")).out, "none\n")
  assert.ok(!fs.existsSync(path.join(home, "missing.json")))
  for (const changed of [{ url: MCP, headers: { Authorization: "Bearer x" } }, { url: MCP + "?x" }, { serverUrl: "https://example.com" }]) {
    const text = JSON.stringify({ mcpServers: { virustotal: changed } })
    fs.writeFileSync(cfg, text)
    assert.strictEqual(remove(cfg).out, "changed\n", JSON.stringify(changed))
    assert.strictEqual(fs.readFileSync(cfg, "utf8"), text)
  }
  // Refusals leave the file alone and keep no backup.
  const backups = () => fs.readdirSync(home).filter(n => n.indexOf(".bak-") >= 0).length
  const nBackups = backups()
  for (const [text, code] of [["{\n  // comment\n}\n", 22], ["[]", 22], ["{\"mcpServers\": []}", 22], ["not json", 22]]) {
    fs.writeFileSync(cfg, text)
    assert.strictEqual(add(cfg).code, code, text)
    assert.strictEqual(fs.readFileSync(cfg, "utf8"), text)
  }
  fs.writeFileSync(cfg, "{}")
  fs.symlinkSync(cfg, path.join(home, "link.json"))
  assert.strictEqual(add(path.join(home, "link.json")).code, 21)
  fs.mkdirSync(path.join(home, "dir.json"))
  assert.strictEqual(add(path.join(home, "dir.json")).code, 21)
  assert.strictEqual(backups(), nBackups)
  assert.strictEqual(fs.readFileSync(cfg, "utf8"), "{}")
  // OpenCode: template for a new file, refused when opencode.jsonc exists.
  const oc = path.join(home, ".config", "opencode", "opencode.json")
  const jsonc = path.join(home, ".config", "opencode", "opencode.jsonc")
  const ocAdd = () => runA(shell, S.jsonMcp, ["add", oc, "mcp", "virustotal", JSON.stringify({ type: "remote", url: MCP }),
    JSON.stringify({ $schema: "https://opencode.ai/config.json" }), jsonc, MCP], home)
  r = ocAdd()
  assert.strictEqual(r.code, 0, r.err)
  assert.deepStrictEqual(read(oc), { $schema: "https://opencode.ai/config.json", mcp: { virustotal: { type: "remote", url: MCP } } })
  fs.unlinkSync(oc)
  fs.writeFileSync(jsonc, "{}")
  assert.strictEqual(ocAdd().code, 27)
  assert.ok(!fs.existsSync(oc))
  // No jq, bad arguments.
  assert.strictEqual(add(path.join(home, "x.json"), { PATH: abin + ":" + sysbinNoJq }).code, 20)
  for (const bad of [["merge", cfg, "mcpServers", "virustotal", entry, "{}", "", MCP], ["add", "rel.json", "mcpServers", "virustotal", entry, "{}", "", MCP],
                     ["add", cfg, "", "virustotal", entry, "{}", "", MCP], ["add", cfg, "mcpServers", "", entry, "{}", "", MCP]]) {
    assert.strictEqual(runA(shell, S.jsonMcp, bad, home).code, 2, JSON.stringify(bad))
  }
  assert.strictEqual(runA(shell, S.jsonMcp, ["add", path.join(home, "y.json"), "mcpServers", "virustotal", "{bad", "{}", "", MCP], home).code, 25)
  const leftovers = []
  for (const d of [home, path.dirname(cursor), path.dirname(oc)]) {
    for (const n of fs.readdirSync(d)) if (n.indexOf(".tmp-omarchy-virustotal") >= 0) leftovers.push(n)
  }
  assert.deepStrictEqual(leftovers, [])
  assert.ok(!fs.existsSync(path.join(home, "x.json")) && !fs.existsSync(path.join(home, "y.json")))
})

test("launchAgent opens sign-in terminals with safely quoted commands", shell => {
  const home = freshHome(shell + "-launch")
  installAgent(home, "codex")
  installAgent(home, "claude")
  stubAgent(home, "opencode", "opencode")
  fs.mkdirSync(path.join(home, "Work"))
  const replay = line => childProcess.spawnSync("bash", ["-c", line], { encoding: "utf8",
    env: { PATH: path.join(home, ".local", "bin") + ":" + sysbin, HOME: home, FAKE_LOG: path.join(home, "log") } })
  let r = runA(shell, S.launchAgent, [omarchy, "login", "", "codex", "codex", "mcp", "login", "virustotal"], home)
  assert.strictEqual(r.code, 0, r.err)
  let log = logged(home)
  assert.deepStrictEqual(log, ["omarchy-launch-floating-terminal-with-presentation", path.join(home, "Work"),
    "'codex' 'mcp' 'login' 'virustotal'"])
  replay(log[2])
  assert.deepStrictEqual(logged(home).slice(2), ["<unset>", "mcp", "login", "virustotal"])
  r = runA(shell, S.launchAgent, [omarchy, "login", "/acc/w x", "claude", "claude", "a b", "$(touch pwned)", "`id`;"], home)
  assert.strictEqual(r.code, 0, r.err)
  log = logged(home)
  assert.strictEqual(log[2], "CLAUDE_CONFIG_DIR='/acc/w x' 'claude' 'a b' '$(touch pwned)' '`id`;'")
  replay(log[2])
  assert.deepStrictEqual(logged(home).slice(2), ["/acc/w x", "a b", "$(touch pwned)", "`id`;"])
  assert.ok(!fs.existsSync(path.join(home, "pwned")) && !fs.existsSync(path.join(home, "Work", "pwned")))
  r = runA(shell, S.launchAgent, [omarchy, "session", "", "claude", "claude"], home, { CLAUDE_CONFIG_DIR: "/inherited" })
  assert.strictEqual(r.code, 0, r.err)
  assert.deepStrictEqual(logged(home), ["omarchy-launch-tui", path.join(home, "Work"), "--app-id=org.omarchy.agent", "claude"])
  r = runA(shell, S.launchAgent, [omarchy, "session", "/acc/work", "claude", "claude"], home)
  assert.deepStrictEqual(logged(home).slice(2), ["--app-id=org.omarchy.agent", "env", "CLAUDE_CONFIG_DIR=/acc/work", "claude"])
  fs.rmdirSync(path.join(home, "Work"))
  runA(shell, S.launchAgent, [omarchy, "session", "", "codex", "codex"], home)
  assert.strictEqual(logged(home)[1], home, "falls back to HOME without ~/Work")
  fs.unlinkSync(path.join(home, "log"))
  for (const bad of [["login", "", "codex", "codex", "it's"], ["login", "/it's", "claude", "claude"], ["session", "/x", "codex", "codex"],
                     ["session", "", "rm", "rm"], ["session", "rel", "claude", "claude"], ["menu", "", "codex", "codex"]]) {
    assert.strictEqual(runA(shell, S.launchAgent, [omarchy].concat(bad), home).code, 2, JSON.stringify(bad))
  }
  assert.strictEqual(runA(shell, S.launchAgent, [omarchy, "login", "", "opencode", "opencode", "mcp", "auth", "virustotal"], home).code, 3)
  assert.ok(!fs.existsSync(path.join(home, "stub-ran")), "a stub must never run")
  assert.strictEqual(logged(home), null, "nothing was launched")
})

test("agentPrompt and agentMenu hand over to Omarchy", shell => {
  const home = freshHome(shell + "-prompt")
  const prompt = "VirusTotal flagged a file.\n\n  name:  a b $(touch pwned) `id` 'q' \"d\" \\\n\nUse the virustotal skill."
  let r = runA(shell, S.agentPrompt, [omarchy, prompt], home)
  assert.strictEqual(r.code, 0, r.err)
  assert.deepStrictEqual(logged(home), ["omarchy-agent-prompt", home, prompt])
  assert.ok(!fs.existsSync(path.join(home, "pwned")))
  r = runA(shell, S.agentMenu, [omarchy], home)
  assert.strictEqual(r.code, 0, r.err)
  assert.deepStrictEqual(logged(home).slice(2), ["summon", "setup.default.agent"])
})

test("copyText feeds wl-copy without waiting for its background child", shell => {
  const home = freshHome(shell + "-copy")
  const clip = path.join(home, "clip")
  const text = "claude mcp add --scope user --transport http virustotal " + MCP + "\n  'q' $(touch pwned) \\n"
  const t0 = Date.now()
  const r = runA(shell, S.copyText, [text], home, { FAKE_CLIP: clip })
  assert.strictEqual(r.code, 0, r.err)
  assert.ok(Date.now() - t0 < 2500, "a forked wl-copy child must not hold the job open")
  assert.strictEqual(fs.readFileSync(clip, "utf8"), text)
  assert.ok(!fs.existsSync(path.join(home, "pwned")))
  assert.strictEqual(runA(shell, S.copyText, ["x"], home, { PATH: sysbin }).code, 127)
})

fs.rmSync(tmp, { recursive: true, force: true })
console.log("shells: " + shells.join(", ") + " | " + passed + " passed, " + failed + " failed")
process.exit(failed ? 1 : 0)
