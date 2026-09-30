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
                      "probePlugins", "hashPlugin", "saveApiKey", "classicUpload"]) {
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
  assert.ok(/^5 \d+ \d+$/.test(clock[2]), "counts regular files outside .git: " + clock[2])
  assert.strictEqual(byId["dev.linked"][5], "link")
  assert.strictEqual(byId["dev.linked"][2].split(" ")[0], "1", "follows the top-level symlink")
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

fs.rmSync(tmp, { recursive: true, force: true })
console.log("shells: " + shells.join(", ") + " | " + passed + " passed, " + failed + " failed")
process.exit(failed ? 1 : 0)
