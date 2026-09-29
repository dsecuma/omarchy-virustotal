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
  for (const name of ["startup", "credentialCheck", "dirCheck", "removeFile", "openUrl", "register", "hash", "notify"]) {
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
  assert.ok(/^downloads=\$HOME\/Descargas$/m.test(r.out), r.out)
  assert.strictEqual(mode(cfg), "700")
  assert.strictEqual(mode(state), "700")
  fs.writeFileSync(auth, "Authorization: Bearer vtai_x\n")
  r = run(shell, S.startup, [cfg, state, auth, path.join(base, "nope")])
  assert.ok(/^auth=present$/m.test(r.out))
  assert.ok(/^downloads=$/m.test(r.out))
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

fs.rmSync(tmp, { recursive: true, force: true })
console.log("shells: " + shells.join(", ") + " | " + passed + " passed, " + failed + " failed")
process.exit(failed ? 1 : 0)
