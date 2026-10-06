import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "Model.js" as Model
import "Scripts.js" as Scripts

// Background service for the VirusTotal plugin: the VirusTotal AI (VTAI)
// credential, lookups, consented uploads, analysis polling, history, the
// optional Downloads watcher, the optional installed-plugin scanner
// (PluginScanner.qml) and Omarchy's coding agents (AgentsManager.qml: the
// VirusTotal AI MCP server, the virustotal skill and "Ask <agent>").
//
// The shell mounts one instance per session (manifest kind "service"), so the
// bars on every monitor share this state and the watcher runs once.
// BarWidget.qml creates a private `standalone` copy only when its host bar
// offers no services; that copy never watches Downloads or notifies.
//
// All network traffic goes to https://ai.virustotal.com through curl. The
// agent token lives in ${XDG_CONFIG_HOME:-~/.config}/vtai/auth.header (mode
// 600, the location the VTAI guide uses so other VTAI clients can share it)
// and curl reads it with `-H @file`: the token never enters QML, logs or any
// process argv. Files are uploaded only from confirmUpload(), which the panel
// calls after an explicit consent dialog.
Item {
  id: root

  // Injected by the shell when it mounts the service.
  property var shell: null
  property var manifest: null
  property string omarchyPath: ""

  property bool standalone: false

  readonly property string pluginId: manifest && manifest.id ? String(manifest.id) : "io.github.dsecuma.virustotal"
  readonly property string pluginVersion: Model.safeVersion(manifest ? manifest.version : "")
  readonly property string apiBase: "https://ai.virustotal.com/api/v3"
  readonly property string userAgent: "omarchy-virustotal/" + pluginVersion

  readonly property string homeDir: String(Quickshell.env("HOME") || "").replace(/\/+$/, "")
  readonly property string configHome: absoluteEnv("XDG_CONFIG_HOME", homeDir + "/.config")
  readonly property string stateHome: absoluteEnv("XDG_STATE_HOME", homeDir + "/.local/state")
  readonly property string authDir: configHome + "/vtai"
  readonly property string authHeaderPath: authDir + "/auth.header"
  readonly property string authHeaderDisplay: Model.displayPath(authHeaderPath, homeDir)
  readonly property string configDir: configHome + "/omarchy-virustotal"
  readonly property string stateDir: stateHome + "/omarchy-virustotal"
  // Optional classic VirusTotal API key for the plugin scanner, stored as a
  // curl header file (mode 600) so the key never enters argv or QML state.
  readonly property string apiKeyPath: configDir + "/vt-apikey.header"
  readonly property string apiKeyDisplay: Model.displayPath(apiKeyPath, homeDir)
  readonly property string classicApiBase: "https://www.virustotal.com/api/v3"
  // Same location omarchy-plugin-add installs to.
  readonly property string pluginsDir: homeDir + "/.config/omarchy/plugins"

  // --- startup ---------------------------------------------------------------
  property bool ready: false
  property bool dirsReady: false
  property string missingTools: ""

  // --- account ---------------------------------------------------------------
  // checking | missing | present (file exists, not verified) | valid | invalid
  property string credentialState: "checking"
  readonly property bool connected: credentialState === "present" || credentialState === "valid"
  property bool connecting: false
  property string connectError: ""
  property bool accountBusy: false
  property bool checkingAccess: false
  property bool accessChecked: false
  property string accountMessage: ""

  // --- scans -----------------------------------------------------------------
  property bool busy: false
  property string busyLabel: ""
  property var result: null
  property string errorMessage: ""
  // Input the user tried to check before connecting; runs after connect().
  property string pendingScan: ""
  property bool panelVisible: false

  // --- upload analysis -------------------------------------------------------
  property bool analysisActive: false
  property bool analysisStalled: false
  property string analysisId: ""
  property string analysisSha: ""
  property int analysisPolls: 0
  property bool pollInFlight: false
  readonly property int maxPolls: 24

  // --- history and the watcher alert (persisted) -----------------------------
  property var history: []
  property var lastAlert: null
  property bool alertAcknowledged: true

  // --- settings (persisted) and the Downloads watcher ------------------------
  property bool watcherEnabled: false
  property bool notifyAll: false
  property bool watcherAvailable: true
  property string watcherMessage: ""
  property string downloadsDir: ""
  readonly property string downloadsDisplay: Model.displayPath(downloadsDir, homeDir)
  property bool downloadsDirExists: false
  property var downloadsModel: null
  property var recentDownloads: []
  readonly property bool watcherActive: watcherEnabled && !standalone && ready && connected
    && watcherAvailable && downloadsDirExists
  property bool watchBusy: false
  property int watchQueueLength: 0

  // --- installed-plugin scanner (persisted settings) -------------------------
  property bool pluginScanEnabled: false
  property bool pluginAutoUpload: false
  property string pluginBackend: "vtai"
  property int maxParallel: 4
  property int classicPerMin: 4
  property int classicPerDay: 500
  property string scanMissingTools: ""
  // missing | present | invalid
  property string apiKeyState: "missing"
  property bool apiKeyBusy: false
  property string apiKeyMessage: ""
  readonly property bool pluginBackendReady: pluginBackend === "classic" ? apiKeyState === "present" : connected
  readonly property bool pluginScannerActive: pluginScanEnabled && !standalone && ready && missingTools === ""
    && scanMissingTools === "" && pluginBackendReady
  property alias scanner: pluginScanner

  // --- coding agents (persisted settings) ------------------------------------
  // "Ask <agent>" buttons on results; the auto-approve warning shows once.
  property bool agentButtons: true
  property bool agentHandoffAck: false
  property alias agents: agentsManager

  readonly property string barStatus: {
    if (lastAlert && !alertAcknowledged) return lastAlert.stats && lastAlert.stats.malicious > 0 ? "malicious" : "suspicious"
    if (busy || connecting || (analysisActive && !analysisStalled)) return "busy"
    return "idle"
  }

  // --- theme -----------------------------------------------------------------
  // Yellow for "suspicious" and other warnings in the panel and the bar dot.
  // Omarchy has no warning colour token, so this is the theme's own yellow
  // when it has a real one (Model.themeYellow), else an amber that is lighter
  // on dark themes and darker on light ones.
  property string themeYellow: ""
  readonly property color warningColor: themeYellow !== "" ? themeYellow
    : Qt.hsla(0.11, 0.85, Color.foreground.hslLightness > 0.5 ? 0.62 : 0.4, 1)
  // Omarchy reads colors.toml at startup and gets theme switches over IPC
  // after replacing the theme directory, so a file watch would go stale:
  // re-read the file whenever the base palette changes instead.
  readonly property string paletteKey: String(Color.foreground) + String(Color.background)
    + String(Color.accent) + String(Color.urgent)
  onPaletteKeyChanged: themeColorsFile.reload()

  // --- private ---------------------------------------------------------------
  property int _openPanels: 0
  property int _scanSeq: 0
  property int _analysisGen: 0
  property var _analysisBase: null
  property string _lastConfigText: ""
  property string _lastStateText: ""
  property bool _configLoaded: false
  property bool _stateLoaded: false
  property bool _configDirty: false
  property bool _stateDirty: false
  property int _watchGen: 0
  property var _seen: null
  property var _queue: []
  property var _sessionShas: ({})
  property real _pauseUntil: 0
  property real _lastWatchLookup: 0
  property var _uploadFiles: []

  Component.onCompleted: startup()
  Component.onDestruction: {
    for (var i = 0; i < root._uploadFiles.length; i++)
      Quickshell.execDetached(["sh", "-c", Scripts.removeUpload, "sh", root._uploadFiles[i]])
  }

  // ===========================================================================
  // Process plumbing
  // ===========================================================================

  function absoluteEnv(name, fallback) {
    var v = String(Quickshell.env(name) || "")
    return v.charAt(0) === "/" ? v.replace(/\/+$/, "") : fallback
  }

  // Run argv once; callback(exitCode, stdout, stderr). Exit 124 = watchdog.
  // `stdinText` (optional) is written to the process and stdin is closed;
  // secrets travel this way instead of argv.
  function runJob(argv, timeoutMs, callback, stdinText) {
    var job = jobComponent.createObject(root, { argv: argv, timeoutMs: timeoutMs || 60000, callback: callback,
                                                stdinText: stdinText === undefined || stdinText === null ? "" : String(stdinText) })
    if (!job) Qt.callLater(function() { callback(125, "", "") })
  }

  // Scripts.* snippets: untrusted values only travel as positional parameters.
  function sh(script, args, timeoutMs, callback) {
    root.runJob(["sh", "-c", script, "sh"].concat(args || []), timeoutMs, callback)
  }

  // One HTTPS request to VTAI (or, with opts.backend === "classic", to the
  // classic VirusTotal API with the saved API key); callback({ exitCode,
  // http, body, json }).
  function api(method, path, opts, callback) {
    var o = opts || {}
    var classic = o.backend === "classic"
    if (root.missingTools.split(" ").indexOf("curl") >= 0) {
      Qt.callLater(function() { callback({ exitCode: 127, http: 0, body: "", json: null }) })
      return
    }
    var maxTime = o.maxTime || 40
    var argv = ["curl", "-sS", "--proto", "=https", "--connect-timeout", "10", "--max-time", String(maxTime),
                "-A", root.userAgent, "-H", "@" + (classic ? root.apiKeyPath : root.authHeaderPath), "-H", "Accept: application/json",
                "-w", Model.CURL_WRITE_OUT]
    if (method === "DELETE") argv.push("-X", "DELETE")
    // Request bodies can carry user data (a checked URL may hold a token in its
    // query or path), so they travel on stdin, never in the visible argv.
    var body = ""
    if (o.json !== undefined) {
      body = JSON.stringify(o.json)
      argv.push("-H", "Content-Type: application/json", "--data-binary", "@-")
    } else if (o.file) {
      // Standard (non-private) submission: the panel asked for consent first.
      argv.push("-H", "Content-Type: application/octet-stream", "-H", "X-VTAI-Consent: standard-v1",
                "--data-binary", "@" + o.file)
    }
    argv.push((classic ? root.classicApiBase : root.apiBase) + path)
    root.runJob(argv, (maxTime + 20) * 1000, function(code, out) {
      var parsed = Model.parseCurlOutput(out)
      var res = { exitCode: code, http: parsed.http, body: parsed.body, retryAfter: parsed.retryAfter, json: Model.parseJson(parsed.body) }
      // curl cannot read a deleted credential file either; resync the state.
      if (!res.http && !classic) root.refreshCredentialPresence()
      callback(res)
    }, body)
  }

  // callback(exitCode, size, sha256); see Scripts.hash for the exit codes.
  function hashFile(path, quietSeconds, maxBytes, callback) {
    root.sh(Scripts.hash, [path, String(quietSeconds || 0), String(maxBytes || 0)], 300000, function(code, out) {
      var m = /^(\d+) ([a-f0-9]{64})$/.exec(String(out || "").trim())
      if (code === 0 && m) callback(0, Number(m[1]), m[2])
      else callback(code === 0 ? 5 : code, -1, "")
    })
  }

  function prepareUploadFile(path, sha, callback) {
    root.sh(Scripts.prepareUpload, [path, sha], 300000, function(code, out) {
      var m = /^(\d+)\t(\/tmp\/omarchy-vt-upload\.[A-Za-z0-9]{8}\/sample)\n?$/.exec(String(out || ""))
      if (code !== 0 || !m) {
        callback(code === 0 ? 5 : code, -1, "")
        return
      }
      root._uploadFiles = root._uploadFiles.concat([m[2]])
      callback(0, Number(m[1]), m[2])
    })
  }

  function removeUploadFile(path) {
    if (root._uploadFiles.indexOf(path) < 0) return
    root.sh(Scripts.removeUpload, [path], 10000, function(code) {
      if (code === 0) root._uploadFiles = root._uploadFiles.filter(function(p) { return p !== path })
    })
  }

  Component {
    id: jobComponent

    Item {
      id: job

      property var argv: []
      property int timeoutMs: 60000
      property var callback: null
      property string stdinText: ""
      property bool finished: false
      property string savedOut: ""
      property string savedErr: ""

      function finish(code, exited) {
        if (job.finished) return
        job.finished = true
        watchdog.stop()
        var cb = job.callback
        job.callback = null
        var out = String(outCollector.text || job.savedOut || "")
        var err = String(errCollector.text || job.savedErr || "")
        try {
          if (cb) cb(code, out, err)
        } catch (e) {
          console.warn("[virustotal] " + e)
        }
        if (exited) job.destroy()
        else reaper.start()
      }

      Process {
        id: proc
        command: job.argv
        stdinEnabled: job.stdinText !== ""
        onStarted: {
          if (job.stdinText === "") return
          write(job.stdinText)
          job.stdinText = ""
          stdinEnabled = false
        }
        stdout: StdioCollector { id: outCollector; waitForEnd: true; onStreamFinished: job.savedOut = text }
        stderr: StdioCollector { id: errCollector; waitForEnd: true; onStreamFinished: job.savedErr = text }
        // Deferred so the collectors can deliver their final text first.
        onExited: function(exitCode) {
          Qt.callLater(function() {
            if (job.finished) job.destroy()
            else job.finish(exitCode, true)
          })
        }
      }

      // curl and the scripts have their own timeouts; this only catches a
      // process that never exits or never starts.
      Timer {
        id: watchdog
        interval: job.timeoutMs
        running: true
        onTriggered: {
          proc.running = false
          job.finish(124, false)
        }
      }

      Timer {
        id: reaper
        interval: 10000
        onTriggered: job.destroy()
      }

      Component.onCompleted: proc.running = true
    }
  }

  // ===========================================================================
  // Startup and persistence
  // ===========================================================================

  function startup() {
    root.sh(Scripts.startup, [root.configDir, root.stateDir, root.authHeaderPath, root.configHome + "/user-dirs.dirs", root.apiKeyPath], 15000,
      function(code, out) {
        var info = Model.parseKeyValues(out)
        root.missingTools = info.missing || ""
        root.scanMissingTools = info.scanmissing || ""
        if (root.apiKeyState !== "invalid" || info.apikey !== "present") root.apiKeyState = info.apikey === "present" ? "present" : "missing"
        if (root.credentialState === "checking")
          root.credentialState = info.auth === "present" ? "present" : "missing"
        root.downloadsDir = Model.resolveDownloadsDir(info.downloads, root.homeDir, Quickshell.env("XDG_DOWNLOAD_DIR"))
        root.dirsReady = true
        root.ready = true
        root.flushWrites()
        root.checkDownloadsDir()
      })
  }

  FileView {
    id: configFile
    path: root.dirsReady ? root.configDir + "/config.json" : ""
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyConfig(configFile.text(), false)
    onLoadFailed: root.applyConfig("", true)
    onFileChanged: configFile.reload()
  }

  FileView {
    id: stateFile
    path: root.dirsReady ? root.stateDir + "/history.json" : ""
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyState(stateFile.text(), false)
    onLoadFailed: root.applyState("", true)
    onFileChanged: stateFile.reload()
  }

  // Read only, for themeYellow; the same file Omarchy's Color singleton reads.
  FileView {
    id: themeColorsFile
    path: String(Color.currentThemePath || root.homeDir + "/.local/state/omarchy/current/theme") + "/colors.toml"
    watchChanges: false
    printErrors: false
    onLoaded: root.themeYellow = Model.themeYellow(themeColorsFile.text())
    onLoadFailed: root.themeYellow = ""
  }

  function applyConfig(text, failed) {
    if (root._configDirty) return             // a local change is about to be written
    if (failed && root._configLoaded) return  // file vanished: keep the in-memory copy
    root._configLoaded = true
    var t = String(text || "")
    if (t !== "" && t === root._lastConfigText) return  // echo of our own write
    root._lastConfigText = t
    var c = Model.parseConfig(t)
    root.watcherEnabled = c.watcherEnabled
    root.notifyAll = c.notifyAll
    root.pluginScanEnabled = c.pluginScanEnabled
    root.pluginAutoUpload = c.pluginAutoUpload
    root.pluginBackend = c.pluginBackend
    root.maxParallel = c.maxParallel
    root.classicPerMin = c.classicPerMin
    root.classicPerDay = c.classicPerDay
    root.agentButtons = c.agentButtons
    root.agentHandoffAck = c.agentHandoffAck
  }

  function saveConfig() {
    var t = Model.serializeConfig({ watcherEnabled: root.watcherEnabled, notifyAll: root.notifyAll,
                                    pluginScanEnabled: root.pluginScanEnabled, pluginAutoUpload: root.pluginAutoUpload,
                                    pluginBackend: root.pluginBackend, maxParallel: root.maxParallel,
                                    classicPerMin: root.classicPerMin, classicPerDay: root.classicPerDay,
                                    agentButtons: root.agentButtons, agentHandoffAck: root.agentHandoffAck })
    root._lastConfigText = t
    if (!root.dirsReady) {
      root._configDirty = true
      return
    }
    root._configDirty = false
    configFile.setText(t)
  }

  function applyState(text, failed) {
    if (root._stateDirty) return
    if (failed && root._stateLoaded) return
    root._stateLoaded = true
    var t = String(text || "")
    if (t !== "" && t === root._lastStateText) return
    root._lastStateText = t
    var s = Model.parseState(t)
    root.history = s.entries
    root.lastAlert = s.alert
    root.alertAcknowledged = s.alertAcknowledged
  }

  function saveState() {
    var t = Model.serializeState(root.history, root.lastAlert, root.alertAcknowledged)
    root._lastStateText = t
    if (!root.dirsReady) {
      root._stateDirty = true
      return
    }
    root._stateDirty = false
    stateFile.setText(t)
  }

  function flushWrites() {
    if (root._configDirty) root.saveConfig()
    if (root._stateDirty) root.saveState()
  }

  // ===========================================================================
  // Account
  // ===========================================================================

  function refreshCredentialPresence() {
    if (!root.ready || root.connecting || root.accountBusy) return
    root.sh(Scripts.credentialCheck, [root.authHeaderPath], 10000, function(code) {
      if (root.connecting || root.accountBusy) return
      var present = code === 0
      if (present && (root.credentialState === "missing" || root.credentialState === "checking")) {
        root.credentialState = "present"
        root.accessChecked = false
      } else if (!present && root.credentialState !== "missing") {
        root.credentialState = "missing"
        root.accessChecked = false
      }
    })
  }

  // GET /agents/me/access is free: it spends no lookup quota.
  function checkAccess(manual) {
    if (root.checkingAccess || root.connecting || root.accountBusy) return
    if (root.credentialState === "missing" || root.credentialState === "checking") return
    root.checkingAccess = true
    if (manual) root.accountMessage = ""
    root.api("GET", "/agents/me/access", {}, function(res) {
      root.checkingAccess = false
      if (res.http === 200) {
        var status = res.json && res.json.status ? String(res.json.status) : "active"
        root.accessChecked = true
        if (status === "active") {
          root.credentialState = "valid"
          if (manual) root.accountMessage = "The token is active."
        } else {
          root.credentialState = "invalid"
          root.accountMessage = "VirusTotal AI reports this token as " + Model.truncate(status, 40) + "."
        }
        return
      }
      if (res.http === 401 || res.http === 403) {
        root.accessChecked = true
        root.credentialState = "invalid"
        if (manual) root.accountMessage = "VirusTotal AI rejected the saved token."
        return
      }
      if (manual) root.accountMessage = Model.apiError(res.http, res.json, res.exitCode, res.retryAfter).message
    })
  }

  // One-time agent registration (explicit user action from the panel).
  function connect() {
    if (root.connecting || root.accountBusy || !root.ready) return
    root.connectError = ""
    root.accountMessage = ""
    root.connecting = true
    root.sh(Scripts.register, [root.authDir, root.authHeaderPath, Model.registerBody(root.pluginVersion),
                               root.apiBase + "/agents/register", root.userAgent], 60000,
      function(code, out) {
        root.connecting = false
        if (code !== 0) {
          root.connectError = Model.registerErrorMessage(code, out)
          return
        }
        root.credentialState = "present"
        root.accessChecked = false
        root.accountMessage = /exists/.test(out)
          ? "Using the VirusTotal AI token already saved in " + root.authHeaderDisplay + "."
          : "Connected. The token is saved in " + root.authHeaderDisplay + "."
        root.checkAccess(false)
        var pending = root.pendingScan
        root.pendingScan = ""
        if (pending !== "") root.scan(pending, "manual")
      })
  }

  // Revoke the token server-side, then delete the local file. `then` runs
  // after a successful disconnect (used by reconnect()).
  function disconnect(then) {
    if (root.accountBusy || root.connecting) return
    root.accountBusy = true
    root.accountMessage = ""
    root.connectError = ""
    root.api("DELETE", "/agents/me/token", {}, function(res) {
      var revoked = res.http === 204 || res.http === 200
      if (!revoked && res.http !== 401 && res.http !== 403) {
        root.accountBusy = false
        root.accountMessage = "Could not revoke the token: " + Model.apiError(res.http, res.json, res.exitCode, res.retryAfter).message
        return
      }
      root.sh(Scripts.removeFile, [root.authHeaderPath], 10000, function(code) {
        root.accountBusy = false
        if (code !== 0) {
          root.credentialState = "invalid"
          root.accountMessage = "The token was revoked, but " + root.authHeaderDisplay + " could not be deleted."
          return
        }
        root.credentialState = "missing"
        root.accessChecked = false
        root.accountMessage = revoked
          ? "Disconnected. The token was revoked and deleted."
          : "Disconnected. The token was no longer valid and has been deleted."
        if (typeof then === "function") then()
      })
    })
  }

  function reconnect() {
    root.disconnect(function() { root.connect() })
  }

  function noteAuthError(e) {
    if (e && e.kind === "auth") {
      root.credentialState = "invalid"
      root.accessChecked = true
    }
  }

  // ===========================================================================
  // Scans
  // ===========================================================================

  function setBusy(label) {
    root.busy = true
    root.busyLabel = label
    root.errorMessage = ""
  }

  function clearBusy() {
    root.busy = false
    root.busyLabel = ""
  }

  function fail(message) {
    root.clearBusy()
    root.errorMessage = message
  }

  function reportError(res) {
    var e = Model.apiError(res.http, res.json, res.exitCode, res.retryAfter)
    root.noteAuthError(e)
    root.errorMessage = e.message
    return e
  }

  function isShowing(sha) {
    return !!(sha && root.result && root.result.sha256 === sha)
  }

  function fileExtra(r) {
    return { name: r.name, path: r.path, sha256: r.sha256, size: r.size, source: r.source || "manual" }
  }

  function showResult(r) {
    r.time = r.time || Date.now()
    root.result = r
    root.recordHistory(r)
  }

  // Look up a URL, domain, IP, hash or local file. Files are hashed locally;
  // only the SHA-256 is sent. Returns false when nothing was started.
  function scan(input, source) {
    if (root.busy) return false
    var raw = String(input === undefined || input === null ? "" : input).trim()
    var target = Model.detectTargetType(raw, root.homeDir)
    root.errorMessage = ""
    if (!target.kind) {
      root.errorMessage = target.error
      return false
    }
    if (!root.ready) {
      root.errorMessage = "Still starting up. Try again in a moment."
      return false
    }
    if (!root.connected) {
      root.pendingScan = raw
      return false
    }
    root.pendingScan = ""
    var seq = ++root._scanSeq
    var src = source || "manual"
    if (target.kind !== "file") {
      root.lookup(target.kind, target.value, target.value, { source: src }, seq)
      return true
    }
    var path = target.value
    var name = Model.basename(path)
    root.setBusy("Hashing \u201c" + Model.truncate(name, 60) + "\u201d\u2026")
    root.hashFile(path, 0, 0, function(code, size, sha) {
      if (seq !== root._scanSeq) return
      if (code !== 0) {
        root.fail(Model.hashErrorMessage(code, path))
        return
      }
      root.lookup("file", sha, path, { name: name, path: path, sha256: sha, size: size, source: src }, seq)
    })
    return true
  }

  function lookup(kind, query, target, extra, seq) {
    var req = Model.requestFor(kind, query)
    root.setBusy("Checking the " + Model.kindNoun(kind) + " with VirusTotal\u2026")
    root.api(req.method, req.path, { json: req.json }, function(res) {
      if (seq !== root._scanSeq) return
      root.clearBusy()
      var r = null
      if (res.http === 200 && res.json && res.json.data) r = Model.resultFromReport(kind, target, res.json.data, extra)
      else if (res.http === 404) r = Model.notFoundResult(kind, target, extra)
      if (!r) {
        root.reportError(res)
        return
      }
      r.time = Date.now()
      root.showResult(r)
    })
  }

  // Upload the current not-found file. Only the panel calls this, after the
  // user accepted the standard-submission consent dialog.
  function confirmUpload() {
    var r = root.result
    if (!r || !r.canUpload || root.busy || !root.connected) return
    var seq = ++root._scanSeq
    var base = Model.copy(r)
    var name = r.name || Model.basename(r.path)
    root.setBusy("Uploading \u201c" + Model.truncate(name, 60) + "\u201d\u2026")
    // Verify a private snapshot, then send those exact bytes, even if the
    // original path is replaced while the request is being prepared.
    root.prepareUploadFile(base.path, base.sha256, function(code, size, snapshot) {
      if (seq !== root._scanSeq || !root.connected || root.accountBusy) {
        root.removeUploadFile(snapshot)
        if (seq === root._scanSeq) root.fail("The connection changed before the upload. Connect and try again.")
        return
      }
      if (code === 8) {
        root.fail("The file is larger than the 32 MB upload limit.")
        return
      }
      if (code === 6) {
        root.fail("The file changed after it was checked. Check it again before uploading.")
        return
      }
      if (code !== 0) {
        root.fail(Model.hashErrorMessage(code, base.path))
        return
      }
      root.api("POST", "/submissions/" + base.sha256, { file: snapshot, maxTime: 130 }, function(res) {
        root.removeUploadFile(snapshot)
        if (seq !== root._scanSeq) return
        root.clearBusy()
        root.handleSubmission(base, res)
      })
    })
  }

  function handleSubmission(base, res) {
    var j = res.json
    if ((res.http === 200 || res.http === 202) && j && typeof j === "object" && typeof j.status === "string") {
      root.applyReceipt(base, j)
      return
    }
    if (!res.http) {
      // The bytes may or may not have reached VirusTotal. Never resend
      // automatically; "Check status" recovers the receipt instead.
      root.showResult(Model.unknownSubmissionResult(base,
        "The connection dropped during the upload. Check its status before uploading again."))
      return
    }
    var d = j && j.detail && typeof j.detail === "object" && !Array.isArray(j.detail) ? j.detail : null
    if (d && d.submission && typeof d.submission === "object" && typeof d.submission.status === "string") {
      root.applyReceipt(base, d.submission)
      return
    }
    root.reportError(res)
  }

  function applyReceipt(base, s) {
    var b = Model.copy(base)
    if (/^[a-f0-9]{64}$/.test(String(s.sha256 || ""))) b.sha256 = String(s.sha256)
    b.canUpload = false
    var extra = root.fileExtra(b)
    if (s.status === "exists") {
      if (s.report && s.report.data) {
        root.showResult(Model.resultFromReport("file", b.target, s.report.data, extra))
        return
      }
      root.lookup("file", b.sha256, b.target, extra, ++root._scanSeq)
      return
    }
    if (s.status === "submitted" && s.analysis_id) {
      root.startAnalysis(b, String(s.analysis_id), s.next_poll_after_seconds)
      return
    }
    root.showResult(Model.unknownSubmissionResult(b, s.status === "submission_unknown"
      ? "VirusTotal has not confirmed this upload yet. Check its status in a minute instead of uploading again."
      : ""))
  }

  // Recover a receipt: GET /submissions/{sha256} never resends the file.
  function checkSubmission() {
    var r = root.result
    if (!r || !r.sha256 || root.busy) return
    if (!root.connected) {
      root.errorMessage = "Connect to VirusTotal AI first."
      return
    }
    var seq = ++root._scanSeq
    var base = Model.copy(r)
    root.setBusy("Checking the upload status\u2026")
    root.api("GET", "/submissions/" + r.sha256, {}, function(res) {
      if (seq !== root._scanSeq) return
      root.clearBusy()
      var j = res.json
      if (res.http === 200 && j && typeof j === "object" && typeof j.status === "string") {
        root.applyReceipt(base, j)
        return
      }
      if (res.http === 404) {
        // No receipt for this identity. That does not prove the file never
        // reached VirusTotal, so look for a report before offering an upload.
        root.lookup("file", base.sha256, base.target, root.fileExtra(base), ++root._scanSeq)
        return
      }
      root.reportError(res)
    })
  }

  // ===========================================================================
  // Analysis polling
  // ===========================================================================

  Timer {
    id: pollTimer
    repeat: false
    onTriggered: root.pollAnalysis()
  }

  function schedulePoll(ms) {
    pollTimer.interval = Math.max(1000, ms)
    pollTimer.restart()
  }

  function startAnalysis(base, id, nextSeconds) {
    var b = Model.copy(base)
    b.analysisId = id
    root._analysisGen++
    root._analysisBase = b
    root.analysisId = id
    root.analysisSha = b.sha256
    root.analysisPolls = 0
    root.analysisActive = true
    root.analysisStalled = false
    root.showResult(Model.analyzingResult(b, id, 0, root.maxPolls, ""))
    root.schedulePoll(Model.pollDelayMs(0, nextSeconds))
  }

  function stopAnalysis() {
    pollTimer.stop()
    root._analysisGen++
    root._analysisBase = null
    root.analysisId = ""
    root.analysisSha = ""
    root.analysisPolls = 0
    root.analysisActive = false
    root.analysisStalled = false
  }

  function pollAnalysis() {
    if (!root.analysisActive) return
    if (root.pollInFlight) {
      root.schedulePoll(2000)
      return
    }
    var gen = root._analysisGen
    var base = root._analysisBase
    var id = root.analysisId
    root.pollInFlight = true
    root.api("GET", "/analyses/" + encodeURIComponent(id), {}, function(res) {
      root.pollInFlight = false
      if (gen !== root._analysisGen) return
      root.analysisPolls++
      var j = res.json
      if (res.http === 200 && j && typeof j === "object") {
        // Top-level status decides: "pending" can coexist with
        // analysis_status "completed" while results are verified.
        if (j.status === "completed") root.completeAnalysis(Model.resultFromAnalysis(base, j, Date.now()))
        else root.updateAnalysis(base, j.pending_reason, j.next_poll_after_seconds)
        return
      }
      var e = Model.apiError(res.http, j, res.exitCode, res.retryAfter)
      if (e.kind === "auth" || res.http === 404) {
        root.noteAuthError(e)
        var lost = Model.unknownSubmissionResult(base, e.kind === "auth" ? e.message
          : "VirusTotal no longer tracks this analysis. Check the upload status instead.")
        var showing = root.isShowing(base.sha256)
        root.stopAnalysis()
        if (showing) root.result = lost
        return
      }
      if (root.analysisPolls >= root.maxPolls) {
        root.updateAnalysis(base, "", 0)
        return
      }
      root.schedulePoll(Math.max(e.retryAfter || 0, e.kind === "rate_limit" ? 10 : 15) * 1000)
    })
  }

  function updateAnalysis(base, reason, nextSeconds) {
    if (root.isShowing(base.sha256))
      root.result = Model.analyzingResult(base, root.analysisId, root.analysisPolls, root.maxPolls, reason)
    if (root.analysisPolls >= root.maxPolls) {
      root.analysisStalled = true
      return
    }
    root.schedulePoll(Model.pollDelayMs(root.analysisPolls, nextSeconds))
  }

  function completeAnalysis(r) {
    var showing = root.isShowing(r.sha256)
    root.stopAnalysis()
    r.time = Date.now()
    root.recordHistory(r)
    if (showing) root.result = r
    if (!root.panelVisible || !showing) root.notifyResult(r)
  }

  // One more poll after the automatic budget ran out.
  function checkAgain() {
    if (!root.analysisActive || root.pollInFlight) return
    root.analysisStalled = false
    root.pollAnalysis()
  }

  // ===========================================================================
  // History, alert, settings, panel lifecycle
  // ===========================================================================

  function recordHistory(r) {
    root.history = Model.addHistory(root.history, r, r.time || Date.now(), Model.HISTORY_LIMIT)
    root.saveState()
  }

  function showHistoryEntry(e) {
    if (!e || root.busy) return
    root.errorMessage = ""
    root.pendingScan = ""
    root.result = Model.copy(e)
  }

  function clearHistory() {
    root.history = []
    root.lastAlert = null
    root.alertAcknowledged = true
    root.saveState()
  }

  function dismissResult() {
    if (root.busy) return
    root.result = null
    root.errorMessage = ""
  }

  function cancelPending() {
    root.pendingScan = ""
  }

  function raiseAlert(r) {
    root.lastAlert = Model.compactResult(r)
    root.alertAcknowledged = false
    root.saveState()
  }

  function viewAlert() {
    if (!root.lastAlert || root.busy) return
    root.errorMessage = ""
    root.result = Model.copy(root.lastAlert)
    root.acknowledgeAlert()
  }

  function acknowledgeAlert() {
    if (root.alertAcknowledged) return
    root.alertAcknowledged = true
    root.saveState()
  }

  function setWatcherEnabled(value) {
    var v = value === true
    if (root.watcherEnabled === v) return
    root.watcherEnabled = v
    root.watcherMessage = ""
    root.saveConfig()
  }

  function setNotifyAll(value) {
    var v = value === true
    if (root.notifyAll === v) return
    root.notifyAll = v
    root.saveConfig()
  }

  // --- installed-plugin scanner settings -------------------------------------

  function setPluginScanEnabled(value) {
    var v = value === true
    if (root.pluginScanEnabled === v) return
    root.pluginScanEnabled = v
    root.saveConfig()
  }

  // Only the panel calls this with true, after the standard-submission
  // consent dialog.
  function setPluginAutoUpload(value) {
    var v = value === true
    if (root.pluginAutoUpload === v) return
    root.pluginAutoUpload = v
    root.saveConfig()
  }

  function setPluginBackend(value) {
    var v = Model.PLUGIN_BACKENDS.indexOf(value) >= 0 ? value : "vtai"
    if (root.pluginBackend === v) return
    root.pluginBackend = v
    root.saveConfig()
  }

  function setMaxParallel(value) {
    var c = Model.normalizeConfig({ maxParallel: value })
    if (root.maxParallel === c.maxParallel) return
    root.maxParallel = c.maxParallel
    root.saveConfig()
  }

  function setClassicLimits(perMin, perDay) {
    var c = Model.normalizeConfig({ classicPerMin: perMin, classicPerDay: perDay })
    if (root.classicPerMin === c.classicPerMin && root.classicPerDay === c.classicPerDay) return
    root.classicPerMin = c.classicPerMin
    root.classicPerDay = c.classicPerDay
    root.saveConfig()
  }

  // The key reaches the shell on stdin only (Scripts.saveApiKey).
  function saveApiKey(key) {
    if (root.apiKeyBusy || !root.dirsReady) return
    var k = String(key || "").replace(/\s+/g, "")
    if (!/^[A-Za-z0-9]{64}$/.test(k)) {
      root.apiKeyMessage = "A VirusTotal API key is 64 letters and digits."
      return
    }
    root.apiKeyBusy = true
    root.apiKeyMessage = ""
    root.runJob(["sh", "-c", Scripts.saveApiKey, "sh", root.configDir, root.apiKeyPath], 10000, function(code) {
      root.apiKeyBusy = false
      if (code === 0) {
        root.apiKeyState = "present"
        root.apiKeyMessage = "API key saved in " + root.apiKeyDisplay + "."
      } else {
        root.apiKeyMessage = code === 2 ? "A VirusTotal API key is 64 letters and digits." : "Could not save the API key."
      }
    }, k + "\n")
  }

  function removeApiKey() {
    if (root.apiKeyBusy) return
    root.apiKeyBusy = true
    root.sh(Scripts.removeFile, [root.apiKeyPath], 10000, function(code) {
      root.apiKeyBusy = false
      if (code !== 0) {
        root.apiKeyMessage = "Could not delete " + root.apiKeyDisplay + "."
        return
      }
      root.apiKeyState = "missing"
      root.apiKeyMessage = "API key removed."
    })
  }

  function markApiKeyInvalid() {
    if (root.apiKeyState === "present") root.apiKeyState = "invalid"
    root.apiKeyMessage = "VirusTotal rejected the API key. Save a valid one to resume the plugin scanner."
  }

  PluginScanner {
    id: pluginScanner
    service: root
    active: root.pluginScannerActive
    backend: root.pluginBackend
    autoUpload: root.pluginAutoUpload
    maxParallel: root.maxParallel
    classicPerMin: root.classicPerMin
    classicPerDay: root.classicPerDay
    notifyAll: root.notifyAll
    pluginsDir: root.pluginsDir
    statePath: root.dirsReady ? root.stateDir + "/plugins.json" : ""
  }

  // --- coding agents ---------------------------------------------------------

  function setAgentButtons(value) {
    var v = value === true
    if (root.agentButtons === v) return
    root.agentButtons = v
    root.saveConfig()
  }

  // The panel sets this after the auto-approve warning before the first
  // "Ask <agent>".
  function setAgentHandoffAck(value) {
    var v = value === true
    if (root.agentHandoffAck === v) return
    root.agentHandoffAck = v
    root.saveConfig()
  }

  AgentsManager {
    id: agentsManager
    service: root
    statePath: root.dirsReady ? root.stateDir + "/agents.json" : ""
  }

  // Each open panel (one per monitor at most) calls panelOpened() once and
  // panelClosed() once.
  function panelOpened() {
    root._openPanels++
    root.panelVisible = true
    if (!root.ready) return
    // Installed since startup? Probe again instead of asking for a restart.
    if (root.missingTools !== "") root.startup()
    root.refreshCredentialPresence()
    if (root.credentialState === "invalid" || (root.connected && !root.accessChecked)) root.checkAccess(false)
    if (root.downloadsDirExists) root.refreshRecentDownloads()
    else root.checkDownloadsDir()
    if (pluginScanner.active) pluginScanner.probe()
    // For the "Ask <agent>" buttons.
    agentsManager.refreshDefault(false)
  }

  function panelClosed() {
    root._openPanels = Math.max(0, root._openPanels - 1)
    root.panelVisible = root._openPanels > 0
  }

  // Only https://*.virustotal.com/ links ever reach the browser.
  function openReport(url) {
    var u = String(url || "")
    if (!/^https:\/\/([a-z0-9-]+\.)*virustotal\.com\//i.test(u)) return
    Quickshell.execDetached(["sh", "-c", Scripts.openUrl, "sh", u, root.omarchyPath])
  }

  function notifyResult(r) {
    if (root.standalone || !r) return
    root.notifyMessage(Model.notificationFor(r))
  }

  // n: { urgency, glyph, title, body }
  function notifyMessage(n) {
    if (root.standalone || !n) return
    Quickshell.execDetached(["sh", "-c", Scripts.notify, "sh", n.urgency, n.glyph, n.title, n.body, root.pluginId, root.omarchyPath])
  }

  // ===========================================================================
  // Downloads folder and watcher
  // ===========================================================================

  function checkDownloadsDir() {
    var dir = root.downloadsDir
    if (dir === "") {
      root.downloadsDirExists = false
      return
    }
    root.sh(Scripts.dirCheck, [dir], 10000, function(code) {
      if (dir !== root.downloadsDir) return
      root.downloadsDirExists = code === 0
      if (!root.downloadsDirExists) return
      root.ensureDownloadsModel()
      root.refreshRecentDownloads()
    })
  }

  // Qt.labs.folderlistmodel is loaded on demand so a system without it only
  // loses the watcher and the recent-downloads list.
  function ensureDownloadsModel() {
    if (root.downloadsModel || !root.watcherAvailable || !root.downloadsDirExists) return root.downloadsModel
    var component = Qt.createComponent(Qt.resolvedUrl("DownloadsFolder.qml"))
    var model = component.status === Component.Ready ? component.createObject(root, { path: root.downloadsDir }) : null
    if (!model) {
      root.watcherAvailable = false
      root.watcherMessage = "Watching Downloads needs the Qt.labs.folderlistmodel QML module (qt6-declarative)."
      console.warn("[virustotal] DownloadsFolder.qml: " + component.errorString())
      return null
    }
    model.updated.connect(root.downloadsUpdated)
    root.downloadsModel = model
    return model
  }

  function downloadsUpdated() {
    downloadsDebounce.restart()
  }

  function refreshRecentDownloads() {
    var m = root.downloadsModel
    root.recentDownloads = m && m.ready ? Model.recentDownloads(m.snapshot(25), 4) : []
  }

  Timer {
    id: downloadsDebounce
    interval: 400
    repeat: false
    onTriggered: {
      if (root.watcherActive) root.watchTick()
      if (root.panelVisible) root.refreshRecentDownloads()
    }
  }

  // Safety net in case a folder change was coalesced away.
  Timer {
    interval: 30000
    repeat: true
    running: root.watcherActive
    onTriggered: root.watchTick()
  }

  Timer {
    id: watchKick
    repeat: false
    onTriggered: root.processWatchQueue()
  }

  onWatcherActiveChanged: {
    root._watchGen++
    root._seen = null
    root._queue = []
    root.watchQueueLength = 0
    watchKick.stop()
    if (!root.watcherActive) return
    root.watcherMessage = ""
    root.ensureDownloadsModel()
    root.watchTick()
  }

  // The first listing after (re)activation is only a baseline: files that
  // were already there never alert.
  function watchTick() {
    if (!root.watcherActive) return
    var m = root.downloadsModel
    if (!m || !m.ready) return
    var d = Model.diffDownloads(root._seen, m.entries(), { maxNew: 20 })
    var baseline = root._seen === null
    root._seen = d.seen
    if (baseline || d.added.length === 0) return
    var now = Date.now()
    var q = root._queue.slice()
    for (var i = 0; i < d.added.length; i++) {
      var f = d.added[i]
      var queued = false
      for (var k = 0; k < q.length; k++) {
        if (q[k].path === f.path) queued = true
      }
      if (!queued) q.push({ name: f.name, path: f.path, attempts: 0, firstSeen: now, notBefore: now + 4000 })
    }
    if (d.dropped > 0) root.watcherMessage = d.dropped + " more new files were skipped (at most 20 are checked at once)."
    root._queue = q
    root.watchQueueLength = q.length
    root.processWatchQueue()
  }

  function requeue(item) {
    var q = root._queue.slice()
    q.push(item)
    root._queue = q
    root.watchQueueLength = q.length
  }

  function kickWatch(ms) {
    watchKick.interval = Math.max(250, Math.min(ms, 3600000))
    watchKick.restart()
  }

  function watchDone() {
    root.watchBusy = false
    root.processWatchQueue()
  }

  // One file at a time, lookups at least 1.2 s apart, paused on rate limits.
  function processWatchQueue() {
    if (!root.watcherActive || root.watchBusy) return
    var q = root._queue
    if (q.length === 0) return
    var now = Date.now()
    var idx = -1
    var soonest = -1
    for (var i = 0; i < q.length; i++) {
      if (q[i].notBefore <= now) {
        idx = i
        break
      }
      if (soonest < 0 || q[i].notBefore < soonest) soonest = q[i].notBefore
    }
    var wait = Math.max(root._pauseUntil - now, root._lastWatchLookup + 1200 - now, idx < 0 ? soonest - now : 0)
    if (wait > 0) {
      root.kickWatch(wait)
      return
    }
    var item = q[idx]
    var rest = q.slice(0, idx).concat(q.slice(idx + 1))
    root._queue = rest
    root.watchQueueLength = rest.length
    root.watchBusy = true
    var gen = root._watchGen
    root.hashFile(item.path, 4, Model.MAX_WATCH_BYTES, function(code, size, sha) {
      if (gen !== root._watchGen || !root.watcherActive) {
        root.watchBusy = false
        return
      }
      if (code === 6 || code === 7) {
        // Still being written, or an empty placeholder while the browser
        // downloads into a .part file. Retry with backoff for up to 30 min.
        item.attempts++
        if (Date.now() - item.firstSeen < 30 * 60000) {
          item.notBefore = Date.now() + Model.watchBackoffMs(item.attempts)
          root.requeue(item)
        }
        root.watchDone()
        return
      }
      if (code !== 0) {
        // Gone, unreadable or above 1 GiB: skip quietly.
        root.watchDone()
        return
      }
      root.watchLookup(item, size, sha, gen)
    })
  }

  function watchLookup(item, size, sha, gen) {
    var now = Date.now()
    if (root._sessionShas[sha] || Model.findRecentBySha(root.history, sha, now, 86400000)) {
      root.watchDone()
      return
    }
    root._sessionShas[sha] = now
    root._lastWatchLookup = now
    var extra = { name: item.name, path: item.path, sha256: sha, size: size, source: "watcher" }
    root.api("GET", "/files/" + sha, {}, function(res) {
      root._lastWatchLookup = Date.now()
      if (gen !== root._watchGen || !root.watcherActive) {
        delete root._sessionShas[sha]
        root.watchBusy = false
        return
      }
      var r = null
      if (res.http === 200 && res.json && res.json.data) r = Model.resultFromReport("file", item.path, res.json.data, extra)
      else if (res.http === 404) r = Model.notFoundResult("file", item.path, extra)
      if (r) {
        r.time = Date.now()
        root.recordHistory(r)
        var flagged = Model.hasFlags(r)
        if (flagged) root.raiseAlert(r)
        if (flagged || root.notifyAll) root.notifyResult(r)
        root.watchDone()
        return
      }
      delete root._sessionShas[sha]
      var e = Model.apiError(res.http, res.json, res.exitCode, res.retryAfter)
      if (e.kind === "auth") {
        // credentialState turns invalid, which stops the watcher.
        root.noteAuthError(e)
        root.watchBusy = false
        return
      }
      item.attempts++
      if (e.kind === "rate_limit") {
        var pause = Math.max(e.retryAfter, 60)
        root._pauseUntil = Date.now() + pause * 1000
        root.watcherMessage = "Rate limit reached; checking resumes in " + Model.formatDuration(pause) + "."
      }
      if (item.attempts < 6) {
        item.notBefore = Date.now() + (e.kind === "rate_limit" ? 0 : 60000)
        root.requeue(item)
      }
      root.watchDone()
    })
  }
}
