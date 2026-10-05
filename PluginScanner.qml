import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model
import "Scanner.js" as Scanner
import "Scripts.js" as Scripts

// Installed-plugin scanner (issue #5), owned by Service.qml.
//
// Watches ~/.config/omarchy/plugins. When a plugin appears or changes it is
// hashed (one sh per plugin, two plugins at a time), every file's SHA-256 is
// looked up with VirusTotal, and unknown files are uploaded only when the user
// turned on automatic uploads (consent given once in Settings).
//
// Requests run in parallel: Scanner.dispatch starts up to `maxParallel` curl
// jobs while the per-minute and per-day quotas allow it, and a single timer
// wakes the queue when the next request may start. The same SHA-256 is never
// checked twice at once, across plugins and versions, and results are cached
// in ${XDG_STATE_HOME}/omarchy-virustotal/plugins.json.
//
// Only VirusTotal's own numbers are reported: a file is flagged when engines
// flagged it or an AI insight (Code Insight) returned a malicious/suspicious
// verdict. The scanner never issues a verdict of its own.
Item {
  id: root

  // --- inputs (bound by Service.qml) -----------------------------------------
  property var service: null
  property bool active: false
  property string backend: "vtai"
  property bool autoUpload: false
  property int maxParallel: 4
  property int classicPerMin: 4
  property int classicPerDay: 500
  property bool notifyAll: false
  property string pluginsDir: ""
  property string statePath: ""

  // --- state for the panel ---------------------------------------------------
  property var plugins: []
  property int revision: 0
  property bool loaded: false
  property bool pluginsDirExists: true
  property int inFlight: 0
  property int uploadsInFlight: 0
  property int queued: 0
  property int hashing: 0
  property int hashQueueLength: 0
  property int scanTotal: 0
  property int scanDone: 0
  property real pauseUntil: 0
  property string pauseReason: ""
  property real nextWakeAt: 0
  property real lastProbe: 0
  property string message: ""
  property var quota: []
  readonly property bool working: inFlight > 0 || queued > 0 || hashing > 0 || hashQueueLength > 0
  readonly property string backendLabel: Scanner.backendFor(backend).label

  // --- private ---------------------------------------------------------------
  property var _st: Scanner.parseState("")
  property var _queue: []
  property var _busy: ({})
  property var _limiter: null
  property int _gen: 0
  property int _uploadGen: 0
  property var _hashQueue: []
  property var _scans: ({})
  property bool _probing: false
  property bool _probeAgain: false
  property var _folder: null
  property bool _folderTried: false

  onActiveChanged: root.restart()
  onBackendChanged: root.restart(true)
  onClassicPerMinChanged: root.rebuildLimiter()
  onClassicPerDayChanged: root.rebuildLimiter()
  onMaxParallelChanged: root.pump()
  onAutoUploadChanged: root.uploadPermissionChanged()

  // ===========================================================================
  // Lifecycle and persistence
  // ===========================================================================

  function restart(reuseState) {
    var resume = reuseState === true && root.active && root.loaded
    if (root.loaded) root.saveNow()
    root._gen++
    root._queue = []
    root._busy = {}
    root._hashQueue = []
    root._scans = {}
    root._probing = false
    root._probeAgain = false
    root.inFlight = 0
    root.hashing = 0
    root.scanTotal = 0
    root.scanDone = 0
    root.pauseUntil = 0
    root.pauseReason = ""
    root.message = ""
    pumpTimer.stop()
    // Reloaded from disk when the scanner becomes active again.
    root.loaded = false
    root.updateCounters()
    // A ready-to-ready backend switch does not change FileView.path, so no
    // loaded signal follows it. Keep the latest in-memory cache and rebuild
    // the backend-specific limiter instead of waiting for a nonexistent load.
    if (resume) {
      root._limiter = null
      root.rebuildLimiter()
      root.loaded = true
      root.refreshUi()
      root.probe()
    }
  }

  function dropQueuedUploads() {
    var keep = []
    for (var i = 0; i < root._queue.length; i++) {
      var t = root._queue[i]
      if (t.type === "upload") root.release(t.sha)
      else keep.push(t)
    }
    root._queue = keep
  }

  function uploadPermissionChanged() {
    // Also invalidate an off/on cycle while an earlier hash is still running.
    root._uploadGen++
    if (!root.autoUpload) root.dropQueuedUploads()
    if (!root.active || !root.loaded) return
    if (root.autoUpload) root.topUp(false)
    else root.afterTask()
  }

  function mayUpload(gen, permission, backendId) {
    return root.active && root.loaded && root.autoUpload && !!root.service
      && gen === root._gen && permission === root._uploadGen && backendId === root.backend
  }

  FileView {
    id: stateFile
    path: root.active && root.statePath !== "" ? root.statePath : ""
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyState(stateFile.text())
    onLoadFailed: root.applyState("")
  }

  function applyState(text) {
    if (!root.active || root.loaded) return
    root._st = Scanner.parseState(text)
    root._limiter = null
    root.rebuildLimiter()
    root.loaded = true
    root.ensureFolder()
    root.refreshUi()
    root.probe()
  }

  function rebuildLimiter() {
    var persisted = root._limiter ? Scanner.persistLimiter(root._limiter) : root._st.quota
    root._limiter = Scanner.makeLimiter(root.backend, { perMin: root.classicPerMin, perDay: root.classicPerDay },
                                        persisted, Date.now())
    root.updateCounters()
    root.pump()
  }

  function scheduleSave() {
    if (root.loaded) saveTimer.restart()
  }

  function saveNow() {
    saveTimer.stop()
    if (!root.loaded || stateFile.path === "") return
    root._st.quota = Scanner.persistLimiter(root._limiter)
    stateFile.setText(Scanner.serializeState(root._st))
  }

  Timer {
    id: saveTimer
    interval: 2000
    onTriggered: root.saveNow()
  }

  // ===========================================================================
  // Detecting new and updated plugins
  // ===========================================================================

  // Qt.labs.folderlistmodel is optional: without it only the instant signal
  // for new folders is lost, the periodic probe still runs.
  function ensureFolder() {
    if (root._folder || root._folderTried || root.pluginsDir === "") return
    root._folderTried = true
    var component = Qt.createComponent(Qt.resolvedUrl("PluginsFolder.qml"))
    var model = component.status === Component.Ready ? component.createObject(root, { path: root.pluginsDir }) : null
    if (!model) {
      console.warn("[virustotal] PluginsFolder.qml: " + component.errorString())
      return
    }
    model.updated.connect(function() { if (root.active && root.loaded) folderDebounce.restart() })
    root._folder = model
  }

  Timer {
    id: folderDebounce
    interval: 2000
    onTriggered: root.probe()
  }

  // Plugin updates rewrite files inside a folder, which the folder model does
  // not see; the probe compares a cheap per-plugin stamp instead.
  Timer {
    interval: 600000
    repeat: true
    running: root.active && root.loaded
    onTriggered: root.probe()
  }

  function probe() {
    if (!root.active || !root.loaded || !root.service) return
    if (root._probing) {
      root._probeAgain = true
      return
    }
    root._probing = true
    var gen = root._gen
    root.service.sh(Scripts.probePlugins, [root.pluginsDir], 60000, function(code, out) {
      if (gen !== root._gen) return
      root._probing = false
      root.lastProbe = Date.now()
      if (code === 3) {
        root.pluginsDirExists = false
        root.handleProbe([])
      } else if (code !== 0) {
        root.message = "Could not list " + Model.displayPath(root.pluginsDir, root.service.homeDir) + "."
      } else {
        root.pluginsDirExists = true
        root.handleProbe(Scanner.parseProbe(out))
      }
      if (root._probeAgain) {
        root._probeAgain = false
        root.probe()
      }
    })
  }

  function handleProbe(list) {
    var st = root._st
    var seen = {}
    for (var i = 0; i < list.length; i++) {
      var p = list[i]
      seen[p.id] = true
      var rec = st.plugins[p.id]
      if (rec && rec.stamp === p.stamp) {
        if (p.name) rec.name = p.name
        if (p.version) rec.version = p.version
        continue
      }
      root.queueHash(p)
    }
    var ids = Object.keys(st.plugins)
    for (var k = 0; k < ids.length; k++) {
      if (seen[ids[k]]) continue
      delete st.plugins[ids[k]]
      delete root._scans[ids[k]]
      root.scheduleSave()
    }
    root.finishBaselineIfIdle()
    // Periodic re-checks: stale reports, unknown files after an hour, and
    // pending uploads once automatic uploads are on.
    root.topUp(false)
    root.refreshUi()
    root.pumpHash()
  }

  function queueHash(p) {
    var q = root._hashQueue.filter(function(x) { return x.id !== p.id })
    q.push(p)
    root._hashQueue = q
    root.hashQueueLength = q.length
  }

  function pumpHash() {
    while (root.hashing < 2 && root._hashQueue.length > 0) {
      var p = root._hashQueue[0]
      root._hashQueue = root._hashQueue.slice(1)
      root.hashing++
      root.hashOne(p)
    }
    root.hashQueueLength = root._hashQueue.length
  }

  function hashOne(p) {
    var gen = root._gen
    var dir = root.pluginsDir + "/" + p.id
    root.service.sh(Scripts.hashPlugin, [dir, String(Scanner.MAX_FILES_PER_PLUGIN)], 300000, function(code, out) {
      if (gen !== root._gen) return
      root.hashing--
      if (code === 0) root.applyHash(p, Scanner.parseHashList(out, Scanner.MAX_FILES_PER_PLUGIN))
      else if (code !== 3) root.message = "Could not read the files of " + p.id + "."
      root.pumpHash()
      root.finishBaselineIfIdle()
    })
  }

  // The very first pass only establishes what is installed: those plugins are
  // checked, but "new plugin" notifications start afterwards.
  function finishBaselineIfIdle() {
    if (root._st.baselineDone || root.hashing > 0 || root._hashQueue.length > 0) return
    root._st.baselineDone = true
    root.scheduleSave()
  }

  function applyHash(p, h) {
    var st = root._st
    var prev = st.plugins[p.id] || null
    var d = Scanner.diffPlugin(prev, h.files)
    var now = Date.now()
    var rec = {
      id: p.id,
      name: p.name || (prev ? prev.name : ""),
      version: p.version || "",
      head: p.head,
      stamp: p.stamp,
      link: p.link,
      files: h.files,
      firstSeen: prev ? prev.firstSeen : now,
      changedAt: prev && d.kind === "unchanged" ? prev.changedAt : now,
      lastScan: prev ? prev.lastScan : 0,
      truncated: h.truncated,
      skipped: h.skipped
    }
    st.plugins[p.id] = rec
    root.scheduleSave()
    if (d.kind === "unchanged") {
      root.refreshUi()
      return
    }
    var event = st.baselineDone ? d.kind : "baseline"
    if (event !== "baseline") root.service.notifyMessage(Scanner.eventNotification(d.kind, rec, d.changed.length))
    root.startScan(p.id, event, false)
  }

  // ===========================================================================
  // Public actions (panel)
  // ===========================================================================

  function checkNow() {
    root.probe()
  }

  function rescan(id) {
    if (!root.active || !root.loaded) return
    root.startScan(id, "rescan", true)
  }

  function rescanAll() {
    if (!root.active || !root.loaded) return
    var ids = Object.keys(root._st.plugins)
    for (var i = 0; i < ids.length; i++) root.startScan(ids[i], "rescan", true)
  }

  function openReport(url) {
    if (root.service) root.service.openReport(url)
  }

  // ===========================================================================
  // Queue
  // ===========================================================================

  function enqueue(tasks) {
    for (var i = 0; i < tasks.length; i++) {
      root._busy[tasks[i].sha] = true
      root._queue.push(tasks[i])
      root.scanTotal++
    }
  }

  function startScan(id, event, force) {
    var rec = root._st.plugins[id]
    if (!rec) return
    root.enqueue(Scanner.tasksFor(rec, root.pluginsDir + "/" + id, root._st.cache, root._busy, Date.now(),
                                  { autoUpload: root.autoUpload, force: force }))
    root._scans[id] = { event: event }
    root.checkDone()
    root.scheduleUi()
    root.pump()
  }

  // Silent re-checks: no per-plugin summary notification, but a newly
  // flagged file still alerts (see setEntry).
  function topUp(force) {
    var ids = Object.keys(root._st.plugins)
    var now = Date.now()
    for (var i = 0; i < ids.length; i++) {
      var rec = root._st.plugins[ids[i]]
      root.enqueue(Scanner.tasksFor(rec, root.pluginsDir + "/" + ids[i], root._st.cache, root._busy, now,
                                    { autoUpload: root.autoUpload, force: force }))
    }
    root.pump()
  }

  Timer {
    id: pumpTimer
    repeat: false
    onTriggered: root.pump()
  }

  function pump() {
    if (!root.active || !root.loaded || !root._limiter || !root.service) return
    if (!root.autoUpload) root.dropQueuedUploads()
    var now = Date.now()
    if (root.pauseUntil <= now) root.pauseReason = ""
    var s = { queue: root._queue, inFlight: root.inFlight, uploadsInFlight: root.uploadsInFlight, maxParallel: root.maxParallel,
              pauseUntil: root.pauseUntil, limiter: root._limiter }
    var d = Scanner.dispatch(s, now)
    root._queue = s.queue
    for (var i = 0; i < d.start.length; i++) root.run(d.start[i])
    root.nextWakeAt = d.wakeAt
    if (d.wakeAt > 0) {
      pumpTimer.interval = Math.max(250, Math.min(d.wakeAt - now, 3600000))
      pumpTimer.restart()
    } else {
      pumpTimer.stop()
    }
    root.updateCounters()
  }

  function afterTask() {
    root.checkDone()
    root.scheduleUi()
    root.pump()
    if (root.inFlight === 0 && root._queue.length === 0) {
      root.scanTotal = 0
      root.scanDone = 0
    }
  }

  function release(sha) {
    if (root._busy[sha]) {
      delete root._busy[sha]
      root.scanDone++
    }
  }

  function requeue(t, delayMs) {
    t.notBefore = Date.now() + (delayMs || 0)
    root._queue.push(t)
  }

  function followUp(t, type, delayMs, extra) {
    var n = { type: type, sha: t.sha, size: t.size, path: t.path, name: t.name, plugin: t.plugin,
              notBefore: Date.now() + (delayMs || 0), attempts: 0 }
    if (extra) for (var k in extra) n[k] = extra[k]
    root._queue.push(n)
  }

  // Drop everything after an authentication failure; the credential state
  // change in Service.qml usually deactivates the scanner right after.
  function stopWork(messageText) {
    root._gen++
    root._queue = []
    root._busy = {}
    root._scans = {}
    root.inFlight = 0
    root.scanTotal = 0
    root.scanDone = 0
    pumpTimer.stop()
    root.message = messageText
    root.updateCounters()
    root.scheduleUi()
  }

  // ===========================================================================
  // Requests
  // ===========================================================================

  function request(method, path, opts, callback) {
    var o = opts || {}
    o.backend = root.backend
    root.service.api(method, path, o, callback)
  }

  function run(t) {
    if (t.type === "upload" && !root.mayUpload(root._gen, root._uploadGen, root.backend)) {
      root.release(t.sha)
      return
    }
    root.inFlight++
    if (t.type === "upload") root.uploadsInFlight++
    var gen = root._gen
    function done(handler) {
      return function(res) {
        if (t.type === "upload") root.uploadsInFlight = Math.max(0, root.uploadsInFlight - 1)
        if (gen !== root._gen) {
          root.pump()
          return
        }
        root.inFlight = Math.max(0, root.inFlight - 1)
        try {
          handler(res)
        } catch (e) {
          console.warn("[virustotal] plugin scanner: " + e)
          root.release(t.sha)
        }
        root.afterTask()
      }
    }
    if (t.type === "lookup") root.request("GET", "/files/" + t.sha, {}, done(function(res) { root.onLookup(t, res) }))
    else if (t.type === "poll") root.request("GET", "/analyses/" + encodeURIComponent(t.analysisId), {}, done(function(res) { root.onPoll(t, res) }))
    else if (t.type === "receipt") root.request("GET", "/submissions/" + t.sha, {}, done(function(res) { root.onReceipt(t, res) }))
    else root.upload(t, done(function(res) { root.onUpload(t, res) }))
  }

  function upload(t, callback) {
    var gen = root._gen
    var permission = root._uploadGen
    var backendId = root.backend
    function cancelled() {
      if (root.mayUpload(gen, permission, backendId)) return false
      callback({ cancelled: true })
      return true
    }
    if (cancelled()) return
    // Hash again right before sending: the bytes must match the SHA-256.
    root.service.hashFile(t.path, 0, Model.MAX_UPLOAD_BYTES, function(code, size, sha) {
      if (cancelled()) return
      if (code !== 0 || sha !== t.sha) {
        callback({ exitCode: 0, http: 0, body: "", json: null, changed: true })
        return
      }
      if (backendId === "classic") {
        root.service.sh(Scripts.classicUpload, [t.path, root.service.apiKeyPath, Scanner.BACKENDS.classic.base + "/files",
                                                root.service.userAgent, "130"], 160000, function(c, out) {
          var parsed = Model.parseCurlOutput(out)
          callback({ exitCode: c, http: parsed.http, body: parsed.body, retryAfter: parsed.retryAfter, json: Model.parseJson(parsed.body) })
        })
        return
      }
      // Standard (non-private) VTAI submission; Service.api adds the consent header.
      root.request("POST", "/submissions/" + t.sha, { file: t.path, maxTime: 130 }, callback)
    })
  }

  function errorFor(res) {
    return root.backend === "classic"
      ? Scanner.classicError(res.http, res.json, res.exitCode, res.retryAfter)
      : Model.apiError(res.http, res.json, res.exitCode, res.retryAfter)
  }

  function extraFor(t) {
    return { name: t.name, path: t.path, sha256: t.sha, size: t.size, source: "plugins" }
  }

  function handleError(t, res) {
    var e = root.errorFor(res)
    var now = Date.now()
    if (e.kind === "auth") {
      if (root.backend === "classic") root.service.markApiKeyInvalid()
      else root.service.noteAuthError(e)
      root.stopWork(e.message)
      return
    }
    if (e.kind === "rate_limit") {
      var seconds = Math.max(e.retryAfter || 0, 60)
      root.pauseUntil = Math.max(root.pauseUntil, now + seconds * 1000)
      root.pauseReason = e.message
      root.requeue(t, 0)
      return
    }
    if (e.kind === "network" || e.kind === "timeout" || e.kind === "unavailable") {
      if (e.retryAfter > 0) {
        root.pauseUntil = Math.max(root.pauseUntil, now + e.retryAfter * 1000)
        root.pauseReason = e.message
      }
      t.attempts = (t.attempts || 0) + 1
      if (t.attempts < Scanner.MAX_ATTEMPTS) {
        root.requeue(t, Math.max(30000 * t.attempts, (e.retryAfter || 0) * 1000))
        return
      }
    }
    root.setEntry(t.sha, Scanner.errorEntry(e.message, now, root._st.cache[t.sha]))
    root.release(t.sha)
  }

  function onLookup(t, res) {
    var now = Date.now()
    if (res.http === 200 && res.json && res.json.data) {
      var data = root.backend === "classic" ? Scanner.classicReport(res.json.data) : res.json.data
      var r = Model.resultFromReport("file", t.path, data, root.extraFor(t))
      root.setEntry(t.sha, Scanner.cacheEntry(r, now, root._st.cache[t.sha]))
      root.release(t.sha)
      return
    }
    if (res.http === 404) {
      root.setEntry(t.sha, Scanner.cacheEntry(Model.notFoundResult("file", t.path, root.extraFor(t)), now, root._st.cache[t.sha]))
      if (root.autoUpload && Scanner.canAutoUpload(root._st.cache[t.sha], t.size, now)) {
        root._busy[t.sha] = true
        root.followUp(t, "upload", 0)
        return
      }
      root.release(t.sha)
      return
    }
    root.handleError(t, res)
  }

  function markUploaded(sha, now, analysisId) {
    var e = Model.copy(root._st.cache[sha]) || Scanner.errorEntry("", now, null)
    e.uploadedAt = now
    e.time = now
    if (analysisId) {
      e.status = "analyzing"
      e.analysisId = analysisId
      e.message = ""
    }
    root.setEntry(sha, e)
  }

  function queuePoll(t, analysisId, polls, nextSeconds) {
    var b = Scanner.backendFor(root.backend)
    root.followUp(t, "poll", Math.max(b.pollMinMs, Model.num(nextSeconds) * 1000), { analysisId: analysisId, polls: polls })
  }

  function onUpload(t, res) {
    var now = Date.now()
    if (res.cancelled) {
      root.release(t.sha)
      return
    }
    if (res.changed) {
      root.setEntry(t.sha, Scanner.errorEntry("The file changed before the upload.", now, root._st.cache[t.sha]))
      root.release(t.sha)
      folderDebounce.restart()
      return
    }
    if (root.backend === "classic") {
      var id = res.http === 200 ? Scanner.classicUploadId(res.json) : ""
      if (id) {
        root.markUploaded(t.sha, now, id)
        root.queuePoll(t, id, 0, 0)
        return
      }
    } else {
      var j = res.json
      var receipt = null
      if ((res.http === 200 || res.http === 202) && j && typeof j === "object" && typeof j.status === "string") receipt = j
      else if (j && j.detail && typeof j.detail === "object" && j.detail.submission
               && typeof j.detail.submission.status === "string") receipt = j.detail.submission
      if (receipt) {
        if (receipt.status === "exists") {
          if (receipt.report && receipt.report.data) {
            var r = Model.resultFromReport("file", t.path, receipt.report.data, root.extraFor(t))
            root.setEntry(t.sha, Scanner.cacheEntry(r, now, root._st.cache[t.sha]))
            root.release(t.sha)
          } else {
            root.followUp(t, "lookup", 0)
          }
          return
        }
        if (receipt.status === "submitted" && receipt.analysis_id) {
          root.markUploaded(t.sha, now, String(receipt.analysis_id))
          root.queuePoll(t, String(receipt.analysis_id), 0, receipt.next_poll_after_seconds)
          return
        }
        root.recoverUpload(t, res, now)
        return
      }
    }
    var capacityRejected = root.backend === "vtai" && res.http === 503 && root.errorFor(res).code === "capacity_exceeded"
    if ((!res.http && res.exitCode !== 127) || (res.http >= 500 && !capacityRejected)
        || res.http === 200 || res.http === 202) {
      // A proxy/server failure may follow an accepted upload. Only VTAI's
      // explicit pre-admission capacity rejection is safe to retry as a POST.
      root.recoverUpload(t, res, now)
      return
    }
    root.handleError(t, res)
  }

  function recoverUpload(t, res, now) {
    root.markUploaded(t.sha, now, "")
    var delay = Math.max(120000, Math.max(Model.num(res.retryAfter), root.errorFor(res).retryAfter || 0) * 1000)
    root.followUp(t, root.backend === "vtai" ? "receipt" : "lookup", delay)
  }

  function onReceipt(t, res) {
    var receipt = res.json
    if (res.http === 200 && receipt && ((receipt.status === "submitted" && receipt.analysis_id) || receipt.status === "exists")) {
      root.onUpload(t, res)
    } else if (res.http === 404 || res.http === 200) {
      // No recoverable analysis ID yet. A report lookup is safe; never turn
      // receipt recovery into an automatic re-submission.
      root.followUp(t, "lookup", 120000)
    } else {
      root.handleError(t, res)
    }
  }

  function onPoll(t, res) {
    var now = Date.now()
    var b = Scanner.backendFor(root.backend)
    if (res.http === 200 && res.json && typeof res.json === "object") {
      var a = root.backend === "classic" ? Scanner.classicAnalysis(res.json) : res.json
      if (a.status === "completed") {
        var r = Model.resultFromAnalysis(Model.baseResult("file", t.path, root.extraFor(t)), a, now)
        root.setEntry(t.sha, Scanner.cacheEntry(r, now, root._st.cache[t.sha]))
        root.release(t.sha)
        // Read the full report a bit later: AI insights (Code Insight) come with it.
        root.followUp(t, "lookup", Scanner.REFRESH_DELAY_MS, { refresh: true })
        return
      }
      var polls = (t.polls || 0) + 1
      if (polls >= b.maxPolls) {
        root.stopPolling(t, now)
        return
      }
      root.queuePoll(t, t.analysisId, polls, a.next_poll_after_seconds)
      return
    }
    if (res.http === 404) {
      root.stopPolling(t, now)
      return
    }
    root.handleError(t, res)
  }

  // Leave the file as "analyzing"; the next periodic pass looks it up again.
  function stopPolling(t, now) {
    var e = Model.copy(root._st.cache[t.sha]) || Scanner.errorEntry("", now, null)
    e.status = "analyzing"
    e.time = now
    root.setEntry(t.sha, e)
    root.release(t.sha)
  }

  // ===========================================================================
  // Results
  // ===========================================================================

  function setEntry(sha, entry) {
    var prev = root._st.cache[sha]
    root._st.cache[sha] = entry
    root.scheduleSave()
    if (Scanner.entryFlagged(entry) && !Scanner.entryFlagged(prev)) root.flaggedOutsideScan(sha)
  }

  // A file VirusTotal newly flagged outside an active plugin check (for
  // example a refreshed report that now carries a Code Insight verdict).
  function flaggedOutsideScan(sha) {
    var ids = Object.keys(root._st.plugins)
    for (var i = 0; i < ids.length; i++) {
      if (root._scans[ids[i]]) continue
      var rec = root._st.plugins[ids[i]]
      var rels = Object.keys(rec.files)
      for (var k = 0; k < rels.length; k++) {
        if (rec.files[rels[k]].sha !== sha) continue
        var r = Scanner.fileResult(rec, root.pluginsDir + "/" + rec.id, rels[k], root._st.cache)
        root.service.recordHistory(r)
        root.service.raiseAlert(r)
        root.service.notifyResult(r)
        return
      }
    }
  }

  function checkDone() {
    var ids = Object.keys(root._scans)
    for (var i = 0; i < ids.length; i++) {
      var id = ids[i]
      var rec = root._st.plugins[id]
      if (!rec) {
        delete root._scans[id]
        continue
      }
      var s = Scanner.summarize(rec, root._st.cache, root._busy)
      if (s.pending > 0) continue
      delete root._scans[id]
      rec.lastScan = Date.now()
      root.scheduleSave()
      root.finishPlugin(rec, s)
    }
  }

  function finishPlugin(rec, s) {
    var dir = root.pluginsDir + "/" + rec.id
    for (var i = s.flaggedFiles.length - 1; i >= 0; i--) {
      if (i >= 10) continue
      var r = Scanner.fileResult(rec, dir, s.flaggedFiles[i].rel, root._st.cache)
      if (r) root.service.recordHistory(r)
    }
    if (s.flaggedFiles.length > 0) root.service.raiseAlert(Scanner.fileResult(rec, dir, s.flaggedFiles[0].rel, root._st.cache))
    var n = Scanner.summaryNotification(rec, s, root.notifyAll)
    if (n) root.service.notifyMessage(n)
  }

  // ===========================================================================
  // Panel data
  // ===========================================================================

  Timer {
    id: uiTimer
    interval: 400
    onTriggered: root.refreshUi()
  }

  function scheduleUi() {
    if (!uiTimer.running) uiTimer.start()
  }

  function updateCounters() {
    root.queued = root._queue.length
    root.quota = Scanner.quotaInfo(root._limiter, Date.now())
  }

  function refreshUi() {
    var list = []
    var ids = Object.keys(root._st.plugins)
    for (var i = 0; i < ids.length; i++) {
      var rec = root._st.plugins[ids[i]]
      var s = Scanner.summarize(rec, root._st.cache, root._busy)
      var st = Scanner.pluginStatus(s)
      list.push({
        id: rec.id, name: rec.name || rec.id, version: rec.version || "",
        head: rec.head ? rec.head.slice(0, 7) : "", link: rec.link === true,
        files: s.files, flagged: s.flagged, status: st.label, role: st.role,
        lastScan: rec.lastScan || 0, changedAt: rec.changedAt || 0,
        truncated: rec.truncated === true, skipped: rec.skipped || 0,
        scanning: !!root._scans[rec.id] || s.pending > 0
      })
    }
    list.sort(function(a, b) {
      return (b.flagged > 0 ? 1 : 0) - (a.flagged > 0 ? 1 : 0) || a.name.toLowerCase().localeCompare(b.name.toLowerCase())
    })
    root.plugins = list
    root.revision++
    root.updateCounters()
  }

  // Rows for one plugin's files; `rev` only makes bindings refresh.
  function filesFor(id, rev) {
    var rec = root._st.plugins[id]
    if (!rec) return []
    var out = []
    var rels = Object.keys(rec.files)
    for (var i = 0; i < rels.length; i++) {
      var f = rec.files[rels[i]]
      var e = root._st.cache[f.sha] || null
      var st = Scanner.fileStatus(e, !!root._busy[f.sha])
      var url = e && e.status === "found" ? (Model.safeReportUrl(e.reportUrl) || Model.fallbackReportUrl("file", f.sha)) : ""
      out.push({ rel: rels[i], sha: f.sha, size: f.size, label: st.label, role: st.role, reportUrl: url,
                 flagged: Scanner.entryFlagged(e) })
    }
    out.sort(function(a, b) { return (b.flagged ? 1 : 0) - (a.flagged ? 1 : 0) || (a.rel < b.rel ? -1 : 1) })
    return out
  }

  function quotaLine() {
    var q = root.quota
    if (!q || !q.length) return ""
    var parts = []
    for (var i = 0; i < q.length; i++) {
      var label = q[i].key === "any" ? "requests" : q[i].key + "s"
      parts.push(q[i].used + "/" + q[i].perDay + " " + label)
    }
    return "Scanner use today (UTC): " + parts.join(" \u00b7 ")
  }

  function statusLine(now) {
    if (!root.active) return ""
    if (!root.loaded) return "Loading\u2026"
    if (root.message !== "") return root.message
    var t = now || Date.now()
    if (root.pauseUntil > t)
      return (root.pauseReason || "Paused.") + " Resuming in " + Model.formatDuration((root.pauseUntil - t) / 1000) + "."
    if (root.hashing > 0 || root.hashQueueLength > 0) return "Reading plugin files\u2026"
    var left = root.inFlight + root.queued
    if (left > 0) {
      var line = "Checking " + left + " file" + (left === 1 ? "" : "s") + " with " + root.backendLabel
      if (root.inFlight > 1) line += " \u00b7 " + root.inFlight + " in parallel"
      if (root.inFlight === 0 && root.nextWakeAt > t)
        line += " \u00b7 next request in " + Model.formatDuration((root.nextWakeAt - t) / 1000)
      var perMin = 0
      for (var i = 0; i < root.quota.length; i++) if (root.quota[i].key !== "upload") perMin = root.quota[i].perMin
      if (perMin > 0 && left > perMin) line += " \u00b7 about " + Model.formatDuration(Math.ceil(left / perMin) * 60) + " left"
      return line
    }
    if (!root.pluginsDirExists) return "No plugins folder yet (" + Model.displayPath(root.pluginsDir, root.service ? root.service.homeDir : "") + ")."
    var n = root.plugins.length
    var ago = Model.timeAgo(root.lastProbe, t)
    return n + " plugin" + (n === 1 ? "" : "s") + (ago !== "" ? " \u00b7 looked " + ago : "")
  }
}
