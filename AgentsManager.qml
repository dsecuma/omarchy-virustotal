import QtQuick
import Quickshell
import Quickshell.Io
import "Agents.js" as Agents
import "Model.js" as Model
import "Scripts.js" as Scripts

// Omarchy's coding agents and the VirusTotal AI MCP server (AgentsTab.qml),
// owned by Service.qml.
//
// probe() finds which agents are installed, reads their MCP configs
// (read-only) and checks the virustotal skill links. The actions then add or
// remove the MCP entry with each agent's own `mcp add` / `mcp remove`, or
// with a jq merge plus a backup for agents that only have a JSON config;
// link the skill into Omarchy's agent skill folders; open an agent to sign
// in; and hand a result to the default agent with `omarchy agent prompt`.
//
// Rules (details in Agents.js):
//  - An entry holds only https://ai.virustotal.com/mcp. Agents sign in to
//    VirusTotal themselves (OAuth), so no token is written anywhere.
//  - Every action probes again right before it runs and carries out only
//    the steps the user saw (Agents.confirmedSteps). Remove only touches
//    entries this plugin added, recorded in
//    ${XDG_STATE_HOME}/omarchy-virustotal/agents.json.
//  - Agents that are not installed are never run: Omarchy's mise launcher
//    stub of a missing agent would install it.
Item {
  id: root

  // --- inputs (bound by Service.qml) -----------------------------------------
  property var service: null
  property string statePath: ""

  // --- state for the panel ---------------------------------------------------
  // This plugin's copy of the skill ("" when the plugin is not loaded from a
  // local folder).
  readonly property string skillPath: Agents.urlToPath(Qt.resolvedUrl("agents/skills/" + Agents.SKILL_NAME))
  readonly property string skillFile: skillPath !== "" ? skillPath + "/SKILL.md" : ""
  property var rows: Agents.buildRows(null, {}, null, {})
  property var skill: Agents.skillSummary("")
  property var record: Agents.emptyRecord()
  // Last failure per agent id (and "skill"), shown on its row.
  property var errors: ({})
  property bool probing: false
  property bool probed: false
  property string probeError: ""
  property string defaultAgent: ""
  property string defaultState: ""
  property bool defaultKnown: false
  readonly property string defaultName: defaultAgent !== "" ? Agents.agentName(defaultAgent) : ""
  readonly property bool canHandoff: defaultAgent !== "" && defaultState === "installed"
  // "connect" | "skill" | an agent id while an action runs.
  property string busyId: ""
  readonly property bool busy: busyId !== ""
  readonly property bool recordReady: _recordLoaded && statePath !== ""
  property string message: ""
  property string messageRole: "muted"
  property bool handoffBusy: false
  property string handoffNote: ""
  property string handoffRole: "muted"

  // --- private ---------------------------------------------------------------
  property var _probe: null
  property var _mcp: ({})
  property var _current: []
  property var _waiters: []
  property bool _probeAgain: false
  property bool _recordLoaded: false
  property string _lastRecordText: ""
  property int _recordRev: 0
  property int _defaultSeq: 0
  property int _defaultApplied: 0
  property real _lastDefaultCheck: 0
  property int _defaultPolls: 0

  // ===========================================================================
  // What the plugin changed (agents.json)
  // ===========================================================================

  FileView {
    id: recordFile
    path: root.statePath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyRecord(recordFile.text(), false)
    onLoadFailed: root.applyRecord("", true)
    onFileChanged: recordFile.reload()
  }

  function applyRecord(text, failed) {
    if (failed && root._recordLoaded) return  // file vanished: keep the in-memory copy
    var t = String(text || "")
    if (root._recordLoaded && t === root._lastRecordText) return  // echo of our own write
    root._lastRecordText = t
    root.record = Agents.parseRecord(t)
    root._recordRev++
    root._recordLoaded = true
    root.refreshRows()
  }

  function saveRecord(rec) {
    var t = Agents.serializeRecord(rec)
    root.record = Agents.parseRecord(t)
    root._recordRev++
    root._lastRecordText = t
    if (recordFile.path !== "") recordFile.setText(t)
  }

  // ===========================================================================
  // Probing
  // ===========================================================================

  function ctx() {
    var s = root.service
    return { home: s ? s.homeDir : "", configHome: s ? s.configHome : "", busyId: root.busyId, errors: root.errors }
  }

  function refreshRows() {
    root.rows = Agents.buildRows(root._probe, root._mcp, root.record, root.ctx())
  }

  function setMessage(text, role) {
    root.message = String(text || "")
    root.messageRole = role || "muted"
  }

  function setError(id, text) {
    var e = {}
    for (var k in root.errors) {
      if (Object.prototype.hasOwnProperty.call(root.errors, k) && k !== id) e[k] = root.errors[k]
    }
    if (text) e[id] = String(text)
    root.errors = e
    root.refreshRows()
  }

  // done(ok) runs after a probe that started after this call: a request made
  // while a probe runs waits for the next one, so an answer never predates
  // the request (an action that just finished, a config edited by hand).
  function probe(done) {
    var cb = typeof done === "function" ? done : null
    if (root.probing) {
      root._probeAgain = true
      if (cb) root._waiters = root._waiters.concat([cb])
      return
    }
    var waiters = cb ? root._waiters.concat([cb]) : root._waiters
    root._waiters = []
    root._probeAgain = false
    var s = root.service
    if (!s) {
      Qt.callLater(function() { root.callWaiters(waiters, false) })
      return
    }
    root._current = waiters
    root.probing = true
    var c = root.ctx()
    var seq = ++root._defaultSeq
    var rev = root._recordRev
    s.sh(Scripts.probeAgents, [s.omarchyPath, "all"].concat(Agents.probeAgentArgs()), 30000, function(code, out) {
      if (code !== 0) {
        root.finishProbe(null, null, null, seq, rev, "Could not check which coding agents are installed (exit " + code + ").")
        return
      }
      var p = Agents.parseProbe(out, c.home)
      var targets = Agents.mcpTargets(p, c)
      var afterMcp = function(mcp) {
        root.readSkill(function(sk) { root.finishProbe(p, mcp, sk, seq, rev, "") })
      }
      if (!targets.length) {
        afterMcp({})
        return
      }
      // A failed probe leaves every config unreadable (completeMcp), so
      // nothing gets changed.
      s.sh(Scripts.probeMcp, [Agents.MCP_URL, Agents.MCP_NAME, Scripts.mcpJq, Scripts.mcpAwk].concat(Agents.mcpProbeArgs(targets)),
           30000, function(code2, out2) {
        afterMcp(Agents.completeMcp(code2 === 0 ? Agents.parseMcpProbe(out2) : {}, targets))
      })
    })
  }

  function readSkill(done) {
    var s = root.service
    if (!s || root.skillPath === "") {
      done(Agents.skillSummary(""))
      return
    }
    s.sh(Scripts.skillLinks, ["status", root.skillPath, Agents.SKILL_NAME, Agents.SKILL_MARKER], 15000, function(code, out) {
      done(Agents.skillSummary(code === 0 ? out : ""))
    })
  }

  function finishProbe(p, mcp, sk, seq, rev, err) {
    if (p) {
      // A newer default-agent check (refreshDefault) wins over this probe.
      if (seq < root._defaultApplied) {
        p.defaultAgent = root.defaultAgent
        p.defaultState = root.defaultState
      } else {
        root.applyDefault(seq, p.defaultAgent, p.defaultState)
      }
      root._probe = p
      root._mcp = mcp || {}
      root.probed = true
      // Forget entries removed by hand, unless the record changed meanwhile.
      if (!root.busy && rev === root._recordRev && root.recordReady) {
        var pruned = Agents.pruneRecord(root.record, p, root._mcp, root.ctx())
        if (pruned.changed) root.saveRecord(pruned.record)
      }
    }
    if (sk) root.skill = sk
    root.probeError = err || ""
    root.refreshRows()
    root.probing = false
    var waiters = root._current
    root._current = []
    if (root._probeAgain) root.probe()
    root.callWaiters(waiters, !!p)
  }

  function callWaiters(list, ok) {
    for (var i = 0; i < list.length; i++) {
      try {
        list[i](ok)
      } catch (e) {
        console.warn("[virustotal] " + e)
      }
    }
  }

  // ===========================================================================
  // Default agent
  // ===========================================================================

  // Answers are numbered; an older one never replaces a newer one.
  // -> true when the default agent or its state changed
  function applyDefault(seq, agent, state) {
    if (seq < root._defaultApplied) return false
    root._defaultApplied = seq
    var changed = agent !== root.defaultAgent || state !== root.defaultState
    root.defaultAgent = agent
    root.defaultState = state
    root.defaultKnown = true
    return changed
  }

  // Reads only the default agent; done(ok, changed).
  function checkDefault(done) {
    var s = root.service
    if (!s) {
      if (done) Qt.callLater(function() { done(false, false) })
      return
    }
    var seq = ++root._defaultSeq
    s.sh(Scripts.probeAgents, [s.omarchyPath, "default"].concat(Agents.probeAgentArgs()), 20000, function(code, out) {
      var changed = false
      if (code === 0) {
        var p = Agents.parseProbe(out, s.homeDir)
        changed = root.applyDefault(seq, p.defaultAgent, p.defaultState)
      }
      if (done) done(code === 0, changed)
    })
  }

  // Cheap check for the "Ask" buttons when a panel opens (at most every 30 s
  // unless forced). Once the tab has probed, a change refreshes every row.
  function refreshDefault(force) {
    if (!root.service || root.probing) return
    var now = Date.now()
    if (!force && now - root._lastDefaultCheck < 30000) return
    root._lastDefaultCheck = now
    root.checkDefault(function(ok, changed) {
      if (ok && changed && root.probed) root.probe()
    })
  }

  // Omarchy's picker runs on its own; watch for the new choice for a minute.
  function changeDefault() {
    var s = root.service
    if (!s) return
    Quickshell.execDetached(["sh", "-c", Scripts.agentMenu, "sh", s.omarchyPath])
    root._defaultPolls = 20
    defaultPoll.restart()
  }

  Timer {
    id: defaultPoll
    interval: 3000
    repeat: true
    onTriggered: {
      root._defaultPolls--
      if (root._defaultPolls <= 0) defaultPoll.stop()
      root.refreshDefault(true)
    }
  }

  // ===========================================================================
  // Actions
  // ===========================================================================

  function canAct() {
    if (!root.service || root.busy) return false
    if (!root.recordReady) {
      root.setMessage("Still starting. Try again in a moment.", "muted")
      return false
    }
    return true
  }

  function stepAgents(steps) {
    var ids = []
    for (var i = 0; i < steps.length; i++) {
      if (steps[i].id && ids.indexOf(steps[i].id) < 0) ids.push(steps[i].id)
    }
    return ids
  }

  function startAction(id, agentIds) {
    root.busyId = id
    var e = {}
    for (var k in root.errors) {
      if (!Object.prototype.hasOwnProperty.call(root.errors, k)) continue
      if (agentIds.indexOf(k) >= 0 || (k === "skill" && (id === "skill" || id === "connect"))) continue
      e[k] = root.errors[k]
    }
    root.errors = e
    root.setMessage("", "muted")
    root.refreshRows()
  }

  function endAction(results, err) {
    root.busyId = ""
    if (err) {
      root.setMessage(err, "danger")
    } else {
      var summary = Agents.actionSummary(results)
      root.setMessage(summary.text, summary.role)
    }
    root.refreshRows()
    root.probe()
  }

  // Probes again, then runs the confirmed steps that fresh() still lists.
  function act(id, confirmed, fresh) {
    if (!confirmed || !confirmed.length || !root.canAct()) return
    root.startAction(id, root.stepAgents(confirmed))
    root.probe(function(ok) {
      if (!ok) {
        root.endAction([], "Could not check the agents again, so nothing was changed.")
        return
      }
      root.runSteps(Agents.confirmedSteps(fresh(), confirmed))
    })
  }

  function connectPlan() {
    return Agents.connectPlan(root.rows, root.skill)
  }

  // "Connect installed agents", after the panel's dialog listed `plan`.
  function connectAll(plan) {
    root.act("connect", plan && plan.steps ? plan.steps : [], function() { return root.connectPlan().steps })
  }

  function add(id) {
    root.act(id, Agents.addSteps(Agents.rowById(root.rows, id)),
             function() { return Agents.addSteps(Agents.rowById(root.rows, id)) })
  }

  // After the panel's dialog; `confirmed` = Agents.removeSteps() it showed.
  function remove(id, confirmed) {
    root.act(id, confirmed || Agents.removeSteps(Agents.rowById(root.rows, id)),
             function() { return Agents.removeSteps(Agents.rowById(root.rows, id)) })
  }

  // The skill script itself only creates missing links, repoints outdated
  // ones and removes this plugin's own links, so it needs no fresh probe.
  function linkSkill() {
    root.skillAction("link")
  }

  function unlinkSkill() {
    root.skillAction("unlink")
  }

  function skillAction(op) {
    if (root.skillPath === "" || !root.canAct()) return
    root.startAction("skill", [])
    root.runSteps([{ kind: "skill", op: op, id: "", home: "", label: "skill" }])
  }

  // One step at a time; results feed Agents.actionSummary.
  function runSteps(steps) {
    var results = []
    var i = 0
    var next = function() {
      if (i >= steps.length) {
        root.endAction(results, "")
        return
      }
      var step = steps[i++]
      root.runStep(step, function(res) {
        res.step = step
        results.push(res)
        next()
      })
    }
    next()
  }

  function runStep(step, done) {
    if (step.kind === "skill") root.runSkillStep(step, done)
    else if (step.kind === "cli") root.runCliStep(step, done)
    else if (step.kind === "json") root.runJsonStep(step, done)
    else done({ ok: false, message: "" })
  }

  function runSkillStep(step, done) {
    var before = root.skill
    root.service.sh(Scripts.skillLinks, [step.op, root.skillPath, Agents.SKILL_NAME, Agents.SKILL_MARKER], 15000, function(code, out) {
      if (code !== 0) {
        var msg = code === 3 ? "The skill file is missing from the plugin folder. Reinstall the plugin."
                             : "Could not change the skill links (exit " + code + ")."
        root.setError("skill", msg)
        done({ ok: false, message: msg })
        return
      }
      var sk = Agents.skillSummary(out)
      root.skill = sk
      root.saveRecord(Agents.recordSkill(root.record, sk.links, Date.now()))
      if (sk.failed > 0) {
        var failed = "Could not change " + sk.failed + " skill folder" + (sk.failed === 1 ? "" : "s") + "."
        root.setError("skill", failed)
        done({ ok: false, message: failed })
        return
      }
      var nothing = before.known && (step.op === "link" ? before.linkable === 0 : before.ours + before.stale === 0)
      done({ ok: true, skipped: nothing,
             message: nothing ? "The virustotal skill was already " + (step.op === "link" ? "linked." : "unlinked.") : "" })
    })
  }

  function runCliStep(step, done) {
    var s = root.service
    var args = Agents.cliArgs(step)
    if (!args) {
      done({ ok: false, message: "" })
      return
    }
    s.sh(Scripts.agentCli, [s.omarchyPath].concat(args), 100000, function(code, out, err) {
      if (code === 0) {
        root.saveRecord(step.op === "add"
          ? Agents.recordMcpAdd(root.record, step.id, step.home, "", "", Date.now())
          : Agents.recordMcpRemove(root.record, step.id, step.home))
        done({ ok: true })
        return
      }
      var msg = Agents.cliErrorMessage(step.id, step.op, code, String(err || "").trim() !== "" ? err : out)
      root.setError(step.id, msg)
      done({ ok: false, message: msg })
    })
  }

  function runJsonStep(step, done) {
    var s = root.service
    var args = Agents.jsonArgs(step, root.ctx())
    if (!args) {
      done({ ok: false, message: "" })
      return
    }
    var name = Agents.agentName(step.id)
    var file = Model.displayPath(args[1], s.homeDir)
    s.sh(Scripts.jsonMcp, args, 20000, function(code, out) {
      var line = String(out || "").split("\n")[0].replace(/\r$/, "")
      if (code === 0 && line.indexOf("done\t") === 0) {
        root.saveRecord(step.op === "add"
          ? Agents.recordMcpAdd(root.record, step.id, "", args[1], line.slice(5), Date.now())
          : Agents.recordMcpRemove(root.record, step.id, ""))
        done({ ok: true })
      } else if (code === 0 && line === "exists") {
        done({ ok: true, skipped: true, message: name + " already had a virustotal entry, so it was left as it is." })
      } else if (code === 0 && (line === "changed" || line === "none")) {
        // The entry is the user's now (or gone): stop offering Remove.
        root.saveRecord(Agents.recordMcpRemove(root.record, step.id, ""))
        done({ ok: true, skipped: true, message: line === "changed"
          ? name + "'s virustotal entry was edited after the plugin added it, so it was left as it is."
          : name + " no longer had a virustotal entry." })
      } else {
        var msg = code === 0 ? "Unexpected answer while updating " + file + "." : Agents.jsonErrorMessage(code, file)
        root.setError(step.id, msg)
        done({ ok: false, message: msg })
      }
    })
  }

  // ===========================================================================
  // Sign-in, clipboard and links
  // ===========================================================================

  function signIn(id) {
    var s = root.service
    var plan = Agents.signInPlan(Agents.rowById(root.rows, id))
    if (!s || !plan) return
    Quickshell.execDetached(["sh", "-c", Scripts.launchAgent, "sh", s.omarchyPath, plan.mode, plan.home, plan.pkg].concat(plan.argv))
    root.setMessage(plan.steps, "muted")
  }

  function copy(id) {
    var s = root.service
    var row = Agents.rowById(root.rows, id)
    if (!s || !row || !row.canCopy) return
    var what = row.copyLabel === "Copy command" ? "the command" : row.copyLabel === "Copy snippet" ? "the snippet" : "the setup details"
    s.runJob(["sh", "-c", Scripts.copyText, "sh", row.copyText], 10000, function(code) {
      if (code === 0) root.setMessage("Copied " + what + " for " + row.name + ".", "muted")
      else root.setMessage(code === 127 ? "wl-copy is not installed, so nothing was copied." : "Could not copy to the clipboard.", "danger")
    })
  }

  function openGuide(id) {
    var row = Agents.rowById(root.rows, id)
    if (root.service && row && row.guideUrl !== "") root.service.openReport(row.guideUrl)
  }

  function openAccess() {
    if (root.service) root.service.openReport(Agents.ACCESS_URL)
  }

  // Only the community projects listed in Agents.js.
  function openLink(id) {
    var s = root.service
    var row = Agents.rowById(root.rows, id)
    if (!s || !row || !Agents.isKnownLink(row.link)) return
    Quickshell.execDetached(["sh", "-c", Scripts.openUrl, "sh", row.link, s.omarchyPath])
  }

  // ===========================================================================
  // "Ask <agent>"
  // ===========================================================================

  // Opens the default agent with a result. The default agent is checked again
  // first, because `omarchy agent prompt` would install a missing one. The
  // panel shows the auto-approve warning before the first hand-off.
  function handoff(result) {
    var s = root.service
    if (!s || root.handoffBusy) return
    var prompt = Agents.handoffPrompt(result, { home: s.homeDir, skillFile: root.skillFile, now: Date.now() })
    if (prompt === "") {
      root.setHandoffNote("Only finished lookups can be handed to an agent.", "muted")
      return
    }
    root.handoffBusy = true
    root.setHandoffNote("", "muted")
    root.checkDefault(function(ok) {
      root.handoffBusy = false
      if (!ok) {
        root.setHandoffNote("Could not check Omarchy's default agent.", "danger")
      } else if (root.defaultAgent === "") {
        root.setHandoffNote("Choose a default agent first (Agents tab \u203a Change).", "danger")
      } else if (root.defaultState !== "installed") {
        root.setHandoffNote(root.defaultName + " is not installed. Install it from Omarchy's agent menu or choose another default agent.", "danger")
      } else {
        Quickshell.execDetached(["sh", "-c", Scripts.agentPrompt, "sh", s.omarchyPath, prompt])
        root.setHandoffNote("Opened " + root.defaultName + " with this result.", "muted")
      }
    })
  }

  function setHandoffNote(text, role) {
    root.handoffNote = String(text || "")
    root.handoffRole = role || "muted"
    if (root.handoffNote !== "") handoffNoteTimer.restart()
    else handoffNoteTimer.stop()
  }

  Timer {
    id: handoffNoteTimer
    interval: 10000
    onTriggered: root.handoffNote = ""
  }
}
