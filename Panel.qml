import QtQuick
import QtQuick.Controls
import Quickshell
import qs.Commons
import qs.Ui
import "Agents.js" as Agents
import "Model.js" as Model

// VirusTotal panel: lookups, consented uploads, history, installed-plugin
// checks (PluginsTab.qml), coding agents (AgentsTab.qml) and settings.
//
// All state and I/O live in Service.qml; BarWidget.qml injects it as
// `service`. This file renders that state and forwards user actions. Every
// Text that can show VirusTotal or file-system data uses PlainText.
Panel {
  id: root
  moduleName: "io.github.dsecuma.virustotal"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  property var service: null

  // scan | history | plugins | agents | settings
  property string tab: "scan"
  // upload | disconnect | clear | autoUpload | agentsConnect | agentRemove |
  // agentHandoff, or "" when no dialog is open
  property string confirmPurpose: ""
  property string _confirmSha: ""
  // What an agent dialog listed: the connect plan, the agent and the steps
  // to remove, or the result to hand off.
  property var _confirmPlan: null
  property string _confirmAgent: ""
  property var _confirmSteps: []
  property var _confirmResult: null
  property int historyIndex: 0
  property int settingsIndex: 0
  property int pluginsIndex: 0
  property int agentsIndex: 0
  property bool cursorActive: false
  property real now: Date.now()
  property var _notifiedService: null

  readonly property bool confirmOpen: confirmPurpose !== ""
  readonly property bool ready: !!service && service.ready === true
  readonly property var result: service ? service.result : null
  readonly property var history: service && service.history ? service.history : []
  readonly property var recent: service && service.recentDownloads ? service.recentDownloads : []
  readonly property bool busy: !!service && service.busy === true
  readonly property bool connected: !!service && service.connected === true
  readonly property string credentialState: service ? String(service.credentialState) : "checking"
  readonly property bool accountIdle: !!service && !service.connecting && !service.accountBusy
  readonly property bool showConnectCard: ready && (credentialState === "missing" || credentialState === "invalid")
  readonly property var alert: service && service.lastAlert && !service.alertAcknowledged ? service.lastAlert : null
  readonly property bool tracking: !!service && !!result && service.analysisActive === true
    && service.analysisSha === result.sha256
  readonly property var agents: service ? service.agents : null
  // "Ask <agent>" needs an installed default agent and the setting on.
  readonly property bool askAvailable: !!agents && agents.canHandoff === true && !!service && service.agentButtons === true
  // Result actions. The row's visibility must not read the buttons' `visible`:
  // a child reports false while its parent is hidden, so the row never shows.
  readonly property bool showOpenAction: !!result && String(result.reportUrl || "") !== ""
  readonly property bool showUploadAction: !!result && result.canUpload === true && connected
  readonly property bool showStatusAction: !!result && connected
    && ((result.status === "analyzing" && !tracking) || result.status === "unknown_submission")
  readonly property bool showAgainAction: tracking && !!service && service.analysisStalled === true
  readonly property bool showAskAction: askAvailable && !!result && (result.status === "found" || result.status === "not_found")
  readonly property bool showAlertAsk: askAvailable && !!alert
  readonly property var tabs: ["scan", "history", "plugins", "agents", "settings"]
  readonly property var scanner: service ? service.scanner : null
  readonly property var pluginRows: scanner && scanner.plugins ? scanner.plugins : []
  readonly property var agentItems: agentsTab.cursorItems
  // Fields that consume Return/arrows themselves; the key catcher stands down.
  readonly property bool fieldFocused: searchField.activeFocus || apiKeyField.activeFocus
    || parallelField.field.activeFocus || perMinField.field.activeFocus || perDayField.field.activeFocus
  readonly property var settingsItems: computeSettingsItems()

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  // The theme has no warning token: a softened urgent keeps "suspicious"
  // distinct from "malicious" in every palette.
  readonly property color warning: Qt.tint(urgent, Util.alpha(foreground, 0.35))
  readonly property color cardBorder: Util.alpha(foreground, 0.16)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property color resultColor: roleColor(Model.verdictRole(result))

  // --- helpers ---------------------------------------------------------------

  function roleColor(role) {
    if (role === "danger") return root.urgent
    if (role === "warning") return root.warning
    if (role === "ok" || role === "pending") return root.foreground
    return root.dim
  }

  function statusLine() {
    var s = root.service
    if (!s || !s.ready) return "Starting\u2026"
    if (s.connecting) return "Connecting\u2026"
    if (s.credentialState === "missing") return "Not connected"
    if (s.credentialState === "invalid") return "Token rejected"
    var parts = ["Connected"]
    if (s.watcherActive) parts.push("watching Downloads")
    if (s.pluginScannerActive) parts.push("checking plugins")
    return parts.join(" \u00b7 ")
  }

  function entrySubline(e) {
    if (!e) return ""
    var parts = [Model.verdictLabel(e)]
    var ago = Model.timeAgo(e.time, root.now)
    if (ago !== "") parts.push(ago)
    return parts.join(" \u00b7 ")
  }

  function resultMeta(r) {
    if (!r) return ""
    var parts = []
    var ago = r.analysisDate ? Model.timeAgo(r.analysisDate, root.now) : ""
    if (ago !== "") parts.push("Analyzed " + ago)
    if (r.kind === "file" && r.size >= 0) parts.push(Model.formatBytes(r.size))
    return parts.join(" \u00b7 ")
  }

  // The full SHA-256 on its own line, unless the target line above already is
  // that hash.
  function resultSha(r) {
    if (!r || !r.sha256 || Model.displayTarget(r) === r.sha256) return ""
    return "SHA-256 " + r.sha256
  }

  function insightTitle(insight) {
    if (!insight) return ""
    var source = String(insight.source || "")
    return source !== "" ? "AI insight \u00b7 " + source : "AI insight"
  }

  function watcherStatus() {
    var s = root.service
    if (!s) return ""
    if (s.standalone) return "This bar does not run plugin services, so downloads are not watched here."
    if (!s.watcherEnabled) return ""
    if (!s.connected) return "Connect to VirusTotal AI to start watching."
    if (!s.watcherAvailable) return s.watcherMessage
    if (!s.downloadsDirExists) return "Folder not found: " + s.downloadsDisplay
    if (s.watcherMessage !== "") return s.watcherMessage
    if (s.watcherActive) {
      var line = "Watching " + s.downloadsDisplay
      if (s.watchQueueLength > 0) line += " \u00b7 " + s.watchQueueLength + " pending"
      return line
    }
    return ""
  }

  function accountLine() {
    var s = root.service
    if (!s || !s.ready) return "Checking\u2026"
    switch (String(s.credentialState)) {
    case "missing": return "Not connected."
    case "invalid": return "VirusTotal AI rejected the token in " + s.authHeaderDisplay + "."
    case "valid": return "Connected. Token in " + s.authHeaderDisplay + "."
    case "present": return "Token in " + s.authHeaderDisplay + " (not verified yet)."
    }
    return "Checking\u2026"
  }

  function computeSettingsItems() {
    var s = root.service
    var items = []
    if (!s || !s.ready) return items
    var state = String(s.credentialState)
    if (state === "missing") items.push("connect")
    else if (state === "invalid") items.push("reconnect", "disconnect")
    else if (state === "present" || state === "valid") items.push("check", "disconnect")
    items.push("watcher")
    if (s.watcherEnabled) items.push("notifyAll")
    items.push("pluginScan")
    if (s.pluginScanEnabled) items.push("pluginUpload")
    return items
  }

  function settingHasCursor(id) {
    return root.cursorActive && root.tab === "settings" && root.settingsItems[root.settingsIndex] === id
  }

  function hoverSetting(id) {
    var i = root.settingsItems.indexOf(id)
    if (i < 0) return
    root.cursorActive = true
    root.settingsIndex = i
  }

  function activateSetting(id) {
    var s = root.service
    if (!s) return
    if (id === "connect") s.connect()
    else if (id === "reconnect") s.reconnect()
    else if (id === "check") s.checkAccess(true)
    else if (id === "disconnect") root.askConfirm("disconnect")
    else if (id === "watcher" && s.watcherAvailable && !s.standalone) s.setWatcherEnabled(!s.watcherEnabled)
    else if (id === "notifyAll") s.setNotifyAll(!s.notifyAll)
    else if (id === "pluginScan" && !s.standalone) s.setPluginScanEnabled(!s.pluginScanEnabled)
    else if (id === "pluginUpload") {
      // Turning automatic uploads on needs consent; turning them off does not.
      if (s.pluginAutoUpload) s.setPluginAutoUpload(false)
      else root.askConfirm("autoUpload")
    }
  }

  // --- actions ---------------------------------------------------------------

  function submitScan() {
    if (!root.service) return
    var text = String(searchField.text || "")
    if (text.trim() === "") return
    if (root.service.scan(text, "manual")) searchField.selectAll()
  }

  function checkPath(path) {
    if (!root.service) return
    searchField.text = path
    root.service.scan(path, "manual")
  }

  function openHistory(index) {
    var e = root.history[index]
    if (!e || !root.service || root.busy) return
    root.service.showHistoryEntry(e)
    root.setTab("scan")
  }

  function setTab(t) {
    if (root.tabs.indexOf(t) < 0) return
    if (root.tab !== t) {
      root.tab = t
      flick.contentY = 0
    }
    if (t === "agents" && root.agents) root.agents.probe()
    Qt.callLater(root.restoreFocus)
  }

  function cycleTab(delta) {
    var i = root.tabs.indexOf(root.tab)
    root.setTab(root.tabs[(i + delta + root.tabs.length) % root.tabs.length])
  }

  function askConfirm(purpose) {
    if (!root.service) return
    if (purpose === "upload") {
      if (!root.result || !root.result.canUpload) return
      root._confirmSha = String(root.result.sha256 || "")
    }
    // Consent, disconnect and agent changes default to Cancel; clearing
    // history mirrors the clipboard's default.
    confirmDialog.selectedIndex = purpose === "clear" ? 1 : 0
    root.confirmPurpose = purpose
    Qt.callLater(root.restoreFocus)
  }

  // From AgentsTab: "agentsConnect" or "agentRemove" (id = agent).
  function askAgentConfirm(purpose, id) {
    var m = root.agents
    if (!m || m.busy) return
    if (purpose === "agentsConnect") {
      var plan = m.connectPlan()
      if (plan.empty) {
        m.setMessage(Agents.connectMessage(plan), "muted")
        return
      }
      root._confirmPlan = plan
    } else if (purpose === "agentRemove") {
      var steps = Agents.removeSteps(Agents.rowById(m.rows, id))
      if (!steps.length) return
      root._confirmAgent = id
      root._confirmSteps = steps
    } else {
      return
    }
    root.askConfirm(purpose)
  }

  // "Ask <agent>" on a result or a download alert. The first time, the
  // auto-approve warning comes first.
  function askAgent(r) {
    var s = root.service
    if (!s || !r || !root.agents) return
    if (s.agentHandoffAck) {
      root.agents.handoff(r)
      return
    }
    root._confirmResult = Model.copy(r)
    root.askConfirm("agentHandoff")
  }

  function clearAgentConfirm() {
    root._confirmPlan = null
    root._confirmAgent = ""
    root._confirmSteps = []
    root._confirmResult = null
  }

  function resolveConfirm(accepted) {
    var purpose = root.confirmPurpose
    var s = root.service
    root.confirmPurpose = ""
    if (accepted && s) {
      if (purpose === "upload") {
        if (s.result && s.result.canUpload && s.result.sha256 === root._confirmSha) s.confirmUpload()
      } else if (purpose === "disconnect") {
        s.disconnect()
      } else if (purpose === "clear") {
        s.clearHistory()
        root.historyIndex = 0
      } else if (purpose === "autoUpload") {
        s.setPluginAutoUpload(true)
      } else if (purpose === "agentsConnect" && root._confirmPlan) {
        s.agents.connectAll(root._confirmPlan)
      } else if (purpose === "agentRemove" && root._confirmAgent !== "") {
        s.agents.remove(root._confirmAgent, root._confirmSteps)
      } else if (purpose === "agentHandoff" && root._confirmResult) {
        s.setAgentHandoffAck(true)
        s.agents.handoff(root._confirmResult)
      }
    }
    root._confirmSha = ""
    root.clearAgentConfirm()
    Qt.callLater(root.restoreFocus)
  }

  function confirmMessage() {
    var s = root.service
    if (root.confirmPurpose === "upload") return Model.uploadConsentMessage(root.result)
    if (root.confirmPurpose === "disconnect") {
      return "Disconnect from VirusTotal AI?\n\nThe token in " + (s ? s.authHeaderDisplay : "auth.header")
        + " is revoked and deleted. Other VirusTotal AI tools that use this file stop working until you connect again."
    }
    if (root.confirmPurpose === "clear") return "Clear the scan history?"
    if (root.confirmPurpose === "autoUpload") {
      return "Upload unknown plugin files automatically?\n\n"
        + "When VirusTotal has never seen a file from an installed plugin, the scanner uploads it (up to 32 MB) "
        + "as a standard, non-private submission: it is shared with the VirusTotal security community and partners. "
        + "Don't turn this on if you keep private plugins with credentials or internal code."
    }
    if (root.confirmPurpose === "agentsConnect") return Agents.connectMessage(root._confirmPlan)
    if (root.confirmPurpose === "agentRemove")
      return Agents.removeMessage(root.agents ? Agents.rowById(root.agents.rows, root._confirmAgent) : null)
    if (root.confirmPurpose === "agentHandoff") return Agents.handoffMessage(root.agents ? root.agents.defaultName : "")
    return ""
  }

  function confirmLabel() {
    if (root.confirmPurpose === "upload" || root.confirmPurpose === "autoUpload") return "Upload"
    if (root.confirmPurpose === "disconnect") return "Disconnect"
    if (root.confirmPurpose === "agentsConnect") return "Connect"
    if (root.confirmPurpose === "agentRemove") return "Remove"
    if (root.confirmPurpose === "agentHandoff") return "Ask"
    return "Clear"
  }

  function restoreFocus() {
    if (!root.opened) return
    if (root.confirmOpen) dialogKeys.forceActiveFocus()
    else if (root.tab === "scan" && searchField.visible && searchField.enabled) searchField.forceActiveFocus()
    else keyCatcher.forceActiveFocus()
  }

  function saveApiKeyField() {
    const key = apiKeyField.text.trim()
    if (!root.service || root.service.apiKeyBusy || key === "") return
    root.service.saveApiKey(key)
    apiKeyField.text = ""
    root.leaveField()
  }

  function leaveField() {
    root.cursorActive = true
    keyCatcher.forceActiveFocus()
  }

  function moveCursor(dx, dy) {
    if (dx !== 0) {
      root.cycleTab(dx > 0 ? 1 : -1)
      return
    }
    if (root.tab === "scan") {
      Qt.callLater(root.restoreFocus)
      return
    }
    if (!root.cursorActive) {
      root.cursorActive = true
      return
    }
    if (root.tab === "history" && root.history.length > 0) {
      root.historyIndex = Math.max(0, Math.min(root.history.length - 1, root.historyIndex + dy))
      root.scrollItemIntoView(historyRepeater.itemAt(root.historyIndex))
    } else if (root.tab === "settings" && root.settingsItems.length > 0) {
      root.settingsIndex = Math.max(0, Math.min(root.settingsItems.length - 1, root.settingsIndex + dy))
    } else if (root.tab === "plugins" && root.pluginRows.length > 0) {
      root.pluginsIndex = Math.max(0, Math.min(root.pluginRows.length - 1, root.pluginsIndex + dy))
    } else if (root.tab === "agents" && root.agentItems.length > 0) {
      root.agentsIndex = Math.max(0, Math.min(root.agentItems.length - 1, root.agentsIndex + dy))
      root.scrollItemIntoView(agentsTab.itemAt(root.agentsIndex))
    }
  }

  function activateCursor() {
    if (root.tab === "scan") {
      Qt.callLater(root.restoreFocus)
    } else if (root.tab === "history") {
      if (root.cursorActive) root.openHistory(root.historyIndex)
      else root.cursorActive = true
    } else if (root.tab === "settings") {
      if (root.cursorActive) root.activateSetting(root.settingsItems[root.settingsIndex])
      else root.cursorActive = true
    } else if (root.tab === "plugins") {
      var row = root.pluginRows[root.pluginsIndex]
      if (root.cursorActive && row) pluginsTab.toggle(row.id)
      else root.cursorActive = true
    } else if (root.tab === "agents") {
      if (root.cursorActive) agentsTab.activate(root.agentItems[root.agentsIndex])
      else root.cursorActive = true
    }
  }

  function handleTextKey(t) {
    if (t.length === 1 && t >= "1" && t <= String(root.tabs.length)) {
      root.setTab(root.tabs[Number(t) - 1])
    } else if (t === "/") {
      root.setTab("scan")
    } else if (root.tab === "scan" && searchField.enabled) {
      searchField.forceActiveFocus()
      searchField.insert(searchField.cursorPosition, t)
    }
  }

  function scrollItemIntoView(item) {
    if (!item) return
    Qt.callLater(function() {
      if (!item) return
      var margin = Style.space(6)
      var top = item.mapToItem(flick.contentItem, 0, 0).y
      var bottom = top + item.height
      var maxY = Math.max(0, flick.contentHeight - flick.height)
      if (top < flick.contentY + margin) flick.contentY = Math.max(0, top - margin)
      else if (bottom > flick.contentY + flick.height - margin) flick.contentY = Math.min(maxY, bottom + margin - flick.height)
    })
  }

  // The service counts open panels (one per monitor at most) so it knows
  // whether a finished analysis is already on screen.
  function syncServiceVisibility() {
    var want = root.opened && root.service ? root.service : null
    if (want === root._notifiedService) return
    var previous = root._notifiedService
    root._notifiedService = want
    try {
      if (previous && typeof previous.panelClosed === "function") previous.panelClosed()
    } catch (e) {}
    if (want) want.panelOpened()
  }

  function open() {
    root.controller.show()
  }

  function close() {
    root.controller.hide()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.hostWidget || root, direction)
    return false
  }

  onOpenedChanged: {
    if (root.opened) {
      root.now = Date.now()
      root.cursorActive = false
      root.tab = "scan"
      flick.contentY = 0
      Qt.callLater(function() { if (root.opened && root.tab === "scan") searchField.selectAll() })
    } else {
      root.confirmPurpose = ""
      root._confirmSha = ""
      root.clearAgentConfirm()
    }
    root.syncServiceVisibility()
  }
  onServiceChanged: root.syncServiceVisibility()
  onResultChanged: {
    if (root.confirmPurpose === "upload"
        && (!root.result || !root.result.canUpload || root.result.sha256 !== root._confirmSha))
      root.resolveConfirm(false)
  }
  onHistoryChanged: {
    if (root.historyIndex >= root.history.length) root.historyIndex = Math.max(0, root.history.length - 1)
  }
  onPluginRowsChanged: {
    if (root.pluginsIndex >= root.pluginRows.length) root.pluginsIndex = Math.max(0, root.pluginRows.length - 1)
  }
  onAgentItemsChanged: {
    if (root.agentsIndex >= root.agentItems.length) root.agentsIndex = Math.max(0, root.agentItems.length - 1)
  }
  onSettingsItemsChanged: {
    if (root.settingsIndex >= root.settingsItems.length) root.settingsIndex = Math.max(0, root.settingsItems.length - 1)
  }
  Component.onDestruction: {
    try {
      if (root._notifiedService) root._notifiedService.panelClosed()
    } catch (e) {}
  }

  // Relative times ("5 min ago") refresh while the panel is visible.
  Timer {
    interval: 30000
    repeat: true
    running: root.opened
    onTriggered: root.now = Date.now()
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
    bar: root.bar
    open: root.opened
    focusTarget: root.tab === "scan" && root.ready && !root.confirmOpen ? searchField : keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(420))
    // Ceil, never round: fittedContentHeight() rounds to whole pixels, so a
    // fractional column height could leave the viewport up to half a pixel
    // short, and at fractional scales the clip then ate the whole bottom
    // border of the last button. The column's bottomPadding adds slack.
    contentHeight: panel.fittedContentHeight(root.confirmOpen
      ? Math.max(Math.ceil(column.implicitHeight), Style.space(300))
      : Math.ceil(column.implicitHeight), Style.space(680))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: root.fieldFocused || root.confirmOpen
      onMoveRequested: function(dx, dy) { root.moveCursor(dx, dy) }
      onActivateRequested: root.activateCursor()
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onDeleteRequested: if (root.tab === "history" && root.history.length > 0) root.askConfirm("clear")
      onTextKey: function(t) { root.handleTextKey(t) }

      Flickable {
        id: flick
        anchors.fill: parent
        contentWidth: width
        contentHeight: Math.ceil(column.implicitHeight)
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: flick.width
          spacing: Style.space(12)
          bottomPadding: Style.space(4)

          // ---- header: mark, title and tabs; status below ---------------------
          Column {
            width: parent.width
            spacing: Style.space(2)

            Item {
              width: parent.width
              implicitHeight: Math.max(headerTitle.implicitHeight, tabGroup.implicitHeight, headerIcon.height)

              VirusTotalIcon {
                id: headerIcon
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                iconSize: Style.space(20)
                color: root.foreground
              }

              Text {
                id: headerTitle
                anchors.left: headerIcon.right
                anchors.leftMargin: Style.space(10)
                anchors.right: tabGroup.left
                anchors.rightMargin: Style.space(8)
                anchors.verticalCenter: parent.verticalCenter
                textFormat: Text.PlainText
                text: "VirusTotal"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
                elide: Text.ElideRight
              }

              ButtonGroup {
                id: tabGroup
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                spacing: Style.space(4)
                focusable: false
                value: root.tab
                options: [
                  { value: "scan", label: "", icon: Model.Glyph.magnify, tooltip: "Scan" },
                  { value: "history", label: "", icon: Model.Glyph.history, tooltip: "History" },
                  { value: "plugins", label: "", icon: Model.Glyph.puzzle, tooltip: "Plugins" },
                  { value: "agents", label: "", icon: Model.Glyph.robot, tooltip: "Agents" },
                  { value: "settings", label: "", icon: Model.Glyph.cog, tooltip: "Settings" }
                ]
                foreground: root.foreground
                background: "transparent"
                fontFamily: root.fontFamily
                onChanged: function(value) { root.setTab(value) }
              }
            }

            // Its own full-width line, aligned under the title: beside five
            // tabs only ~25 caption characters fit, so the status was elided.
            // It wraps instead, so it is never cut whatever the font size.
            Text {
              textFormat: Text.PlainText
              width: parent.width
              leftPadding: headerIcon.width + Style.space(10)
              text: root.statusLine()
              color: root.service && root.service.credentialState === "invalid" ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.Wrap
            }
          }

          PanelSeparator {
            width: parent.width
            foreground: root.foreground
          }

          Text {
            textFormat: Text.PlainText
            visible: !root.ready
            width: parent.width
            text: "Starting\u2026"
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          // ================================================================
          // Scan tab
          // ================================================================
          Column {
            id: scanTab
            visible: root.tab === "scan" && root.ready
            width: parent.width
            spacing: Style.space(12)

            Text {
              textFormat: Text.PlainText
              visible: !!root.service && root.service.missingTools !== ""
              width: parent.width
              text: root.service ? "Required tools not found: " + root.service.missingTools + ". Install them and reopen this panel." : ""
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
            }

            // ---- connect card -------------------------------------------
            BorderSurface {
              id: connectCard
              visible: root.showConnectCard
              width: parent.width
              implicitHeight: connectColumn.implicitHeight + connectCard.contentTopInset + connectCard.contentBottomInset
              color: Util.alpha(root.foreground, 0.04)
              borderSpec: Border.flat(root.credentialState === "invalid" ? Util.alpha(root.urgent, 0.6) : root.cardBorder, Style.normalBorderWidth)
              radius: Style.cornerRadius
              padding: Style.space(12)

              Column {
                id: connectColumn
                x: connectCard.contentLeftInset
                y: connectCard.contentTopInset
                width: connectCard.width - connectCard.contentLeftInset - connectCard.contentRightInset
                spacing: Style.space(8)

                Row {
                  width: parent.width
                  spacing: Style.space(8)

                  Text {
                    id: connectGlyph
                    textFormat: Text.PlainText
                    text: root.credentialState === "invalid" ? Model.Glyph.alertCircle : Model.Glyph.key
                    color: root.credentialState === "invalid" ? root.urgent : root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.iconLarge
                    anchors.verticalCenter: parent.verticalCenter
                  }

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width - connectGlyph.width - parent.spacing
                    text: root.credentialState === "invalid" ? "VirusTotal AI rejected the saved token" : "Connect to VirusTotal AI"
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.subtitle
                    font.bold: true
                    wrapMode: Text.Wrap
                    anchors.verticalCenter: parent.verticalCenter
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: root.credentialState === "invalid"
                    ? "Reconnect revokes and deletes the saved token, then registers this computer again."
                    : "Registers this computer once as an \u201comarchy\u201d agent. No API key is needed. The token is saved to "
                      + (root.service ? root.service.authHeaderDisplay : "") + " (mode 600), where other VirusTotal AI tools can reuse it. "
                      + "Free quota: 60 lookups per minute, 1,000 per day."
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.Wrap
                }

                Text {
                  textFormat: Text.PlainText
                  visible: !!root.service && root.service.pendingScan !== ""
                  width: parent.width
                  text: root.service ? "Connect to check \u201c" + Model.truncate(root.service.pendingScan, 80) + "\u201d." : ""
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.Wrap
                }

                Text {
                  textFormat: Text.PlainText
                  visible: !!root.service && root.service.connectError !== ""
                  width: parent.width
                  text: root.service ? root.service.connectError : ""
                  color: root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.Wrap
                }

                Row {
                  spacing: Style.space(6)

                  Button {
                    text: root.service && (root.service.connecting || root.service.accountBusy) ? "Connecting\u2026"
                      : (root.credentialState === "invalid" ? "Reconnect" : "Connect")
                    iconText: Model.Glyph.login
                    bordered: true
                    enabled: root.accountIdle
                    opacity: enabled ? 1 : 0.55
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: {
                      if (root.credentialState === "invalid") root.service.reconnect()
                      else root.service.connect()
                    }
                  }

                  Button {
                    visible: !!root.service && root.service.pendingScan !== ""
                    text: "Cancel"
                    bordered: true
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.service.cancelPending()
                  }
                }
              }
            }

            // ---- watcher alert ------------------------------------------
            BorderSurface {
              id: alertCard
              readonly property color tone: root.alert && root.alert.stats && root.alert.stats.malicious > 0 ? root.urgent : root.warning
              visible: !!root.alert
              width: parent.width
              implicitHeight: alertColumn.implicitHeight + alertCard.contentTopInset + alertCard.contentBottomInset
              color: Util.alpha(alertCard.tone, 0.1)
              borderSpec: Border.flat(Util.alpha(alertCard.tone, 0.6), Style.normalBorderWidth)
              radius: Style.cornerRadius
              padding: Style.space(10)

              Column {
                id: alertColumn
                x: alertCard.contentLeftInset
                y: alertCard.contentTopInset
                width: alertCard.width - alertCard.contentLeftInset - alertCard.contentRightInset
                spacing: Style.space(8)

                Row {
                  width: parent.width
                  spacing: Style.space(8)

                  Text {
                    id: alertGlyph
                    textFormat: Text.PlainText
                    text: Model.verdictGlyph(root.alert)
                    color: alertCard.tone
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.iconLarge
                    anchors.verticalCenter: parent.verticalCenter
                  }

                  Column {
                    width: parent.width - alertGlyph.width - parent.spacing
                    spacing: Style.space(2)
                    anchors.verticalCenter: parent.verticalCenter

                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      text: root.alert
                        ? "Flagged download: " + Model.displayTarget(root.alert)
                        : ""
                      color: alertCard.tone
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      font.bold: true
                      elide: Text.ElideMiddle
                    }

                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      text: root.alert ? Model.summaryLine(root.alert) : ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.Wrap
                    }
                  }
                }

                Row {
                  spacing: Style.space(6)

                  Button {
                    text: "View"
                    iconText: Model.Glyph.eye
                    bordered: true
                    enabled: !root.busy
                    opacity: enabled ? 1 : 0.55
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.service.viewAlert()
                  }

                  Button {
                    text: "Dismiss"
                    bordered: true
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.service.acknowledgeAlert()
                  }

                  Button {
                    visible: root.showAlertAsk
                    text: "Ask " + (root.agents ? root.agents.defaultName : "")
                    iconText: Model.Glyph.robot
                    tooltipText: "Open Omarchy's default agent with this alert"
                    bordered: true
                    enabled: !!root.agents && !root.agents.handoffBusy
                    opacity: enabled ? 1 : 0.55
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.askAgent(root.alert)
                  }
                }
              }
            }

            // ---- input --------------------------------------------------
            Item {
              width: parent.width
              implicitHeight: Math.max(searchField.implicitHeight, scanButton.implicitHeight)

              TextField {
                id: searchField
                anchors.left: parent.left
                anchors.right: scanButton.left
                anchors.rightMargin: Style.space(6)
                anchors.verticalCenter: parent.verticalCenter
                placeholderText: "URL, domain, IP, hash or file path"
                foreground: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                enabled: root.ready
                selectByMouse: true
                onAccepted: root.submitScan()
                Keys.onEscapePressed: root.close()
                Keys.onTabPressed: root.switchPanel(1)
                Keys.onBacktabPressed: root.switchPanel(-1)
                Keys.onUpPressed: root.leaveField()
                Keys.onDownPressed: root.leaveField()
              }

              Button {
                id: scanButton
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                text: "Scan"
                iconText: Model.Glyph.magnify
                bordered: true
                enabled: root.ready && !root.busy && searchField.text.trim() !== ""
                opacity: enabled ? 1 : 0.55
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.submitScan()
              }
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: "To check a file, enter its path (e.g. ~/Downloads/setup.sh) or press Check on a recent download. Only its hash is sent; if VirusTotal has never seen it, you can upload it after confirming."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.Wrap
            }

            Row {
              visible: root.busy
              width: parent.width
              spacing: Style.space(8)

              Text {
                id: busyGlyph
                textFormat: Text.PlainText
                text: Model.Glyph.refresh
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                anchors.verticalCenter: parent.verticalCenter

                RotationAnimation on rotation {
                  from: 0
                  to: 360
                  duration: 900
                  loops: Animation.Infinite
                  running: root.busy && root.opened && !Style.reduceMotion
                }
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width - busyGlyph.width - parent.spacing
                text: root.service ? root.service.busyLabel : ""
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                elide: Text.ElideRight
                anchors.verticalCenter: parent.verticalCenter
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: !!root.service && root.service.errorMessage !== ""
              width: parent.width
              text: root.service ? root.service.errorMessage : ""
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
            }

            // "Ask <agent>" feedback: opened, or why it could not.
            Text {
              textFormat: Text.PlainText
              visible: !!root.agents && root.agents.handoffNote !== ""
              width: parent.width
              text: root.agents ? root.agents.handoffNote : ""
              color: root.roleColor(root.agents ? root.agents.handoffRole : "muted")
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
            }

            // ---- result -------------------------------------------------
            BorderSurface {
              id: resultCard
              visible: !!root.result
              width: parent.width
              implicitHeight: resultColumn.implicitHeight + resultCard.contentTopInset + resultCard.contentBottomInset
              color: Util.alpha(root.resultColor, 0.06)
              borderSpec: Border.flat(Util.alpha(root.resultColor, 0.45), Style.normalBorderWidth)
              radius: Style.cornerRadius
              padding: Style.space(12)

              Column {
                id: resultColumn
                x: resultCard.contentLeftInset
                y: resultCard.contentTopInset
                width: resultCard.width - resultCard.contentLeftInset - resultCard.contentRightInset
                spacing: Style.space(6)

                Item {
                  width: parent.width
                  implicitHeight: Math.max(verdictRow.implicitHeight, dismissButton.implicitHeight)

                  Row {
                    id: verdictRow
                    anchors.left: parent.left
                    anchors.right: dismissButton.left
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(8)

                    Text {
                      textFormat: Text.PlainText
                      text: Model.verdictGlyph(root.result)
                      color: root.resultColor
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.iconLarge
                      anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                      textFormat: Text.PlainText
                      text: Model.verdictLabel(root.result)
                      color: root.resultColor
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.heading
                      font.bold: true
                      anchors.verticalCenter: parent.verticalCenter
                    }
                  }

                  Button {
                    id: dismissButton
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    visible: !root.busy
                    iconText: Model.Glyph.close
                    tooltipText: "Dismiss"
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.service.dismissResult()
                  }
                }

                Row {
                  width: parent.width
                  spacing: Style.space(6)

                  Text {
                    id: kindGlyph
                    textFormat: Text.PlainText
                    text: root.result ? Model.kindGlyph(root.result.kind) : ""
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    anchors.verticalCenter: parent.verticalCenter
                  }

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width - kindGlyph.width - parent.spacing
                    text: Model.displayTarget(root.result)
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    // A hash wraps instead: it is never shown shortened.
                    elide: Model.isHash(text) ? Text.ElideNone : Text.ElideMiddle
                    wrapMode: Model.isHash(text) ? Text.WrapAnywhere : Text.NoWrap
                    anchors.verticalCenter: parent.verticalCenter
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  visible: text !== ""
                  width: parent.width
                  text: Model.summaryLine(root.result)
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.Wrap
                }

                Text {
                  textFormat: Text.PlainText
                  visible: !!root.result && !!root.result.topDetections && root.result.topDetections.length > 0
                  width: parent.width
                  text: root.result && root.result.topDetections ? "Detections: " + root.result.topDetections.join(", ") : ""
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.Wrap
                }

                Text {
                  textFormat: Text.PlainText
                  visible: !!root.result && !!root.result.typeDescription
                  width: parent.width
                  text: root.result && root.result.typeDescription ? "Type: " + root.result.typeDescription : ""
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }

                Column {
                  visible: !!root.result && !!root.result.insight && String(root.result.insight.analysis || "") !== ""
                  width: parent.width
                  spacing: Style.space(2)

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    text: root.result ? root.insightTitle(root.result.insight) : ""
                    color: root.result && root.result.insight
                      && (root.result.insight.verdict === "malicious" || root.result.insight.verdict === "suspicious")
                      ? root.warning : root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    elide: Text.ElideRight
                  }

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    text: root.result && root.result.insight ? String(root.result.insight.analysis || "") : ""
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.Wrap
                    maximumLineCount: 6
                    elide: Text.ElideRight
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  visible: text !== ""
                  width: parent.width
                  text: root.resultMeta(root.result)
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }

                Text {
                  textFormat: Text.PlainText
                  visible: text !== ""
                  width: parent.width
                  text: root.resultSha(root.result)
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WrapAnywhere
                }

                Flow {
                  width: parent.width
                  spacing: Style.space(6)
                  visible: root.showOpenAction || root.showUploadAction || root.showStatusAction || root.showAgainAction
                    || root.showAskAction

                  Button {
                    id: openButton
                    visible: root.showOpenAction
                    text: "Open report"
                    iconText: Model.Glyph.openInNew
                    bordered: true
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.service.openReport(root.result.reportUrl)
                  }

                  Button {
                    id: uploadButton
                    visible: root.showUploadAction
                    text: "Upload for analysis"
                    iconText: Model.Glyph.cloudUpload
                    bordered: true
                    enabled: !root.busy
                    opacity: enabled ? 1 : 0.55
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.askConfirm("upload")
                  }

                  Button {
                    id: statusButton
                    visible: root.showStatusAction
                    text: "Check status"
                    iconText: Model.Glyph.refresh
                    bordered: true
                    enabled: !root.busy
                    opacity: enabled ? 1 : 0.55
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.service.checkSubmission()
                  }

                  Button {
                    id: againButton
                    visible: root.showAgainAction
                    text: "Check again"
                    iconText: Model.Glyph.refresh
                    bordered: true
                    enabled: !!root.service && !root.service.pollInFlight
                    opacity: enabled ? 1 : 0.55
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.service.checkAgain()
                  }

                  Button {
                    id: askButton
                    visible: root.showAskAction
                    text: "Ask " + (root.agents ? root.agents.defaultName : "")
                    iconText: Model.Glyph.robot
                    tooltipText: "Open Omarchy's default agent with this result"
                    bordered: true
                    enabled: !!root.agents && !root.agents.handoffBusy
                    opacity: enabled ? 1 : 0.55
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.askAgent(root.result)
                  }
                }
              }
            }

            // ---- recent downloads ---------------------------------------
            Column {
              visible: root.recent.length > 0
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: "RECENT DOWNLOADS"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Repeater {
                model: root.recent

                delegate: Item {
                  id: recentRow
                  required property var modelData
                  width: parent ? parent.width : 0
                  implicitHeight: Math.max(recentText.implicitHeight, recentButton.implicitHeight)

                  Column {
                    id: recentText
                    anchors.left: parent.left
                    anchors.right: recentButton.left
                    anchors.rightMargin: Style.space(8)
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(1)

                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      text: String(recentRow.modelData.name || "")
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.bodySmall
                      elide: Text.ElideMiddle
                    }

                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      text: [Model.formatBytes(recentRow.modelData.size), Model.timeAgo(recentRow.modelData.mtime, root.now)]
                        .filter(function(part) { return part !== "" }).join(" \u00b7 ")
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      elide: Text.ElideRight
                    }
                  }

                  Button {
                    id: recentButton
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    text: "Check"
                    bordered: true
                    enabled: !root.busy && root.ready
                    opacity: enabled ? 1 : 0.55
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    onClicked: root.checkPath(String(recentRow.modelData.path || ""))
                  }
                }
              }
            }
          }

          // ================================================================
          // History tab
          // ================================================================
          Column {
            id: historyTab
            visible: root.tab === "history" && root.ready
            width: parent.width
            spacing: Style.space(8)

            Item {
              width: parent.width
              implicitHeight: Math.max(historyCount.implicitHeight, clearButton.implicitHeight)

              Text {
                id: historyCount
                textFormat: Text.PlainText
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                text: root.history.length === 0 ? "" : root.history.length === 1 ? "1 check" : root.history.length + " checks"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              Button {
                id: clearButton
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                visible: root.history.length > 0
                text: "Clear"
                iconText: Model.Glyph.trash
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.askConfirm("clear")
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: root.history.length === 0
              width: parent.width
              text: "Nothing checked yet. Results from the Scan tab and the Downloads watcher appear here."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
            }

            Column {
              id: historyColumn
              width: parent.width
              spacing: Style.space(2)

              Repeater {
                id: historyRepeater
                model: root.history

                delegate: CursorSurface {
                  id: historyRow
                  required property var modelData
                  required property int index
                  readonly property color tone: root.roleColor(Model.verdictRole(historyRow.modelData))
                  width: historyColumn.width
                  implicitHeight: historyContent.implicitHeight + Style.space(12)
                  foreground: root.foreground
                  hasCursor: root.cursorActive && root.historyIndex === historyRow.index

                  Row {
                    id: historyContent
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.leftMargin: Style.space(8)
                    anchors.rightMargin: Style.space(8)
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(8)

                    Text {
                      id: historyGlyph
                      textFormat: Text.PlainText
                      text: Model.verdictGlyph(historyRow.modelData)
                      color: historyRow.tone
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.icon
                      anchors.verticalCenter: parent.verticalCenter
                    }

                    Column {
                      width: parent.width - historyGlyph.width - sourceGlyph.width - parent.spacing * 2
                      spacing: Style.space(1)
                      anchors.verticalCenter: parent.verticalCenter

                      Text {
                        textFormat: Text.PlainText
                        width: parent.width
                        text: Model.displayTarget(historyRow.modelData)
                        color: root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        elide: Model.isHash(text) ? Text.ElideNone : Text.ElideMiddle
                        wrapMode: Model.isHash(text) ? Text.WrapAnywhere : Text.NoWrap
                      }

                      Text {
                        textFormat: Text.PlainText
                        width: parent.width
                        text: root.entrySubline(historyRow.modelData)
                        color: historyRow.modelData.status === "found" && historyRow.modelData.verdict !== "undetected"
                          && historyRow.modelData.verdict !== "unknown" ? historyRow.tone : root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                      }
                    }

                    Text {
                      id: sourceGlyph
                      textFormat: Text.PlainText
                      text: historyRow.modelData.source === "watcher" ? Model.Glyph.eye
                        : historyRow.modelData.source === "plugins" ? Model.Glyph.puzzle : ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.bodySmall
                      anchors.verticalCenter: parent.verticalCenter
                    }
                  }

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onEntered: {
                      root.cursorActive = true
                      root.historyIndex = historyRow.index
                    }
                    onClicked: root.openHistory(historyRow.index)
                  }
                }
              }
            }
          }

          // ================================================================
          // Plugins tab
          // ================================================================
          PluginsTab {
            id: pluginsTab
            visible: root.tab === "plugins" && root.ready
            width: parent.width
            panel: root
            service: root.service
            now: root.now
            cursorActive: root.cursorActive && root.tab === "plugins"
            cursorIndex: root.pluginsIndex
            onCursorRequested: index => {
              root.cursorActive = true
              root.pluginsIndex = index
            }
            onOpenSettings: root.setTab("settings")
          }

          // ================================================================
          // Agents tab
          // ================================================================
          AgentsTab {
            id: agentsTab
            visible: root.tab === "agents" && root.ready
            width: parent.width
            panel: root
            service: root.service
            cursorActive: root.cursorActive && root.tab === "agents"
            cursorIndex: root.agentsIndex
            onCursorRequested: index => {
              root.cursorActive = true
              root.agentsIndex = index
            }
            onConfirmRequested: (purpose, id) => root.askAgentConfirm(purpose, id)
          }

          // ================================================================
          // Settings tab
          // ================================================================
          Column {
            id: settingsTab
            visible: root.tab === "settings" && root.ready
            width: parent.width
            spacing: Style.space(10)

            PanelSectionHeader {
              text: "ACCOUNT"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.accountLine()
              color: root.credentialState === "invalid" ? root.urgent : root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
            }

            Flow {
              width: parent.width
              spacing: Style.space(6)

              Button {
                visible: root.settingsItems.indexOf("connect") >= 0
                text: root.service && root.service.connecting ? "Connecting\u2026" : "Connect"
                iconText: Model.Glyph.login
                bordered: true
                hasCursor: root.settingHasCursor("connect")
                enabled: root.accountIdle
                opacity: enabled ? 1 : 0.55
                foreground: root.foreground
                fontFamily: root.fontFamily
                onHovered: function(h) { if (h) root.hoverSetting("connect") }
                onClicked: root.activateSetting("connect")
              }

              Button {
                visible: root.settingsItems.indexOf("reconnect") >= 0
                text: root.service && (root.service.connecting || root.service.accountBusy) ? "Reconnecting\u2026" : "Reconnect"
                iconText: Model.Glyph.login
                bordered: true
                hasCursor: root.settingHasCursor("reconnect")
                enabled: root.accountIdle
                opacity: enabled ? 1 : 0.55
                foreground: root.foreground
                fontFamily: root.fontFamily
                onHovered: function(h) { if (h) root.hoverSetting("reconnect") }
                onClicked: root.activateSetting("reconnect")
              }

              Button {
                visible: root.settingsItems.indexOf("check") >= 0
                text: root.service && root.service.checkingAccess ? "Checking\u2026" : "Check access"
                iconText: Model.Glyph.shieldCheck
                bordered: true
                hasCursor: root.settingHasCursor("check")
                enabled: root.accountIdle && !!root.service && !root.service.checkingAccess
                opacity: enabled ? 1 : 0.55
                foreground: root.foreground
                fontFamily: root.fontFamily
                onHovered: function(h) { if (h) root.hoverSetting("check") }
                onClicked: root.activateSetting("check")
              }

              Button {
                visible: root.settingsItems.indexOf("disconnect") >= 0
                text: root.service && root.service.accountBusy ? "Disconnecting\u2026" : "Disconnect"
                iconText: Model.Glyph.logout
                bordered: true
                hasCursor: root.settingHasCursor("disconnect")
                enabled: root.accountIdle
                opacity: enabled ? 1 : 0.55
                foreground: root.foreground
                fontFamily: root.fontFamily
                onHovered: function(h) { if (h) root.hoverSetting("disconnect") }
                onClicked: root.activateSetting("disconnect")
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: text !== ""
              width: parent.width
              text: root.service ? (root.service.connectError !== "" ? root.service.connectError : root.service.accountMessage) : ""
              color: root.service && root.service.connectError !== "" ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.Wrap
            }

            PanelSeparator {
              width: parent.width
              foreground: root.foreground
            }

            PanelSectionHeader {
              text: "DOWNLOADS"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Toggle {
              width: parent.width
              label: "Check new downloads"
              description: "Looks up the SHA-256 of each new file in "
                + (root.service && root.service.downloadsDisplay !== "" ? root.service.downloadsDisplay : "the Downloads folder")
                + ". Nothing is uploaded automatically."
              checked: !!root.service && root.service.watcherEnabled
              hasCursor: root.settingHasCursor("watcher")
              enabled: !!root.service && root.service.watcherAvailable && !root.service.standalone
              opacity: enabled ? 1 : 0.55
              foreground: root.foreground
              fontFamily: root.fontFamily
              onHovered: function(h) { if (h) root.hoverSetting("watcher") }
              onClicked: root.activateSetting("watcher")
            }

            Toggle {
              visible: !!root.service && root.service.watcherEnabled
              width: parent.width
              label: "Notify for every checked file"
              description: "Otherwise only downloads flagged by VirusTotal notify."
              checked: !!root.service && root.service.notifyAll
              hasCursor: root.settingHasCursor("notifyAll")
              foreground: root.foreground
              fontFamily: root.fontFamily
              onHovered: function(h) { if (h) root.hoverSetting("notifyAll") }
              onClicked: root.activateSetting("notifyAll")
            }

            Text {
              textFormat: Text.PlainText
              visible: text !== ""
              width: parent.width
              text: root.watcherStatus()
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.Wrap
            }

            PanelSeparator {
              width: parent.width
              foreground: root.foreground
            }

            PanelSectionHeader {
              text: "PLUGINS"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Toggle {
              width: parent.width
              label: "Check installed plugins"
              description: "Hashes every file of new and updated plugins in "
                + (root.service ? Model.displayPath(root.service.pluginsDir, root.service.homeDir) : "~/.config/omarchy/plugins")
                + " and looks each SHA-256 up with VirusTotal."
              checked: !!root.service && root.service.pluginScanEnabled
              hasCursor: root.settingHasCursor("pluginScan")
              enabled: !!root.service && !root.service.standalone
              opacity: enabled ? 1 : 0.55
              foreground: root.foreground
              fontFamily: root.fontFamily
              onHovered: function(h) { if (h) root.hoverSetting("pluginScan") }
              onClicked: root.activateSetting("pluginScan")
            }

            Column {
              visible: !!root.service && root.service.pluginScanEnabled
              width: parent.width
              spacing: Style.space(10)

              Toggle {
                width: parent.width
                label: "Upload unknown plugin files automatically"
                description: "Files VirusTotal has never seen are uploaded as standard (public) submissions. Off: they are only reported as unknown."
                checked: !!root.service && root.service.pluginAutoUpload
                hasCursor: root.settingHasCursor("pluginUpload")
                foreground: root.foreground
                fontFamily: root.fontFamily
                onHovered: function(h) { if (h) root.hoverSetting("pluginUpload") }
                onClicked: root.activateSetting("pluginUpload")
              }

              Dropdown {
                width: parent.width
                label: "Engine"
                value: root.service ? root.service.pluginBackend : "vtai"
                options: [
                  { value: "vtai", label: "VirusTotal AI (connected account)" },
                  { value: "classic", label: "VirusTotal API key" }
                ]
                foreground: root.foreground
                fontFamily: root.fontFamily
                onChanged: function(value) { if (root.service) root.service.setPluginBackend(value) }
              }

              Column {
                visible: !!root.service && root.service.pluginBackend === "classic"
                width: parent.width
                spacing: Style.space(8)

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: !root.service ? ""
                    : root.service.apiKeyState === "present" ? "API key saved in " + root.service.apiKeyDisplay + "."
                    : root.service.apiKeyState === "invalid" ? "VirusTotal rejected the key in " + root.service.apiKeyDisplay + "."
                    : "No API key saved. Paste yours from virustotal.com (profile \u2192 API key)."
                  color: root.service && root.service.apiKeyState === "invalid" ? root.urgent : root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.Wrap
                }

                Item {
                  width: parent.width
                  implicitHeight: Math.max(apiKeyField.implicitHeight, apiKeyButtons.implicitHeight)

                  TextField {
                    id: apiKeyField
                    anchors.left: parent.left
                    anchors.right: apiKeyButtons.left
                    anchors.rightMargin: Style.space(6)
                    anchors.verticalCenter: parent.verticalCenter
                    password: true
                    placeholderText: root.service && root.service.apiKeyState !== "missing" ? "Replace the API key" : "VirusTotal API key"
                    foreground: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    selectByMouse: true
                    onAccepted: root.saveApiKeyField()
                    Keys.onEscapePressed: root.leaveField()
                  }

                  Row {
                    id: apiKeyButtons
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(4)

                    Button {
                      id: saveKeyButton
                      text: "Save"
                      iconText: Model.Glyph.key
                      bordered: true
                      enabled: !!root.service && !root.service.apiKeyBusy && apiKeyField.text.trim() !== ""
                      opacity: enabled ? 1 : 0.55
                      foreground: root.foreground
                      fontFamily: root.fontFamily
                      onClicked: root.saveApiKeyField()
                    }

                    Button {
                      visible: !!root.service && root.service.apiKeyState !== "missing"
                      iconText: Model.Glyph.trash
                      tooltipText: "Delete the saved API key"
                      bordered: true
                      enabled: !!root.service && !root.service.apiKeyBusy
                      opacity: enabled ? 1 : 0.55
                      foreground: root.foreground
                      fontFamily: root.fontFamily
                      onClicked: root.service.removeApiKey()
                    }
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  visible: text !== ""
                  width: parent.width
                  text: root.service ? root.service.apiKeyMessage : ""
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.Wrap
                }

                NumberField {
                  id: perMinField
                  width: parent.width
                  label: "Requests per minute"
                  from: 1
                  to: 10000
                  value: root.service ? root.service.classicPerMin : 4
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  onModified: function(v) { if (root.service) root.service.setClassicLimits(v, root.service.classicPerDay) }
                }

                NumberField {
                  id: perDayField
                  width: parent.width
                  label: "Requests per day"
                  from: 1
                  to: 1000000
                  stepSize: 100
                  value: root.service ? root.service.classicPerDay : 500
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  onModified: function(v) { if (root.service) root.service.setClassicLimits(root.service.classicPerMin, v) }
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: "A public API key allows 4 requests per minute and 500 per day, counting lookups, uploads and analysis checks. Raise the limits for a premium key."
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.Wrap
                }
              }

              NumberField {
                id: parallelField
                width: parent.width
                label: "Parallel requests"
                from: 1
                to: 8
                value: root.service ? root.service.maxParallel : 4
                foreground: root.foreground
                fontFamily: root.fontFamily
                onModified: function(v) { if (root.service) root.service.setMaxParallel(v) }
              }
            }

            PanelSeparator {
              width: parent.width
              foreground: root.foreground
            }

            PanelSectionHeader {
              text: "ABOUT"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: "Version " + (root.service ? root.service.pluginVersion : Model.DEFAULT_VERSION)
                + ". Community plugin using the VirusTotal AI API (ai.virustotal.com); the plugin scanner can use a VirusTotal API key (www.virustotal.com) instead."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.Wrap
            }
          }
        }
      }

      // Receives the keys while the confirmation dialog is open.
      Item {
        id: dialogKeys
        Keys.onPressed: function(event) {
          if (!confirmDialog.handleKey(event) && event.key === Qt.Key_Space) {
            if (confirmDialog.selectedIndex === 0) root.resolveConfirm(false)
            else root.resolveConfirm(true)
          }
          event.accepted = true
        }
      }

      ConfirmDialog {
        id: confirmDialog
        anchors.fill: parent
        z: 10
        opened: root.confirmOpen
        message: root.confirmMessage()
        confirmText: root.confirmLabel()
        background: Color.popups.background
        foreground: root.foreground
        fontFamily: root.fontFamily
        onCanceled: root.resolveConfirm(false)
        onConfirmed: root.resolveConfirm(true)
      }
    }
  }
}
