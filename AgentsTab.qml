import QtQuick
import qs.Commons
import qs.Ui
import "Agents.js" as Agents
import "Model.js" as Model

// Agents tab: connects Omarchy's coding agents to the VirusTotal AI MCP
// server and links the virustotal skill. AgentsManager.qml does the work.
//
// Rendering only; Panel.qml passes itself as `panel` for colours and roles,
// and owns the keyboard cursor and the confirmation dialogs (requested with
// confirmRequested). Agent names, states and texts come from Agents.js.
Column {
  id: root

  property var panel: null
  property var service: null
  property bool cursorActive: false
  property int cursorIndex: 0
  property string expanded: ""

  readonly property var manager: service ? service.agents : null
  readonly property var rows: manager && manager.rows ? manager.rows : []
  readonly property var skill: manager && manager.skill ? manager.skill : Agents.skillSummary("")
  readonly property bool busy: !!manager && manager.busy
  readonly property bool hasSkill: !!manager && manager.skillPath !== ""
  // Keyboard cursor stops, top to bottom.
  readonly property var cursorItems: {
    var items = ["connect", "skill"]
    for (var i = 0; i < root.rows.length; i++) items.push(root.rows[i].id)
    items.push("ask")
    return items
  }
  readonly property color foreground: panel ? panel.foreground : Color.foreground
  readonly property color dim: panel ? panel.dim : Color.foreground
  readonly property string fontFamily: panel ? panel.fontFamily : Style.font.family

  signal cursorRequested(int index)
  signal confirmRequested(string purpose, string id)

  spacing: Style.space(10)

  function tone(role) {
    return root.panel ? root.panel.roleColor(role) : root.foreground
  }

  function hasCursor(id) {
    return root.cursorActive && root.cursorItems[root.cursorIndex] === id
  }

  function hover(id) {
    var i = root.cursorItems.indexOf(id)
    if (i >= 0) root.cursorRequested(i)
  }

  function toggle(id) {
    root.expanded = root.expanded === id ? "" : id
  }

  // Return on a cursor stop (Panel.activateCursor).
  function activate(id) {
    var m = root.manager
    if (!m) return
    if (id === "connect") {
      if (root.canConnect()) root.confirmRequested("agentsConnect", "")
    } else if (id === "skill") {
      if (root.canLink()) m.linkSkill()
      else if (root.canUnlink()) m.unlinkSkill()
    } else if (id === "ask") {
      if (root.service) root.service.setAgentButtons(!root.service.agentButtons)
    } else {
      root.toggle(id)
    }
  }

  // The item to scroll into view for a cursor stop.
  function itemAt(index) {
    var id = root.cursorItems[index]
    if (id === "connect") return actionRow
    if (id === "skill") return skillItem
    if (id === "ask") return askToggle
    return agentRepeater.itemAt(index - 2)
  }

  function canConnect() {
    return !!root.manager && !root.busy && root.manager.probed && root.manager.recordReady
  }

  function canLink() {
    return root.hasSkill && !root.busy && root.skill.known && root.skill.linkable > 0
  }

  function canUnlink() {
    return root.hasSkill && !root.busy && root.skill.ours + root.skill.stale > 0
  }

  function defaultLine() {
    var m = root.manager
    if (!m || !m.defaultKnown) return "Default agent: checking\u2026"
    if (m.defaultAgent === "") return "Default agent: none chosen yet"
    if (m.defaultState === "installed") return "Default agent: " + m.defaultName
    return "Default agent: " + m.defaultName + " (not installed)"
  }

  function skillLabel() {
    if (!root.hasSkill) return "Skill: unavailable (the plugin is not loaded from a local folder)"
    return "Skill: " + root.skill.text
  }

  function messageText() {
    var m = root.manager
    if (!m) return ""
    if (m.busy) return "Working\u2026"
    return m.message !== "" ? m.message : m.probeError
  }

  function messageRole() {
    var m = root.manager
    if (!m || m.busy) return "muted"
    return m.message !== "" ? m.messageRole : "danger"
  }

  function rowGlyph(r) {
    if (r.busy || r.state === "unknown") return Model.Glyph.progressClock
    if (r.role === "danger") return Model.Glyph.alertCircle
    if (r.state === "added" || r.state === "other") return Model.Glyph.shieldCheck
    if (r.state === "partial") return Model.Glyph.shieldAlert
    if (r.state === "not-added") return Model.Glyph.shieldOutline
    if (r.state === "manual") return Model.Glyph.cog
    if (r.state === "skill") return Model.Glyph.file
    return Model.Glyph.robot
  }

  function rowGlyphColor(r) {
    if (r.state === "added" || r.state === "other") return root.foreground
    return root.tone(r.role)
  }

  function accountsLine(r) {
    if (!r.accounts || r.accounts.length < 2) return ""
    var words = { ours: "added", none: "not added", other: "your own entry", error: "unreadable", unknown: "checking" }
    var parts = []
    for (var i = 0; i < r.accounts.length; i++) {
      var a = r.accounts[i]
      parts.push(a.id + " " + (words[a.state] || a.state) + (a.active ? " (active)" : ""))
    }
    return "Claude accounts: " + parts.join(" \u00b7 ")
  }

  function backupLine(r) {
    var m = root.manager
    var e = m && m.record && m.record.mcp ? m.record.mcp[r.id] : null
    if (!e || !e.backup) return ""
    return "Previous file kept as " + Model.displayPath(e.backup, root.service ? root.service.homeDir : "")
  }

  function hasActions(r) {
    return r.canAdd || r.canSignIn || r.canRemove || r.canCopy || r.guideUrl !== "" || r.link !== ""
  }

  // ---- intro ----------------------------------------------------------------
  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: "Give Omarchy's coding agents VirusTotal AI. Each agent gets the remote MCP server and signs in with your "
      + "Google account once; the virustotal skill tells it how to look things up and report. No token is written to agent settings."
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.Wrap
  }

  Flow {
    id: actionRow
    width: parent.width
    spacing: Style.space(6)

    Button {
      text: "Connect installed agents"
      iconText: Model.Glyph.robot
      bordered: true
      hasCursor: root.hasCursor("connect")
      enabled: root.canConnect()
      opacity: enabled ? 1 : 0.55
      foreground: root.foreground
      fontFamily: root.fontFamily
      onHovered: function(h) { if (h) root.hover("connect") }
      onClicked: root.activate("connect")
    }

    Button {
      text: "VirusTotal access"
      iconText: Model.Glyph.openInNew
      tooltipText: "See or revoke the agents you signed in, on ai.virustotal.com"
      bordered: true
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: if (root.manager) root.manager.openAccess()
    }
  }

  // ---- default agent ----------------------------------------------------------
  Item {
    width: parent.width
    implicitHeight: Math.max(defaultText.implicitHeight, changeButton.implicitHeight)

    Text {
      id: defaultText
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.right: changeButton.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      text: root.defaultLine()
      color: !!root.manager && root.manager.defaultAgent !== "" && root.manager.defaultKnown
        && root.manager.defaultState !== "installed" ? root.tone("warning") : root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.Wrap
    }

    Button {
      id: changeButton
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      text: "Change"
      tooltipText: "Choose the default agent in Omarchy's menu"
      bordered: true
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: if (root.manager) root.manager.changeDefault()
    }
  }

  // ---- skill ------------------------------------------------------------------
  Item {
    id: skillItem
    width: parent.width
    implicitHeight: Math.max(skillInfo.implicitHeight, skillButtons.implicitHeight)

    Column {
      id: skillInfo
      anchors.left: parent.left
      anchors.right: skillButtons.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(2)

      Text {
        textFormat: Text.PlainText
        width: parent.width
        text: root.skillLabel()
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.Wrap
      }

      Text {
        textFormat: Text.PlainText
        visible: text !== ""
        width: parent.width
        text: root.manager && typeof root.manager.errors.skill === "string" ? root.manager.errors.skill : ""
        color: root.tone("danger")
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        wrapMode: Text.Wrap
      }
    }

    Row {
      id: skillButtons
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(4)

      Button {
        id: linkButton
        visible: root.hasSkill
        text: "Link"
        iconText: Model.Glyph.link
        tooltipText: "Link the skill into the agents' skill folders"
        bordered: true
        hasCursor: root.hasCursor("skill") && root.canLink()
        enabled: root.canLink()
        opacity: enabled ? 1 : 0.55
        foreground: root.foreground
        fontFamily: root.fontFamily
        onHovered: function(h) { if (h) root.hover("skill") }
        onClicked: root.manager.linkSkill()
      }

      Button {
        visible: root.hasSkill && root.skill.ours + root.skill.stale > 0
        text: "Unlink"
        iconText: Model.Glyph.linkOff
        tooltipText: "Remove only this plugin's skill links"
        bordered: true
        hasCursor: root.hasCursor("skill") && !root.canLink()
        enabled: root.canUnlink()
        opacity: enabled ? 1 : 0.55
        foreground: root.foreground
        fontFamily: root.fontFamily
        onHovered: function(h) { if (h) root.hover("skill") }
        onClicked: root.manager.unlinkSkill()
      }
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: text !== ""
    width: parent.width
    text: root.messageText()
    color: root.tone(root.messageRole())
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.Wrap
  }

  PanelSeparator {
    width: parent.width
    foreground: root.foreground
  }

  // ---- one row per agent --------------------------------------------------------
  Column {
    id: agentColumn
    width: parent.width
    spacing: Style.space(2)

    Repeater {
      id: agentRepeater
      model: root.rows

      delegate: Column {
        id: agentRow
        required property var modelData
        required property int index
        readonly property var r: agentRow.modelData
        readonly property bool open: root.expanded === agentRow.r.id
        readonly property bool hasPrimary: agentRow.r.canAdd || agentRow.r.canSignIn
        width: agentColumn.width
        spacing: Style.space(2)

        CursorSurface {
          width: parent.width
          implicitHeight: rowContent.implicitHeight + Style.space(12)
          foreground: root.foreground
          hasCursor: root.hasCursor(agentRow.r.id)

          Row {
            id: rowContent
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: Style.space(8)
            anchors.rightMargin: Style.space(8)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(8)

            Text {
              id: agentGlyph
              textFormat: Text.PlainText
              text: root.rowGlyph(agentRow.r)
              color: root.rowGlyphColor(agentRow.r)
              font.family: root.fontFamily
              font.pixelSize: Style.font.icon
              anchors.verticalCenter: parent.verticalCenter
            }

            Column {
              width: parent.width - agentGlyph.width - parent.spacing
                - (agentRow.hasPrimary ? primaryButton.width + parent.spacing : 0)
              spacing: Style.space(1)
              anchors.verticalCenter: parent.verticalCenter

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: agentRow.r.name + (agentRow.r.isDefault ? " \u00b7 default" : "")
                color: agentRow.r.installed ? root.foreground : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
                elide: Text.ElideRight
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: agentRow.r.status
                color: agentRow.r.role === "danger" || agentRow.r.role === "warning" ? root.tone(agentRow.r.role) : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.Wrap
              }
            }

            Button {
              id: primaryButton
              visible: agentRow.hasPrimary
              anchors.verticalCenter: parent.verticalCenter
              text: agentRow.r.canAdd ? "Add" : "Sign in"
              iconText: agentRow.r.canAdd ? Model.Glyph.plus : Model.Glyph.login
              bordered: true
              enabled: !root.busy
              opacity: enabled ? 1 : 0.55
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: {
                if (agentRow.r.canAdd) root.manager.add(agentRow.r.id)
                else root.manager.signIn(agentRow.r.id)
              }
            }
          }

          MouseArea {
            anchors.fill: parent
            anchors.rightMargin: agentRow.hasPrimary ? primaryButton.width + Style.space(12) : 0
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onEntered: root.hover(agentRow.r.id)
            onClicked: root.toggle(agentRow.r.id)
          }
        }

        // ---- details of the expanded agent ---------------------------------
        Column {
          id: detailColumn
          readonly property real innerWidth: width - leftPadding - rightPadding
          visible: agentRow.open
          width: parent.width
          leftPadding: Style.space(28)
          rightPadding: Style.space(8)
          topPadding: Style.space(2)
          bottomPadding: Style.space(6)
          spacing: Style.space(6)

          Text {
            textFormat: Text.PlainText
            visible: text !== ""
            width: detailColumn.innerWidth
            text: agentRow.r.steps
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.Wrap
          }

          Text {
            textFormat: Text.PlainText
            visible: text !== ""
            width: detailColumn.innerWidth
            text: root.accountsLine(agentRow.r)
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.Wrap
          }

          Text {
            textFormat: Text.PlainText
            visible: text !== ""
            width: detailColumn.innerWidth
            text: agentRow.r.file !== "" && (agentRow.r.tier === "cli" || agentRow.r.tier === "json")
              ? "Settings: " + agentRow.r.file : ""
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            elide: Text.ElideMiddle
          }

          Text {
            textFormat: Text.PlainText
            visible: text !== ""
            width: detailColumn.innerWidth
            text: root.backupLine(agentRow.r)
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            elide: Text.ElideMiddle
          }

          Text {
            textFormat: Text.PlainText
            visible: text !== ""
            width: detailColumn.innerWidth
            text: agentRow.r.note
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.Wrap
          }

          Flow {
            visible: root.hasActions(agentRow.r)
            width: detailColumn.innerWidth
            spacing: Style.space(6)

            Button {
              visible: agentRow.r.canAdd
              text: "Add"
              iconText: Model.Glyph.plus
              bordered: true
              enabled: !root.busy
              opacity: enabled ? 1 : 0.55
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.manager.add(agentRow.r.id)
            }

            Button {
              visible: agentRow.r.canSignIn
              text: "Sign in"
              iconText: Model.Glyph.login
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.manager.signIn(agentRow.r.id)
            }

            Button {
              visible: agentRow.r.canRemove
              text: "Remove"
              iconText: Model.Glyph.linkOff
              tooltipText: "Remove the entry this plugin added"
              bordered: true
              enabled: !root.busy
              opacity: enabled ? 1 : 0.55
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.confirmRequested("agentRemove", agentRow.r.id)
            }

            Button {
              visible: agentRow.r.canCopy
              text: agentRow.r.copyLabel
              iconText: Model.Glyph.copy
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.manager.copy(agentRow.r.id)
            }

            Button {
              visible: agentRow.r.guideUrl !== ""
              text: "Setup guide"
              iconText: Model.Glyph.openInNew
              tooltipText: "VirusTotal's instructions for this agent"
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.manager.openGuide(agentRow.r.id)
            }

            Button {
              visible: agentRow.r.link !== ""
              text: agentRow.r.linkLabel
              iconText: Model.Glyph.openInNew
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.manager.openLink(agentRow.r.id)
            }
          }
        }
      }
    }
  }

  PanelSeparator {
    width: parent.width
    foreground: root.foreground
  }

  Toggle {
    id: askToggle
    width: parent.width
    label: "Show an \u201cAsk\u201d button on results"
    description: "Opens " + (root.manager && root.manager.defaultName !== "" ? root.manager.defaultName : "Omarchy's default agent")
      + " with a finished lookup or a download alert. Omarchy starts agents in auto-approve mode."
    checked: !!root.service && root.service.agentButtons
    hasCursor: root.hasCursor("ask")
    foreground: root.foreground
    fontFamily: root.fontFamily
    onHovered: function(h) { if (h) root.hover("ask") }
    onClicked: root.activate("ask")
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: "Agents use your Google account's VirusTotal AI quota (60 lookups per minute, 1,000 per day). "
      + "Removing an entry does not revoke access: use VirusTotal access for that. Uploads are public, so agents are told to ask first."
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.Wrap
  }
}
