import QtQuick
import qs.Commons
import qs.Ui
import "Model.js" as Model

// Plugins tab: what the installed-plugin scanner (PluginScanner.qml) found.
//
// Rendering only; Panel.qml passes itself as `panel` for colours and roles.
// Labels come from Scanner.js and only restate VirusTotal's numbers.
Column {
  id: root

  property var panel: null
  property var service: null
  property real now: Date.now()
  property bool cursorActive: false
  property int cursorIndex: 0
  property string expanded: ""

  readonly property var scanner: service ? service.scanner : null
  readonly property var plugins: scanner && scanner.plugins ? scanner.plugins : []
  readonly property bool enabledSetting: !!service && service.pluginScanEnabled === true
  readonly property bool active: !!service && service.pluginScannerActive === true
  readonly property color foreground: panel ? panel.foreground : Color.foreground
  readonly property color dim: panel ? panel.dim : Color.foreground
  readonly property string fontFamily: panel ? panel.fontFamily : Style.font.family

  signal openSettings()
  signal cursorRequested(int index)

  spacing: Style.space(8)

  function tone(role) {
    return root.panel ? root.panel.roleColor(role) : root.foreground
  }

  function toggle(id) {
    root.expanded = root.expanded === id ? "" : id
  }

  function blockedReason() {
    var s = root.service
    if (!s || !s.ready) return ""
    if (s.standalone) return "This bar does not run plugin services, so plugins are not checked here."
    if (s.missingTools !== "") return "Missing tools: " + s.missingTools + "."
    if (s.scanMissingTools !== "") return "The plugin scanner needs: " + s.scanMissingTools + "."
    if (s.pluginBackend === "classic") {
      if (s.apiKeyState === "invalid") return "VirusTotal rejected the API key. Save a valid one in Settings."
      if (s.apiKeyState !== "present") return "Save a VirusTotal API key in Settings, or switch the engine to VirusTotal AI."
    } else if (!s.connected) {
      return "Connect to VirusTotal AI in Settings to check plugins."
    }
    return ""
  }

  function pluginSubline(p) {
    var parts = [p.id]
    if (p.version) parts.push("v" + p.version)
    if (p.head) parts.push(p.head)
    if (p.link) parts.push("symlink")
    return parts.join(" \u00b7 ")
  }

  function pluginMeta(p) {
    var parts = [p.status]
    var ago = p.lastScan ? Model.timeAgo(p.lastScan, root.now) : ""
    if (ago !== "" && !p.scanning) parts.push("checked " + ago)
    if (p.truncated) parts.push("only the first files were checked")
    if (p.skipped > 0) parts.push(p.skipped + " skipped (unusual names)")
    return parts.join(" \u00b7 ")
  }

  // ---- disabled -------------------------------------------------------------
  Column {
    visible: !root.enabledSetting
    width: parent.width
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      width: parent.width
      text: "Check every installed Omarchy plugin with VirusTotal. New and updated plugins in "
        + (root.service ? Model.displayPath(root.service.pluginsDir, root.service.homeDir) : "~/.config/omarchy/plugins")
        + " are hashed locally and each file's SHA-256 is looked up. Files are uploaded only if you allow it in Settings."
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.Wrap
    }

    Button {
      text: "Turn on"
      iconText: Model.Glyph.puzzle
      bordered: true
      enabled: !!root.service && !root.service.standalone
      opacity: enabled ? 1 : 0.55
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: if (root.service) root.service.setPluginScanEnabled(true)
    }
  }

  // ---- enabled but blocked --------------------------------------------------
  Text {
    textFormat: Text.PlainText
    visible: root.enabledSetting && !root.active && text !== ""
    width: parent.width
    text: root.blockedReason()
    color: root.panel ? root.panel.urgent : root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.Wrap
  }

  Button {
    visible: root.enabledSetting && !root.active && root.blockedReason() !== ""
    text: "Settings"
    iconText: Model.Glyph.cog
    bordered: true
    foreground: root.foreground
    fontFamily: root.fontFamily
    onClicked: root.openSettings()
  }

  // ---- active ---------------------------------------------------------------
  Item {
    visible: root.active
    width: parent.width
    implicitHeight: Math.max(statusColumn.implicitHeight, actions.implicitHeight)

    Column {
      id: statusColumn
      anchors.left: parent.left
      anchors.right: actions.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(2)

      Text {
        textFormat: Text.PlainText
        width: parent.width
        text: root.scanner ? root.scanner.statusLine(root.now) : ""
        color: root.scanner && root.scanner.pauseUntil > root.now ? root.panel.warning : root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.Wrap
      }

      Text {
        textFormat: Text.PlainText
        visible: text !== ""
        width: parent.width
        text: root.scanner ? root.scanner.quotaLine() : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        wrapMode: Text.Wrap
      }
    }

    Row {
      id: actions
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(4)

      Button {
        iconText: Model.Glyph.refresh
        tooltipText: "Look for new or updated plugins"
        bordered: true
        enabled: !!root.scanner && root.scanner.loaded
        opacity: enabled ? 1 : 0.55
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: root.scanner.checkNow()
      }

      Button {
        text: "Rescan all"
        tooltipText: "Look up every file again, ignoring cached results"
        bordered: true
        enabled: !!root.scanner && root.scanner.loaded && root.plugins.length > 0
        opacity: enabled ? 1 : 0.55
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: root.scanner.rescanAll()
      }
    }
  }

  // Progress for the current burst of work.
  Rectangle {
    visible: root.active && !!root.scanner && root.scanner.scanTotal > 0
    width: parent.width
    height: Style.space(3)
    radius: height / 2
    color: Util.alpha(root.foreground, 0.12)

    Rectangle {
      width: root.scanner && root.scanner.scanTotal > 0
        ? parent.width * Math.min(1, root.scanner.scanDone / root.scanner.scanTotal) : 0
      height: parent.height
      radius: parent.radius
      color: root.foreground
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: root.active && !!root.scanner && root.scanner.loaded && root.plugins.length === 0
    width: parent.width
    text: "No third-party plugins installed."
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.Wrap
  }

  Column {
    id: pluginColumn
    visible: root.plugins.length > 0
    width: parent.width
    spacing: Style.space(2)

    Repeater {
      id: pluginRepeater
      model: root.plugins

      delegate: Column {
        id: pluginRow
        required property var modelData
        required property int index
        readonly property bool open: root.expanded === pluginRow.modelData.id
        width: pluginColumn.width
        spacing: Style.space(2)

        CursorSurface {
          width: parent.width
          implicitHeight: rowContent.implicitHeight + Style.space(12)
          foreground: root.foreground
          hasCursor: root.cursorActive && root.cursorIndex === pluginRow.index

          Row {
            id: rowContent
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: Style.space(8)
            anchors.rightMargin: Style.space(8)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(8)

            Text {
              id: pluginGlyph
              textFormat: Text.PlainText
              text: pluginRow.modelData.role === "danger" ? Model.Glyph.alertOctagon
                : pluginRow.modelData.role === "warning" ? Model.Glyph.alert
                : pluginRow.modelData.role === "ok" ? Model.Glyph.shieldCheck
                : pluginRow.modelData.role === "pending" ? Model.Glyph.progressClock
                : Model.Glyph.puzzle
              color: root.tone(pluginRow.modelData.role)
              font.family: root.fontFamily
              font.pixelSize: Style.font.icon
              anchors.verticalCenter: parent.verticalCenter
            }

            Column {
              width: parent.width - pluginGlyph.width - rescanButton.width - parent.spacing * 2
              spacing: Style.space(1)
              anchors.verticalCenter: parent.verticalCenter

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: String(pluginRow.modelData.name || "")
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
                elide: Text.ElideRight
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.pluginSubline(pluginRow.modelData)
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideMiddle
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.pluginMeta(pluginRow.modelData)
                color: pluginRow.modelData.role === "danger" || pluginRow.modelData.role === "warning"
                  ? root.tone(pluginRow.modelData.role) : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.Wrap
              }
            }

            Button {
              id: rescanButton
              anchors.verticalCenter: parent.verticalCenter
              iconText: Model.Glyph.refresh
              tooltipText: "Check this plugin again"
              enabled: !!root.scanner && root.scanner.loaded
              opacity: enabled ? 1 : 0.55
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.scanner.rescan(pluginRow.modelData.id)
            }
          }

          MouseArea {
            anchors.fill: parent
            anchors.rightMargin: rescanButton.width + Style.space(8)
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onEntered: root.cursorRequested(pluginRow.index)
            onClicked: root.toggle(pluginRow.modelData.id)
          }
        }

        // ---- files of the expanded plugin ---------------------------------
        Column {
          id: fileColumn
          visible: pluginRow.open
          width: parent.width
          leftPadding: Style.space(28)
          spacing: Style.space(1)

          Repeater {
            model: pluginRow.open && root.scanner ? root.scanner.filesFor(pluginRow.modelData.id, root.scanner.revision) : []

            delegate: Item {
              id: fileRow
              required property var modelData
              width: fileColumn.width - fileColumn.leftPadding
              implicitHeight: fileText.implicitHeight + Style.space(6)

              Column {
                id: fileText
                anchors.left: parent.left
                anchors.right: openGlyph.left
                anchors.rightMargin: Style.space(6)
                anchors.verticalCenter: parent.verticalCenter
                spacing: 0

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: String(fileRow.modelData.rel || "")
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideMiddle
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: fileRow.modelData.label + " \u00b7 " + Model.formatBytes(fileRow.modelData.size)
                  color: fileRow.modelData.role === "danger" || fileRow.modelData.role === "warning"
                    ? root.tone(fileRow.modelData.role) : root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }

              Text {
                id: openGlyph
                textFormat: Text.PlainText
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                text: fileRow.modelData.reportUrl !== "" ? Model.Glyph.openInNew : ""
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              MouseArea {
                anchors.fill: parent
                enabled: fileRow.modelData.reportUrl !== ""
                cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                onClicked: root.scanner.openReport(fileRow.modelData.reportUrl)
              }
            }
          }
        }
      }
    }
  }
}
