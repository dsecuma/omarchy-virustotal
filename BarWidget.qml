import QtQuick
import Quickshell
import qs.Commons
import qs.Ui

// Bar entry point: the VirusTotal mark with a status dot, plus Panel.qml.
//
// State lives in Service.qml, which the shell mounts once per session
// (manifest kind "service") and shares between the bars on every monitor.
// Replacement bars that expose no plugin services get a private standalone
// copy after a short grace period, so the panel still works there (without
// the Downloads watcher or notifications).
BarWidget {
  id: root
  moduleName: "io.github.dsecuma.virustotal"

  readonly property string pluginId: "io.github.dsecuma.virustotal"

  readonly property bool opened: panelLoader.item
    ? panelLoader.item.opened === true
    : false
  readonly property bool popoutSwitchClosing: panelLoader.item
    ? panelLoader.item.popoutSwitchClosing === true
    : false

  property int _serviceTick: 0
  property bool _fallbackAllowed: false

  // shell.serviceFor() only returns this plugin's own service.
  readonly property var sharedService: {
    var tick = root._serviceTick
    var api = root.bar ? root.bar.shell : null
    if (!api || typeof api.serviceFor !== "function") return null
    return api.serviceFor(root.pluginId) || null
  }
  readonly property var service: root.sharedService
    ? root.sharedService
    : (fallbackLoader.item ? fallbackLoader.item : null)
  readonly property string status: root.service ? String(root.service.barStatus || "idle") : "idle"

  readonly property color iconColor: root.bar ? root.bar.barForeground : Color.foreground
  readonly property color urgent: root.bar ? root.bar.urgent : Color.urgent

  function open() {
    if (panelLoader.item) panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item) panelLoader.item.close()
  }

  function toggle() {
    if (panelLoader.item) panelLoader.item.toggle()
  }

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  function injectPanel() {
    if (!panelLoader.item) return
    panelLoader.item.bar = root.bar
    panelLoader.item.anchorItem = button
    panelLoader.item.hostWidget = root
    panelLoader.item.service = root.service
  }

  function tooltip() {
    var s = root.service
    if (!s) return "VirusTotal"
    if (s.lastAlert && !s.alertAcknowledged) {
      var name = String(s.lastAlert.name || s.lastAlert.target || "")
      return "Flagged download: " + name
    }
    if (s.busy && s.busyLabel) return s.busyLabel
    if (s.connecting) return "Connecting to VirusTotal AI\u2026"
    if (s.analysisActive && !s.analysisStalled) return "VirusTotal is analyzing an upload\u2026"
    if (s.watcherActive) return "VirusTotal \u00b7 watching Downloads"
    return "VirusTotal"
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onServiceChanged: injectPanel()

  // The service may register after the bar; poll until it shows up.
  Timer {
    interval: 1500
    repeat: true
    running: !root.sharedService
    onTriggered: root._serviceTick++
  }

  Timer {
    interval: 5000
    running: !root.sharedService && !root._fallbackAllowed
    onTriggered: root._fallbackAllowed = true
  }

  Loader {
    id: fallbackLoader
    active: root._fallbackAllowed && !root.sharedService
    source: Qt.resolvedUrl("Service.qml")
    onLoaded: item.standalone = true
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    tooltipText: root.tooltip()
    iconComponent: Component {
      Item {
        VirusTotalIcon {
          anchors.centerIn: parent
          iconSize: Style.space(11)
          color: root.iconColor
          opacity: root.status === "busy" ? 0.6 : 1.0
        }

        Rectangle {
          visible: root.status !== "idle"
          width: Math.max(4, Style.space(5))
          height: width
          radius: Style.cornerRadius > 0 ? width / 2 : 0
          anchors.top: parent.top
          anchors.right: parent.right
          color: root.status === "malicious" ? root.urgent
            : root.status === "suspicious" ? Qt.tint(root.urgent, Util.alpha(root.iconColor, 0.35))
            : Qt.darker(root.iconColor, 1.55)
        }
      }
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.LeftButton) root.toggle()
    }
  }
}
