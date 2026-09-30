import QtQuick
import Qt.labs.folderlistmodel

// Directory listing for ~/.config/omarchy/plugins.
//
// PluginScanner.qml creates this with Qt.createComponent, like
// DownloadsFolder.qml, so a system without Qt.labs.folderlistmodel only loses
// the instant "new plugin" signal; the periodic probe still finds changes.
//
// FolderListModel only sees plugin folders appearing, disappearing or being
// renamed. Updates inside a plugin (omarchy plugin update) are caught by the
// scanner's periodic probe, which compares a per-plugin stamp.
Item {
  id: root

  property string path: ""
  readonly property bool ready: path !== "" && listing.status === FolderListModel.Ready

  signal updated()

  function dirUrl(p) {
    return "file://" + String(p).split("/").map(encodeURIComponent).join("/")
  }

  FolderListModel {
    id: listing
    folder: root.path !== "" ? root.dirUrl(root.path) : ""
    showDirs: true
    showFiles: false
    showDotAndDotDot: false
    showHidden: false

    onStatusChanged: root.updated()
    onCountChanged: root.updated()
    onDataChanged: root.updated()
  }
}
