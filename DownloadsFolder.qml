import QtQuick
import Qt.labs.folderlistmodel

// Directory listing for the Downloads folder.
//
// Service.qml creates this with Qt.createComponent, so a system without the
// Qt.labs.folderlistmodel module (qt6-declarative) only loses the watcher and
// the recent-downloads list instead of failing to load the whole plugin.
//
// FolderListModel follows the directory with inotify: it notices files being
// added, removed and renamed, but not files growing in place. The service
// therefore only uses it to spot new names; Scripts.hash checks that a file
// has stopped changing before anything is looked up.
Item {
  id: root

  property string path: ""
  readonly property bool ready: path !== "" && listing.status === FolderListModel.Ready
  readonly property int count: listing.count

  signal updated()

  function fileUrl(p) {
    return "file://" + String(p).split("/").map(encodeURIComponent).join("/")
  }

  function entryAt(i) {
    var modified = listing.get(i, "fileModified")
    var t = modified ? new Date(modified).getTime() : 0
    return {
      name: String(listing.get(i, "fileName") || ""),
      path: String(listing.get(i, "filePath") || ""),
      size: Number(listing.get(i, "fileSize")) || 0,
      mtime: isFinite(t) ? t : 0
    }
  }

  // [{ name, path }] for every file, used to detect new names.
  function entries() {
    var out = []
    if (!ready) return out
    for (var i = 0; i < listing.count; i++)
      out.push({ name: String(listing.get(i, "fileName") || ""), path: String(listing.get(i, "filePath") || "") })
    return out
  }

  // Candidates for the "recent downloads" list without walking a large
  // folder. Which end of a Time-sorted listing is newest is not documented
  // consistently across Qt versions, so both ends are returned and
  // Model.recentDownloads sorts them.
  function snapshot(limit) {
    var out = []
    if (!ready) return out
    var n = listing.count
    var take = Math.max(1, limit || 25)
    var i
    if (n <= take * 2) {
      for (i = 0; i < n; i++) out.push(entryAt(i))
    } else {
      for (i = 0; i < take; i++) out.push(entryAt(i))
      for (i = n - take; i < n; i++) out.push(entryAt(i))
    }
    return out
  }

  FolderListModel {
    id: listing
    folder: root.path !== "" ? root.fileUrl(root.path) : ""
    showDirs: false
    showDotAndDotDot: false
    showHidden: false
    showOnlyReadable: true
    sortField: FolderListModel.Time

    onStatusChanged: root.updated()
    onCountChanged: root.updated()
    // A rename (browser.part -> file.zip) keeps the count and only changes rows.
    onDataChanged: root.updated()
  }
}
