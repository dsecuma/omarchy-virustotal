import QtQuick
import QtQuick.Shapes
import qs.Commons

// VirusTotal mark drawn natively (same approach as Omarchy's TailscaleIcon and
// DropboxIcon), so it follows the theme colour instead of shipping a bitmap.
Item {
  id: root

  property real iconSize: Style.font.icon
  property color color: Color.foreground

  width: iconSize * 100 / 89
  height: iconSize
  implicitWidth: width
  implicitHeight: height

  Shape {
    anchors.fill: parent
    antialiasing: true
    layer.enabled: true
    layer.samples: 4

    ShapePath {
      fillColor: root.color
      fillRule: ShapePath.OddEvenFill
      strokeColor: "transparent"
      strokeWidth: -1
      scale: Qt.size(root.width / 100, root.height / 89)

      PathSvg { path: "M45.292 44.5 0 89h100V0H0l45.292 44.5zM90 80H22l35.987-35.2L22 9h68v71z" }
    }
  }
}
