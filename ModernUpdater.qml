import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

Window {
    id: updateWindow
    width: 600
    height: 350
    visible: true
    title: "System Update"
    
    // Frameless window for that sleek, modern tech feel
    flags: Qt.FramelessWindowHint | Qt.Window
    color: "#1A1D21" // Deep tech background

    // Signals to tell C++ what the user clicked
    signal acceptUpdate()
    signal declineUpdate()

    // Drag area so the user can still move the frameless window around
    MouseArea {
        anchors.fill: parent
        property variant clickPos: "1,1"
        onPressed: (mouse) => { clickPos = Qt.point(mouse.x, mouse.y) }
        onPositionChanged: (mouse) => {
            var delta = Qt.point(mouse.x - clickPos.x, mouse.y - clickPos.y)
            updateWindow.x += delta.x; updateWindow.y += delta.y
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 40
        spacing: 20

        Text {
            text: "SYSTEM UPDATE AVAILABLE"
            color: "#F3F4F6"
            font.pixelSize: 22
            font.bold: true
            font.letterSpacing: 2
        }

        // We will pass `latestVersionStr` directly from C++!
        Text {
            text: "Version " + latestVersionStr + " is ready for deployment."
            color: "#34D399" // Emerald Accent
            font.pixelSize: 16
        }

        Text {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            lineHeight: 1.5
            color: "#9BA3AF"
            text: "This update introduces automated background synchronization and reinforces SSH communication stability for MM/MD deployments. To maintain peak operational performance, please authorize the initialization."
        }

        Item { Layout.fillHeight: true } // Spacer

        RowLayout {
            Layout.alignment: Qt.AlignRight
            spacing: 15

            // NO BUTTON
            Button {
                text: "IGNORE"
                contentItem: Text {
                    text: parent.text
                    color: "#9BA3AF"
                    font.bold: true
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 120; implicitHeight: 40
                    color: parent.hovered ? "#2A2F35" : "transparent"
                    radius: 4
                }
                onClicked: {
                    updateWindow.declineUpdate()
                    updateWindow.close()
                }
            }

            // YES BUTTON
            Button {
                text: "INITIALIZE UPDATE"
                contentItem: Text {
                    text: parent.text
                    color: "#1A1D21"
                    font.bold: true
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 180; implicitHeight: 40
                    color: parent.hovered ? "#3EE6AB" : "#34D399"
                    radius: 4
                    scale: parent.pressed ? 0.98 : 1.0 // Subtle click animation
                    Behavior on scale { NumberAnimation { duration: 50 } }
                }
                onClicked: {
                    updateWindow.acceptUpdate()
                    updateWindow.close()
                }
            }
        }
    }
}