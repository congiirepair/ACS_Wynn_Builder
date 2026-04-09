#include "ACS_Wynn_Builder.h"
#include <QtWidgets/QApplication>
#include <QSplashScreen>
#include <QPixmap>
#include <QTimer> 
#include <QDebug>

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);

    // 1. Load the splash image from the simplified root path
    QPixmap pixmap(":/splash.png");

    // Check if the image is actually found
    if (pixmap.isNull()) {
        qDebug() << "IMAGE ERROR: splash.png not found in resources!";
        pixmap = QPixmap(600, 400);
        pixmap.fill(QColor("#1C1918")); // Fallback dark background
    }

    // 2. Setup and show the Splash Screen
    QSplashScreen splash(pixmap);
    splash.show();
    splash.showMessage("ACS Hotel Wifi Tool - Initializing...",
        Qt::AlignBottom | Qt::AlignCenter, Qt::white);

    // 3. Keep the UI responsive while loading
    a.processEvents();

    // 4. Initialize Main Window (but don't show it yet)
    ACS_Wynn_Builder w;

    // 5. Use QTimer::singleShot to handle the transition
    // This waits 2.5 seconds, then shows the main window and closes the splash
    QTimer::singleShot(2500, [&]() {
        w.show();
        splash.finish(&w);
        });

    return a.exec();
}