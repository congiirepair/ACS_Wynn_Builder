#include "ACS_Wynn_Builder.h"
#include <QtWidgets/QApplication>
#include <QSplashScreen>
#include <QThread>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);

    // 1. Create the splash screen using your logo
    // Note: Make sure logo.png (or logo.jpg) is in your resource file!
    QPixmap pixmap(":/logo.png");
    QSplashScreen splash(pixmap);

    // 2. Show the splash screen immediately
    splash.show();

    // This ensures the image draws before the 5-second pause begins
    app.processEvents();

    // 3. Keep it on screen for 5 seconds (5000 milliseconds)
    QThread::msleep(5000);

    // 4. Load and show the main builder window
    ACS_Wynn_Builder window;
    window.show();

    // 5. Close the splash screen automatically when the main window appears
    splash.finish(&window);

    return app.exec();
}