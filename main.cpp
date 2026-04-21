#include "ACS_Wynn_Builder.h"
#include <QtWidgets/QApplication>
#include <QSplashScreen>
#include <QPixmap>
#include <QTimer> 
#include <QDebug>
#include <QSize>
#include <QScreen>
#include <QElapsedTimer>

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);
    const QSize targetSplashSize(526, 401);
    const qreal splashDpr = a.primaryScreen() ? a.primaryScreen()->devicePixelRatio() : 1.0;
    const QSize renderedSplashSize(qRound(targetSplashSize.width() * splashDpr),
                                   qRound(targetSplashSize.height() * splashDpr));

    QPixmap pixmap(":/splash.png");
    if (pixmap.isNull()) {
        qDebug() << "IMAGE ERROR: splash image not found in resources!";
        pixmap = QPixmap(renderedSplashSize);
        pixmap.fill(QColor("#1C1918")); // Fallback dark background
    }

    pixmap = pixmap.scaled(renderedSplashSize, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
    pixmap.setDevicePixelRatio(splashDpr);

    // Show a short branded splash while the main window initializes.
    QSplashScreen splash(pixmap);
    splash.show();
    splash.showMessage("Preparing ACS Hotel WiFi Builder...",
        Qt::AlignBottom | Qt::AlignCenter, Qt::white);

    QElapsedTimer splashTimer;
    splashTimer.start();
    a.processEvents();

    // Build the main window first, then only keep the splash around briefly.
    ACS_Wynn_Builder w;

    const int minimumSplashMs = 650;
    const int remainingDelayMs = qMax(0, minimumSplashMs - static_cast<int>(splashTimer.elapsed()));
    QTimer::singleShot(remainingDelayMs, [&]() {
        w.show();
        splash.finish(&w);
    });

    return a.exec();
}
