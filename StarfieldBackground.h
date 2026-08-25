#pragma once

#include <QWidget>
#include <QTimer>
#include <QVector>
#include <QPointF>

// ====================================================
// ANIMATED CONSTELLATION / STARFIELD BACKGROUND
// ====================================================
//
// Purely decorative widget that paints a slow drifting field of nodes with
// proximity links, plus extra links to the mouse cursor. It is designed to sit
// BEHIND every other widget:
//
//   * Qt::WA_TransparentForMouseEvents  -> never steals input
//   * Qt::WA_OpaquePaintEvent           -> Qt skips the parent background fill
//   * lower()                           -> stays at the bottom of the z-order
//
// The node vector is preallocated on resize; the per-frame update performs no
// heap allocation. The animation timer stops whenever the widget is hidden or
// the owning top level window is minimised.
class StarfieldBackground : public QWidget {
    Q_OBJECT

public:
    explicit StarfieldBackground(QWidget* parent = nullptr);
    ~StarfieldBackground() override;

    // Follow the geometry of `host` (typically the scroll area viewport that
    // owns this widget). Installs a lightweight resize watcher on it.
    void followGeometryOf(QWidget* host);

    // Master switch, used by the theme code so the light theme does not pay for
    // an animation nobody can see.
    void setAnimationEnabled(bool enabled);
    bool isAnimationEnabled() const { return m_animationEnabled; }

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    struct Node {
        qreal x = 0.0;
        qreal y = 0.0;
        qreal vx = 0.0;
        qreal vy = 0.0;
        bool  spectrumBlue = false;
    };

    void reseedNodes();
    void advanceFrame();
    void syncTimerState();
    void trackCursor();

    QVector<Node> m_nodes;
    QTimer        m_timer;
    QPointF       m_mouse{ -9999.0, -9999.0 };
    QWidget*      m_host = nullptr;
    QWidget*      m_watchedWindow = nullptr;
    bool          m_animationEnabled = true;
};
