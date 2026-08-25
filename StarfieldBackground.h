#pragma once

#include <QWidget>
#include <QTimer>
#include <QVector>
#include <QPointF>
#include <QPixmap>

// ====================================================
// ANIMATED CONSTELLATION / STARFIELD BACKGROUND
// ====================================================
//
// Purely decorative widget that paints a parallax field of drifting nodes with
// proximity links, plus an interactive constellation that forms around the
// mouse cursor. It is designed to sit BEHIND every other widget:
//
//   * Qt::WA_TransparentForMouseEvents  -> never steals input
//   * Qt::WA_OpaquePaintEvent           -> Qt skips the parent background fill
//   * lower()                           -> stays at the bottom of the z-order
//
// Depth comes from three things:
//   1. Three parallax layers (far / mid / near). Only mid+near link and react
//      to the cursor; the far layer is a pure backdrop that drifts slowly.
//   2. A slow per-node twinkle (sinusoidal alpha, per-node phase and speed).
//   3. A vignette baked into the cached backdrop pixmap, so the field falls
//      away toward the window edges at zero per-frame cost.
//
// Everything is preallocated on resize; the per-frame update performs no heap
// allocation. The animation timer stops whenever the widget is hidden or the
// owning top level window is minimised.
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
    // layer: 0 = far backdrop, 1 = mid, 2 = near. Layers 1 and 2 are the only
    // ones that link to each other and react to the cursor; they are stored at
    // the FRONT of m_nodes so the link loops can stop at m_interactiveCount.
    struct Node {
        qreal x = 0.0;
        qreal y = 0.0;
        qreal vx = 0.0;            // live velocity (cursor attraction perturbs this)
        qreal vy = 0.0;
        qreal driftVx = 0.0;       // the calm drift the node springs back to
        qreal driftVy = 0.0;
        qreal radius = 1.6;
        qreal baseAlpha = 0.8;
        qreal twinklePhase = 0.0;
        qreal twinkleSpeed = 0.02;
        qreal glow = 0.0;          // 0..1 eased "the cursor is near me" highlight
        int   layer = 1;
        bool  spectrumBlue = false;
    };

    // Short lived motes spawned along fast cursor movement. Fixed size pool, so
    // spawning never allocates.
    struct Spark {
        qreal x = 0.0;
        qreal y = 0.0;
        qreal vx = 0.0;
        qreal vy = 0.0;
        qreal life = 0.0;          // 1.0 -> 0.0, dead at <= 0
    };

    void reseedNodes();
    void rebuildBackdrop();
    void advanceFrame();
    void syncTimerState();
    void trackCursor();
    void spawnSparks();

    QVector<Node>  m_nodes;
    QVector<Spark> m_sparks;
    QPixmap        m_backdrop;      // gradient + vignette, rebuilt only on resize
    QTimer         m_timer;
    QPointF        m_mouse{ -9999.0, -9999.0 };
    QPointF        m_previousMouse{ -9999.0, -9999.0 };
    qsizetype      m_interactiveCount = 0;
    int            m_sparkCursor = 0;
    QWidget*       m_host = nullptr;
    QWidget*       m_watchedWindow = nullptr;
    bool           m_animationEnabled = true;
};
