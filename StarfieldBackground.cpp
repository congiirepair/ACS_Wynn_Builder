#include "StarfieldBackground.h"

#include <QPainter>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QShowEvent>
#include <QHideEvent>
#include <QLinearGradient>
#include <QRadialGradient>
#include <QRandomGenerator>
#include <QCursor>
#include <QtMath>

namespace {

constexpr int    kFrameIntervalMs = 33;      // ~30 fps
constexpr int    kMaxNodes = 210;
constexpr int    kAreaPerNode = 5200;

// Layer mix. Far is the most numerous and the dimmest; near is sparse, big and
// bright. Only mid + near take part in links and cursor interaction.
constexpr qreal  kFarShare = 0.50;
constexpr qreal  kMidShare = 0.33;           // the remainder is the near layer

constexpr qreal  kNodeSpeed = 0.30;          // px per frame, +/- half range
constexpr qreal  kFarSpeedScale = 0.35;
constexpr qreal  kMidSpeedScale = 0.85;
constexpr qreal  kNearSpeedScale = 1.30;

constexpr qreal  kFarRadius = 0.9;
constexpr qreal  kMidRadius = 1.7;
constexpr qreal  kNearRadius = 2.4;

constexpr qreal  kFarAlpha = 0.34;
constexpr qreal  kMidAlpha = 0.72;
constexpr qreal  kNearAlpha = 0.95;

constexpr qreal  kLinkDistance = 140.0;
constexpr qreal  kLinkAlpha = 0.22;
constexpr qreal  kNearLinkAlpha = 0.58;      // node-to-node links beside the cursor
constexpr qreal  kConstellationRadius = 260.0;

constexpr qreal  kCursorLinkDistance = 230.0;
constexpr qreal  kCursorLinkAlpha = 0.82;
// Three stacked passes make the cursor links read as glowing filaments rather
// than hairlines. They have to punch through the translucent card surfaces
// above them, so the core pass is near-white rather than mid blue.
constexpr qreal  kCursorHaloWidth = 5.2;
constexpr qreal  kCursorHaloScale = 0.22;
constexpr qreal  kCursorBodyWidth = 2.2;
constexpr qreal  kCursorBodyScale = 0.55;
constexpr qreal  kCursorCoreWidth = 1.1;
constexpr qreal  kSpotlightAlpha = 0.18;     // soft halo that travels with the pointer

constexpr qreal  kAttractRadius = 220.0;
constexpr qreal  kAttractAccel = 0.075;
constexpr qreal  kMaxSpeed = 1.7;
constexpr qreal  kDriftRestore = 0.05;       // spring back to the calm drift
constexpr qreal  kGlowEase = 0.18;

constexpr int    kSparkPool = 26;
constexpr qreal  kSparkSpawnDistance = 16.0; // cursor travel per frame that spawns one
constexpr qreal  kSparkDecay = 1.0 / 45.0;   // ~1.5 s at 30 fps
constexpr qreal  kSparkLinkDistance = 150.0;

constexpr qreal  kTwinkleDepth = 0.30;       // +/- fraction of base alpha
constexpr qreal  kOffscreen = -9999.0;

// Spectrum brand palette.
const QColor kSpectrumLightBlue(0, 160, 223);   // #00A0DF
const QColor kSpectrumIce(158, 224, 255);       // bright core for the cursor links
const QColor kSpectrumBright(72, 200, 250);     // constellation links beside the cursor
const QColor kGradientTop(0x04, 0x05, 0x0A);    // #04050A
const QColor kGradientBottom(0x00, 0x00, 0x00); // #000000

inline qreal randomUnit() {
    return QRandomGenerator::global()->generateDouble();
}

} // namespace

StarfieldBackground::StarfieldBackground(QWidget* parent)
    : QWidget(parent)
{
    setObjectName("starfieldBackground");
    // Never intercept input - every real control sits above this widget.
    setAttribute(Qt::WA_TransparentForMouseEvents, true);
    // paintEvent covers the whole rect, so Qt can skip the parent background.
    setAttribute(Qt::WA_OpaquePaintEvent, true);
    setAttribute(Qt::WA_NoSystemBackground, true);
    setFocusPolicy(Qt::NoFocus);
    setAutoFillBackground(false);

    m_sparks.resize(kSparkPool);

    m_timer.setInterval(kFrameIntervalMs);
    m_timer.setTimerType(Qt::CoarseTimer);
    connect(&m_timer, &QTimer::timeout, this, &StarfieldBackground::advanceFrame);

    if (parent)
        followGeometryOf(parent);

    lower();
}

StarfieldBackground::~StarfieldBackground() {
    m_timer.stop();
    if (m_host)
        m_host->removeEventFilter(this);
    if (m_watchedWindow)
        m_watchedWindow->removeEventFilter(this);
}

void StarfieldBackground::followGeometryOf(QWidget* host) {
    if (m_host == host)
        return;

    if (m_host)
        m_host->removeEventFilter(this);

    m_host = host;

    if (m_host) {
        m_host->installEventFilter(this);
        setGeometry(m_host->rect());
    }
}

void StarfieldBackground::setAnimationEnabled(bool enabled) {
    if (m_animationEnabled == enabled)
        return;
    m_animationEnabled = enabled;
    syncTimerState();
}

void StarfieldBackground::reseedNodes() {
    const int w = qMax(1, width());
    const int h = qMax(1, height());

    const int desired = qBound(0, static_cast<int>(qFloor(static_cast<qreal>(w) * h / kAreaPerNode)), kMaxNodes);

    const int farCount = static_cast<int>(desired * kFarShare);
    const int midCount = static_cast<int>(desired * kMidShare);
    const int nearCount = desired - farCount - midCount;

    // Interactive layers (mid + near) are stored FIRST so every link loop can
    // simply stop at m_interactiveCount instead of testing the layer per pair.
    m_interactiveCount = midCount + nearCount;

    // Preallocate once; advanceFrame() never touches the heap afterwards.
    m_nodes.resize(desired);
    for (qsizetype i = 0; i < m_nodes.size(); ++i) {
        Node& node = m_nodes[i];

        if (i < midCount)
            node.layer = 1;
        else if (i < m_interactiveCount)
            node.layer = 2;
        else
            node.layer = 0;

        qreal speedScale = kFarSpeedScale;
        switch (node.layer) {
        case 1:
            node.radius = kMidRadius;
            node.baseAlpha = kMidAlpha;
            speedScale = kMidSpeedScale;
            break;
        case 2:
            node.radius = kNearRadius;
            node.baseAlpha = kNearAlpha;
            speedScale = kNearSpeedScale;
            break;
        default:
            node.radius = kFarRadius;
            node.baseAlpha = kFarAlpha;
            break;
        }

        node.x = randomUnit() * w;
        node.y = randomUnit() * h;
        node.driftVx = (randomUnit() - 0.5) * kNodeSpeed * speedScale;
        node.driftVy = (randomUnit() - 0.5) * kNodeSpeed * speedScale;
        node.vx = node.driftVx;
        node.vy = node.driftVy;
        node.twinklePhase = randomUnit() * M_PI * 2.0;
        node.twinkleSpeed = 0.010 + randomUnit() * 0.022;
        node.glow = 0.0;
        node.spectrumBlue = randomUnit() < 0.5;
    }

    for (Spark& spark : m_sparks)
        spark.life = 0.0;
}

// The vertical gradient and the vignette never change while the size is stable,
// so they are baked into one pixmap and blitted with CompositionMode_Source.
// That is strictly cheaper per frame than the old fillRect(QLinearGradient).
void StarfieldBackground::rebuildBackdrop() {
    const int w = qMax(1, width());
    const int h = qMax(1, height());
    const qreal dpr = devicePixelRatioF();

    m_backdrop = QPixmap(QSize(qCeil(w * dpr), qCeil(h * dpr)));
    m_backdrop.setDevicePixelRatio(dpr);
    m_backdrop.fill(Qt::black);

    QPainter painter(&m_backdrop);
    const QRectF fullRect(0.0, 0.0, w, h);

    QLinearGradient backdrop(fullRect.topLeft(), fullRect.bottomLeft());
    backdrop.setColorAt(0.0, kGradientTop);
    backdrop.setColorAt(1.0, kGradientBottom);
    painter.fillRect(fullRect, backdrop);

    // Soft radial darkening toward the edges. The circular gradient is stretched
    // to the widget's aspect ratio so every edge falls off by the same amount -
    // an unstretched circle would leave the short edges untouched.
    const qreal aspect = fullRect.height() > 0.0 ? fullRect.width() / fullRect.height() : 1.0;
    QRadialGradient vignette(fullRect.center(), qMin(fullRect.width(), fullRect.height()) * 0.72);
    vignette.setColorAt(0.00, QColor(0, 0, 0, 0));
    vignette.setColorAt(0.55, QColor(0, 0, 0, 0));
    vignette.setColorAt(0.80, QColor(0, 0, 0, 95));
    vignette.setColorAt(1.00, QColor(0, 0, 0, 200));

    painter.save();
    painter.translate(fullRect.center());
    painter.scale(aspect >= 1.0 ? aspect : 1.0, aspect >= 1.0 ? 1.0 : 1.0 / aspect);
    painter.translate(-fullRect.center());
    // The scale above stretches the brush space, so paint a rect big enough to
    // still cover the widget after the transform.
    painter.fillRect(fullRect.adjusted(-fullRect.width(), -fullRect.height(),
        fullRect.width(), fullRect.height()), vignette);
    painter.restore();
}

void StarfieldBackground::trackCursor() {
    // Polling the cursor is deliberate: an application wide MouseMove filter
    // only sees moves while a button is held (or with mouse tracking enabled on
    // every widget), and installing a global filter on a production app is a
    // far bigger blast radius than one cheap mapFromGlobal per frame.
    m_previousMouse = m_mouse;

    const QPoint local = mapFromGlobal(QCursor::pos());
    // A generous margin keeps the constellation alive while the cursor sits on
    // the toolbar or just outside the viewport, so it does not snap off.
    if (rect().adjusted(-60, -60, 60, 60).contains(local))
        m_mouse = QPointF(local);
    else
        m_mouse = QPointF(kOffscreen, kOffscreen);
}

void StarfieldBackground::spawnSparks() {
    if (m_mouse.x() <= kOffscreen / 2.0 || m_previousMouse.x() <= kOffscreen / 2.0)
        return;

    const qreal dx = m_mouse.x() - m_previousMouse.x();
    const qreal dy = m_mouse.y() - m_previousMouse.y();
    const qreal travelSquared = dx * dx + dy * dy;
    if (travelSquared < kSparkSpawnDistance * kSparkSpawnDistance)
        return;

    // One spark per frame from the fixed pool: the oldest slot is recycled, so
    // a fast sweep leaves a fading trail without ever allocating.
    Spark& spark = m_sparks[m_sparkCursor];
    m_sparkCursor = (m_sparkCursor + 1) % m_sparks.size();

    spark.x = m_previousMouse.x() + dx * randomUnit();
    spark.y = m_previousMouse.y() + dy * randomUnit();
    spark.vx = (randomUnit() - 0.5) * 0.8;
    spark.vy = (randomUnit() - 0.5) * 0.8;
    spark.life = 1.0;
}

void StarfieldBackground::advanceFrame() {
    const qreal w = width();
    const qreal h = height();

    trackCursor();
    spawnSparks();

    const bool cursorLive = m_mouse.x() > kOffscreen / 2.0;

    for (qsizetype i = 0; i < m_nodes.size(); ++i) {
        Node& node = m_nodes[i];

        // Twinkle runs on every layer - it is what stops the far backdrop from
        // reading as a flat sheet of dust.
        node.twinklePhase += node.twinkleSpeed;
        if (node.twinklePhase > M_PI * 2.0)
            node.twinklePhase -= M_PI * 2.0;

        if (cursorLive && i < m_interactiveCount) {
            const qreal dx = m_mouse.x() - node.x;
            const qreal dy = m_mouse.y() - node.y;
            const qreal squared = dx * dx + dy * dy;

            if (squared < kAttractRadius * kAttractRadius && squared > 1.0) {
                const qreal distance = qSqrt(squared);
                const qreal pull = 1.0 - distance / kAttractRadius;
                // Gentle acceleration toward the cursor - the node leans in, it
                // does not get sucked in.
                node.vx += (dx / distance) * kAttractAccel * pull;
                node.vy += (dy / distance) * kAttractAccel * pull;
                node.glow += (pull - node.glow) * kGlowEase;
            }
            else {
                node.glow += (0.0 - node.glow) * kGlowEase;
            }
        }
        else if (node.glow > 0.0) {
            node.glow += (0.0 - node.glow) * kGlowEase;
        }

        // Spring the live velocity back toward the calm drift so the field
        // settles again the moment the cursor moves away.
        node.vx += (node.driftVx - node.vx) * kDriftRestore;
        node.vy += (node.driftVy - node.vy) * kDriftRestore;

        const qreal speedSquared = node.vx * node.vx + node.vy * node.vy;
        if (speedSquared > kMaxSpeed * kMaxSpeed) {
            const qreal scale = kMaxSpeed / qSqrt(speedSquared);
            node.vx *= scale;
            node.vy *= scale;
        }

        node.x += node.vx;
        node.y += node.vy;

        if (node.x < 0.0 || node.x > w) {
            node.vx = -node.vx;
            node.driftVx = -node.driftVx;
            node.x = qBound(0.0, node.x, w);
        }
        if (node.y < 0.0 || node.y > h) {
            node.vy = -node.vy;
            node.driftVy = -node.driftVy;
            node.y = qBound(0.0, node.y, h);
        }
    }

    for (Spark& spark : m_sparks) {
        if (spark.life <= 0.0)
            continue;
        spark.x += spark.vx;
        spark.y += spark.vy;
        spark.life -= kSparkDecay;
    }

    update();
}

void StarfieldBackground::syncTimerState() {
    const bool windowMinimised = m_watchedWindow && m_watchedWindow->isMinimized();
    const bool shouldRun = m_animationEnabled && isVisible() && !windowMinimised;

    if (shouldRun) {
        if (!m_timer.isActive())
            m_timer.start();
    }
    else if (m_timer.isActive()) {
        m_timer.stop();
    }
}

void StarfieldBackground::resizeEvent(QResizeEvent* event) {
    QWidget::resizeEvent(event);
    rebuildBackdrop();
    reseedNodes();
}

void StarfieldBackground::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);

    if (QWidget* top = window()) {
        if (m_watchedWindow != top) {
            if (m_watchedWindow)
                m_watchedWindow->removeEventFilter(this);
            m_watchedWindow = top;
            m_watchedWindow->installEventFilter(this);
        }
    }

    if (m_backdrop.isNull())
        rebuildBackdrop();
    if (m_nodes.isEmpty())
        reseedNodes();

    syncTimerState();
}

void StarfieldBackground::hideEvent(QHideEvent* event) {
    QWidget::hideEvent(event);
    syncTimerState();
}

bool StarfieldBackground::eventFilter(QObject* watched, QEvent* event) {
    if (watched == m_host && event->type() == QEvent::Resize) {
        setGeometry(m_host->rect());
    }
    else if (watched == m_watchedWindow) {
        switch (event->type()) {
        case QEvent::WindowStateChange:
        case QEvent::Show:
        case QEvent::Hide:
            syncTimerState();
            break;
        default:
            break;
        }
    }

    // Never consume anything - this widget is decoration only.
    return QWidget::eventFilter(watched, event);
}

void StarfieldBackground::paintEvent(QPaintEvent* event) {
    Q_UNUSED(event);

    QPainter painter(this);

    // 1. Cached gradient + vignette backdrop.
    if (m_backdrop.isNull())
        rebuildBackdrop();
    painter.setCompositionMode(QPainter::CompositionMode_Source);
    painter.drawPixmap(0, 0, m_backdrop);
    painter.setCompositionMode(QPainter::CompositionMode_SourceOver);

    painter.setRenderHint(QPainter::Antialiasing, true);

    if (m_nodes.isEmpty())
        return;

    const qsizetype nodeCount = m_nodes.size();
    const bool cursorLive = m_mouse.x() > kOffscreen / 2.0;

    QColor whiteNode(255, 255, 255);
    QColor blueNode = kSpectrumLightBlue;

    // 2. Far layer first - pure parallax backdrop, no links, no interaction.
    painter.setPen(Qt::NoPen);
    for (qsizetype i = m_interactiveCount; i < nodeCount; ++i) {
        const Node& node = m_nodes.at(i);
        const qreal twinkle = 1.0 + kTwinkleDepth * qSin(node.twinklePhase);
        QColor colour = node.spectrumBlue ? blueNode : whiteNode;
        colour.setAlphaF(static_cast<float>(qBound(0.0, node.baseAlpha * twinkle, 1.0)));
        painter.setBrush(colour);
        painter.drawEllipse(QPointF(node.x, node.y), node.radius, node.radius);
    }

    // 3. Node-to-node links across the interactive layers. Pairs that both sit
    //    inside the cursor's constellation radius brighten hard - that is what
    //    makes a local shape FORM around the pointer instead of the effect
    //    being nothing but spokes back to the cursor.
    QPen linkPen;
    linkPen.setCapStyle(Qt::RoundCap);

    QColor linkColor = kSpectrumLightBlue;
    for (qsizetype i = 0; i < m_interactiveCount; ++i) {
        const Node& a = m_nodes.at(i);
        const bool aNear = cursorLive
            && qAbs(a.x - m_mouse.x()) < kConstellationRadius
            && qAbs(a.y - m_mouse.y()) < kConstellationRadius;

        for (qsizetype j = i + 1; j < m_interactiveCount; ++j) {
            const Node& b = m_nodes.at(j);
            const qreal dx = a.x - b.x;
            const qreal dy = a.y - b.y;
            const qreal squared = dx * dx + dy * dy;
            if (squared >= kLinkDistance * kLinkDistance)
                continue;

            const qreal distance = qSqrt(squared);
            const qreal falloff = 1.0 - distance / kLinkDistance;

            qreal alpha = falloff * kLinkAlpha;
            qreal width = 0.7;
            linkColor = kSpectrumLightBlue;

            if (aNear
                && qAbs(b.x - m_mouse.x()) < kConstellationRadius
                && qAbs(b.y - m_mouse.y()) < kConstellationRadius) {
                // Strength of the pair is driven by whichever end the cursor is
                // closest to, so the constellation fades in from the edges.
                const qreal proximity = qMax(a.glow, b.glow);
                alpha = falloff * (kLinkAlpha + (kNearLinkAlpha - kLinkAlpha) * proximity);
                width = 0.7 + 0.9 * proximity;
                if (proximity > 0.02)
                    linkColor = kSpectrumBright;
            }

            linkColor.setAlphaF(static_cast<float>(qBound(0.0, alpha, 1.0)));
            linkPen.setColor(linkColor);
            linkPen.setWidthF(width);
            painter.setPen(linkPen);
            painter.drawLine(QPointF(a.x, a.y), QPointF(b.x, b.y));
        }
    }

    // 4. Cursor constellation links. Three stacked passes - a wide dim halo, a
    //    mid body, then a near-white core - so the filaments still read after
    //    the translucent card surfaces above have knocked most of the alpha
    //    out of them.
    if (cursorLive) {
        // A soft travelling halo. This is the part that survives even under the
        // most opaque chrome, so the pointer always has a visible presence.
        QRadialGradient spotlight(m_mouse, kCursorLinkDistance);
        QColor spotCentre = kSpectrumLightBlue;
        spotCentre.setAlphaF(static_cast<float>(kSpotlightAlpha));
        QColor spotMid = kSpectrumLightBlue;
        spotMid.setAlphaF(static_cast<float>(kSpotlightAlpha * 0.35));
        spotlight.setColorAt(0.0, spotCentre);
        spotlight.setColorAt(0.45, spotMid);
        spotlight.setColorAt(1.0, QColor(0, 160, 223, 0));
        painter.setPen(Qt::NoPen);
        painter.setBrush(spotlight);
        painter.drawEllipse(m_mouse, kCursorLinkDistance, kCursorLinkDistance);

        struct LinkPass { qreal width; qreal scale; QColor colour; };
        const LinkPass passes[3] = {
            { kCursorHaloWidth, kCursorHaloScale, kSpectrumLightBlue },
            { kCursorBodyWidth, kCursorBodyScale, kSpectrumLightBlue },
            { kCursorCoreWidth, 1.0,              kSpectrumIce },
        };

        QPen cursorPen;
        cursorPen.setCapStyle(Qt::RoundCap);

        for (const LinkPass& pass : passes) {
            cursorPen.setWidthF(pass.width);
            QColor cursorColor = pass.colour;
            for (qsizetype i = 0; i < m_interactiveCount; ++i) {
                const Node& node = m_nodes.at(i);
                const qreal dx = node.x - m_mouse.x();
                const qreal dy = node.y - m_mouse.y();
                const qreal squared = dx * dx + dy * dy;
                if (squared >= kCursorLinkDistance * kCursorLinkDistance)
                    continue;

                const qreal distance = qSqrt(squared);
                const qreal falloff = 1.0 - distance / kCursorLinkDistance;
                const qreal alpha = falloff * kCursorLinkAlpha * pass.scale;

                cursorColor.setAlphaF(static_cast<float>(qBound(0.0, alpha, 1.0)));
                cursorPen.setColor(cursorColor);
                painter.setPen(cursorPen);
                painter.drawLine(QPointF(node.x, node.y), m_mouse);
            }
        }

        // 5. Sparks: motes shed along fast pointer movement. They link like real
        //    nodes while they last, then fade out.
        QPen sparkPen;
        sparkPen.setCapStyle(Qt::RoundCap);
        sparkPen.setWidthF(0.9);
        QColor sparkColor = kSpectrumLightBlue;

        for (const Spark& spark : m_sparks) {
            if (spark.life <= 0.0)
                continue;

            const qreal fade = spark.life * spark.life;

            for (qsizetype i = 0; i < m_interactiveCount; ++i) {
                const Node& node = m_nodes.at(i);
                const qreal dx = node.x - spark.x;
                const qreal dy = node.y - spark.y;
                const qreal squared = dx * dx + dy * dy;
                if (squared >= kSparkLinkDistance * kSparkLinkDistance)
                    continue;

                const qreal falloff = 1.0 - qSqrt(squared) / kSparkLinkDistance;
                sparkColor.setAlphaF(static_cast<float>(qBound(0.0, falloff * fade * 0.42, 1.0)));
                sparkPen.setColor(sparkColor);
                painter.setPen(sparkPen);
                painter.drawLine(QPointF(node.x, node.y), QPointF(spark.x, spark.y));
            }

            painter.setPen(Qt::NoPen);
            QColor sparkDot(190, 232, 255);
            sparkDot.setAlphaF(static_cast<float>(qBound(0.0, fade * 0.9, 1.0)));
            painter.setBrush(sparkDot);
            painter.drawEllipse(QPointF(spark.x, spark.y), 1.5 * fade + 0.5, 1.5 * fade + 0.5);
        }
    }

    // 6. Interactive nodes on top: twinkle, plus a glow lift while the cursor
    //    is close (bigger and brighter, eased both ways).
    painter.setPen(Qt::NoPen);
    for (qsizetype i = 0; i < m_interactiveCount; ++i) {
        const Node& node = m_nodes.at(i);
        const qreal twinkle = 1.0 + kTwinkleDepth * qSin(node.twinklePhase);
        const qreal alpha = node.baseAlpha * twinkle + (1.0 - node.baseAlpha * twinkle) * node.glow;
        const qreal radius = node.radius * (1.0 + 0.55 * node.glow);

        // Lit nodes shift toward the bright ice tone, so "woken up" reads as a
        // colour change as well as a size change.
        const QColor restColour = node.spectrumBlue ? blueNode : whiteNode;
        QColor colour = node.glow > 0.02
            ? QColor(
                static_cast<int>(restColour.red() + (kSpectrumIce.red() - restColour.red()) * node.glow),
                static_cast<int>(restColour.green() + (kSpectrumIce.green() - restColour.green()) * node.glow),
                static_cast<int>(restColour.blue() + (kSpectrumIce.blue() - restColour.blue()) * node.glow))
            : restColour;
        colour.setAlphaF(static_cast<float>(qBound(0.0, alpha, 1.0)));
        painter.setBrush(colour);
        painter.drawEllipse(QPointF(node.x, node.y), radius, radius);

        // A faint halo only on the strongly lit ones - cheap, and it sells the
        // "this star woke up" read.
        if (node.glow > 0.18) {
            QColor halo = colour;
            halo.setAlphaF(static_cast<float>(qBound(0.0, node.glow * 0.28, 1.0)));
            painter.setBrush(halo);
            painter.drawEllipse(QPointF(node.x, node.y), radius * 2.8, radius * 2.8);
        }
    }
}
