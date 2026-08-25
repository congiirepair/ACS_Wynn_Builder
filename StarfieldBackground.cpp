#include "StarfieldBackground.h"

#include <QPainter>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QShowEvent>
#include <QHideEvent>
#include <QLinearGradient>
#include <QRandomGenerator>
#include <QCursor>
#include <QtMath>

namespace {

// Tuning constants ported 1:1 from the reference canvas background.
constexpr int    kFrameIntervalMs = 33;      // ~30 fps
constexpr int    kMaxNodes = 170;
constexpr int    kAreaPerNode = 9000;
constexpr qreal  kNodeSpeed = 0.28;          // px per frame, +/- half range
constexpr qreal  kNodeRadius = 1.8;
constexpr qreal  kLinkDistance = 130.0;
constexpr qreal  kCursorLinkDistance = 130.0 * 1.6;   // 208 px
constexpr qreal  kLinkAlpha = 0.20;
constexpr qreal  kCursorLinkAlpha = 0.28;
constexpr qreal  kOffscreen = -9999.0;

// Spectrum brand palette.
const QColor kSpectrumLightBlue(0, 160, 223);   // #00A0DF
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

    // Preallocate once; advanceFrame() never touches the heap afterwards.
    m_nodes.resize(desired);
    for (Node& node : m_nodes) {
        node.x = randomUnit() * w;
        node.y = randomUnit() * h;
        node.vx = (randomUnit() - 0.5) * kNodeSpeed;
        node.vy = (randomUnit() - 0.5) * kNodeSpeed;
        node.spectrumBlue = randomUnit() < 0.5;
    }
}

void StarfieldBackground::trackCursor() {
    // Polling the cursor is deliberate: an application wide MouseMove filter
    // only sees moves while a button is held (or with mouse tracking enabled on
    // every widget), and installing a global filter on a production app is a
    // far bigger blast radius than one cheap mapFromGlobal per frame.
    const QPoint local = mapFromGlobal(QCursor::pos());
    if (rect().contains(local))
        m_mouse = QPointF(local);
    else
        m_mouse = QPointF(kOffscreen, kOffscreen);
}

void StarfieldBackground::advanceFrame() {
    const qreal w = width();
    const qreal h = height();

    for (Node& node : m_nodes) {
        node.x += node.vx;
        node.y += node.vy;

        if (node.x < 0.0 || node.x > w)
            node.vx = -node.vx;
        if (node.y < 0.0 || node.y > h)
            node.vy = -node.vy;
    }

    trackCursor();
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
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRectF fullRect = rect();

    // 1. Near-black vertical gradient backdrop.
    QLinearGradient backdrop(fullRect.topLeft(), fullRect.bottomLeft());
    backdrop.setColorAt(0.0, kGradientTop);
    backdrop.setColorAt(1.0, kGradientBottom);
    painter.fillRect(fullRect, backdrop);

    if (m_nodes.isEmpty())
        return;

    const qsizetype nodeCount = m_nodes.size();

    // 2. Node-to-node links.
    QPen linkPen;
    linkPen.setWidthF(0.6);
    linkPen.setCapStyle(Qt::RoundCap);

    QColor linkColor = kSpectrumLightBlue;
    for (qsizetype i = 0; i < nodeCount; ++i) {
        const Node& a = m_nodes.at(i);
        for (qsizetype j = i + 1; j < nodeCount; ++j) {
            const Node& b = m_nodes.at(j);
            const qreal dx = a.x - b.x;
            const qreal dy = a.y - b.y;
            const qreal squared = dx * dx + dy * dy;
            if (squared >= kLinkDistance * kLinkDistance)
                continue;

            const qreal distance = qSqrt(squared);
            linkColor.setAlphaF(static_cast<float>((1.0 - distance / kLinkDistance) * kLinkAlpha));
            linkPen.setColor(linkColor);
            painter.setPen(linkPen);
            painter.drawLine(QPointF(a.x, a.y), QPointF(b.x, b.y));
        }
    }

    // 3. Cursor constellation links.
    if (m_mouse.x() > kOffscreen / 2.0) {
        QPen cursorPen;
        cursorPen.setWidthF(0.7);
        cursorPen.setCapStyle(Qt::RoundCap);

        QColor cursorColor = kSpectrumLightBlue;
        for (qsizetype i = 0; i < nodeCount; ++i) {
            const Node& node = m_nodes.at(i);
            const qreal dx = node.x - m_mouse.x();
            const qreal dy = node.y - m_mouse.y();
            const qreal squared = dx * dx + dy * dy;
            if (squared >= kCursorLinkDistance * kCursorLinkDistance)
                continue;

            const qreal distance = qSqrt(squared);
            cursorColor.setAlphaF(static_cast<float>((1.0 - distance / kCursorLinkDistance) * kCursorLinkAlpha));
            cursorPen.setColor(cursorColor);
            painter.setPen(cursorPen);
            painter.drawLine(QPointF(node.x, node.y), m_mouse);
        }
    }

    // 4. Nodes themselves.
    painter.setPen(Qt::NoPen);

    QColor whiteNode(255, 255, 255);
    whiteNode.setAlphaF(0.9f);
    QColor blueNode = kSpectrumLightBlue;
    blueNode.setAlphaF(0.9f);

    for (qsizetype i = 0; i < nodeCount; ++i) {
        const Node& node = m_nodes.at(i);
        painter.setBrush(node.spectrumBlue ? blueNode : whiteNode);
        painter.drawEllipse(QPointF(node.x, node.y), kNodeRadius, kNodeRadius);
    }
}
