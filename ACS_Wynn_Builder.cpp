#include "ACS_Wynn_Builder.h"
#include <QGuiApplication>
#include <QCoreApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QTimer>
#include <QIcon>
#include <QThread>
#include <QDebug>
#include <QDesktopServices>
#include <QDateTime>
#include <QElapsedTimer>
#include <QGridLayout>
#include <QCryptographicHash>
#include <QDialogButtonBox>
#include <QScreen>
#include <algorithm>

QString resolveCiscoInterfaceName(const QString& selection);
QString formatCiscoInterfaceLabel(const QString& interfaceName);
QStringList ciscoWizardMiscGroups();
bool ensureTrustedHost(QWidget* parent, const QString& ip, const QString& user,
    const DeploymentOptions& deployOptions, QString* errorMessage = nullptr);
bool fetchCiscoWlanSummary(QWidget* parent, const QString& ip, const QString& user, const QString& pass,
    QString* output, QString* errorMessage = nullptr);

QList<int> extractCiscoUsedWlanIds(const QString& rawSummary) {
    QRegularExpression idRegex(R"((?m)^\s*(\d+)\s+\S)");
    QRegularExpressionMatchIterator matches = idRegex.globalMatch(rawSummary);
    QList<int> usedIds;
    while (matches.hasNext()) {
        const QRegularExpressionMatch match = matches.next();
        bool ok = false;
        const int id = match.captured(1).toInt(&ok);
        if (ok && !usedIds.contains(id))
            usedIds << id;
    }

    std::sort(usedIds.begin(), usedIds.end());
    return usedIds;
}

int findLowestAvailableCiscoWlanId(const QList<int>& usedIds, int minimumExclusive = 60) {
    for (int candidate = minimumExclusive + 1; candidate <= 512; ++candidate) {
        if (!usedIds.contains(candidate))
            return candidate;
    }

    return -1;
}

int extractSuggestedCiscoWlanId(const QString& summarizedOutput) {
    QRegularExpression suggestedRegex(R"((?im)^Lowest available ID above 60:\s*(\d+)\s*$)");
    const QRegularExpressionMatch match = suggestedRegex.match(summarizedOutput);
    if (!match.hasMatch())
        return -1;

    bool ok = false;
    const int suggestedId = match.captured(1).toInt(&ok);
    return ok ? suggestedId : -1;
}

QString sanitizeCiscoWlanSummaryTranscript(const QString& rawSummary) {
    const QString normalized = rawSummary;
    const QStringList lines = normalized.split(QRegularExpression(R"(\r?\n)"));
    QStringList cleanedLines;

    const QList<QRegularExpression> skipPatterns = {
        QRegularExpression(R"(^\s*$)"),
        QRegularExpression(R"(^\s*config paging disable\s*$)", QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(R"(^\s*show wlan summary\s*$)", QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(R"(^\s*[-\w().:@/]+\s*[>#]\s*$)"),
        QRegularExpression(R"(^\s*[-\w().:@/]+\s*[>#]\s*(config paging disable|show wlan summary)\s*$)", QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(R"(^\s*--more--(?:\s+or\s+\(q\)uit)?\s*$)", QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(R"(^\s*\(q\)uit\s*$)", QRegularExpression::CaseInsensitiveOption)
    };

    for (const QString& line : lines) {
        const QString trimmed = line.trimmed();
        bool skip = false;
        for (const QRegularExpression& pattern : skipPatterns) {
            if (pattern.match(trimmed).hasMatch()) {
                skip = true;
                break;
            }
        }

        if (!skip)
            cleanedLines << line;
    }

    return cleanedLines.join("\n").trimmed();
}

QString summarizeCiscoWlanIds(const QString& rawSummary) {
    const QString cleanedSummary = sanitizeCiscoWlanSummaryTranscript(rawSummary);
    const QList<int> usedIds = extractCiscoUsedWlanIds(cleanedSummary);
    const int suggestedId = findLowestAvailableCiscoWlanId(usedIds, 60);

    QStringList nextAvailable;
    for (int candidate = 61; candidate <= 512 && nextAvailable.size() < 12; ++candidate) {
        if (!usedIds.contains(candidate))
            nextAvailable << QString::number(candidate);
    }

    QStringList usedIdStrings;
    for (int id : usedIds)
        usedIdStrings << QString::number(id);

    QStringList report;
    report << ">>> Cisco WLAN ID summary";
    report << "Used IDs: " + (usedIdStrings.isEmpty() ? QString("<none detected>") : usedIdStrings.join(", "));
    report << "Lowest available ID above 60: " + (suggestedId > 0 ? QString::number(suggestedId) : QString("<none detected>"));
    report << "Next available IDs: " + (nextAvailable.isEmpty() ? QString("<none detected>") : nextAvailable.join(", "));
    report << "";
    report << "Raw controller output:";
    report << (cleanedSummary.isEmpty() ? QString("<no WLAN summary returned>") : cleanedSummary);
    return report.join("\n");
}

// ====================================================
// SYNTAX HIGHLIGHTER
// ====================================================

ArubaHighlighter::ArubaHighlighter(QTextDocument* parent) : QSyntaxHighlighter(parent) {
    keywordFormat.setForeground(QColor("#569CD6"));
    keywordFormat.setFontWeight(QFont::Bold);
    stringFormat.setForeground(QColor("#CE9178"));
    commentFormat.setForeground(QColor("#6A9955"));
    commentFormat.setFontItalic(true);
}

void ArubaHighlighter::highlightBlock(const QString& text) {
    QRegularExpression stringRegex("\".*?\"");
    QRegularExpressionMatchIterator i = stringRegex.globalMatch(text);
    while (i.hasNext()) {
        QRegularExpressionMatch match = i.next();
        setFormat(match.capturedStart(), match.capturedLength(), stringFormat);
    }

    static const QStringList keywords = {
        "aaa", "authentication", "profile", "wlan", "ssid-profile",
        "virtual-ap", "ap-group", "vlan", "opmode", "configuration",
        "write", "memory", "change-config-node", "configure", "terminal", "no", "end"
    };
    for (const QString& kw : keywords) {
        QRegularExpression kwRegex("\\b" + kw + "\\b");
        QRegularExpressionMatchIterator j = kwRegex.globalMatch(text);
        while (j.hasNext()) {
            QRegularExpressionMatch match = j.next();
            setFormat(match.capturedStart(), match.capturedLength(), keywordFormat);
        }
    }

    if (text.startsWith("!")) {
        setFormat(0, text.length(), commentFormat);
    }
}

// ====================================================
// SHARED CONFIG BUILDER (FIX: single source of truth)
// ====================================================

// FIX (C++ Code): This free function replaces the duplicated config-generation
// blocks that previously existed independently in buildConfigScript() and
// WizardPage5::initializePage(). Both now call this function.
QString buildArubaConfig(const QString& ssid,
    const QString& vlan,
    const QString& auth,
    const QString& psk,
    const QString& role,
    bool           hideSsid,
    bool           splashPage,
    int            siteIdx,
    const QStringList& groups,
    const ApGroupData& apData)
{
    QString path = (siteIdx == 0) ? apData.wynnConfigPath : apData.stationsConfigPath;
    QString htProfile = ssid;
    QString effectiveRole = role.trimmed().isEmpty() ? "50Mbps-Per-User" : role.trimmed();
    const QString effectiveAuth = splashPage ? "Open" : auth;

    QStringList config;
    config << "! ==========================================";
    config << "! TARGET SSID: " + ssid;
    config << "! TARGET AP GROUPS (" + QString::number(groups.size()) + " Total):";
    for (const QString& g : groups) config << "!   - " + g;
    config << "! ==========================================\n";

    if (siteIdx == 1) config << "change-config-node " + path;
    else              config << "cd " + path;

    config << "configure terminal";

    config << "aaa authentication dot1x \"" + ssid + "\"" << "!";
    config << "aaa profile \"" + ssid + "\""
        << "  authentication-dot1x \"" + ssid + "\""
        << "  initial-role \"" + effectiveRole + "\""
        << "  enforce-dhcp" << "!";

    config << "wlan ht-ssid-profile \"" + htProfile + "\""
        << "  no 80mhz-enable"
        << "  no 40mhz-enable" << "!";

    config << "wlan ssid-profile \"" + ssid + "\""
        << "  essid \"" + ssid + "\"";

    if (hideSsid)
        config << "  hide-ssid";

    if (effectiveAuth == "WPA2-PSK")
        config << "  wpa-passphrase \"" + (psk.isEmpty() ? "CHANGEME" : psk) + "\""
        << "  opmode wpa2-psk-aes";
    else
        config << "  opmode opensystem";

    config << "  opmode-transition"
        << "  dot11r-profile \"default\""
        << "  dtim-period 1"
        << "  no qbss-load-enable"
        << "  advertise-location"
        << "  advertise-ap-name"
        << "  g-tx-rates 24 36 48 54"
        << "  a-tx-rates 24 36 48 54"
        << "  g-basic-rates 24"
        << "  a-basic-rates 24"
        << "  a-beacon-rate 24"
        << "  g-beacon-rate 24"
        << "  Max-clients 250"
        << "  local-probe-req-thresh 6"
        << "  ht-ssid-profile \"" + htProfile + "\"" << "!";

    config << "wlan virtual-ap \"" + ssid + "\""
        << "  aaa-profile \"" + ssid + "\""
        << "  dot11k-profile \"default\"";

    if (!vlan.isEmpty()) config << "  vlan " + vlan;

    if (siteIdx == 1) config << "  forward-mode decrypt-tunnel";
    else              config << "  forward-mode tunnel";

    config << "  band-steering"
        << "  broadcast-filter all"
        << "  ssid-profile \"" + ssid + "\"" << "!";

    for (const QString& g : groups) {
        config << "ap-group \"" + g + "\"" << "  virtual-ap \"" + ssid + "\"" << "!";
    }

    config << "end";
    config << "configuration commit";
    config << "configuration commit";
    config << "write memory";

    return config.join("\n");
}

QString buildCiscoWlanConfig(const QString& ssid,
    const QString& vlan,
    const QString& psk,
    const QString& wlanId,
    const QString& companyName,
    const QString& removalDate,
    const QString& maxClients,
    bool           splashPage,
    const QStringList& groups)
{
    if (ssid.trimmed().isEmpty())
        return "! ERROR: Please enter a Broadcast SSID.";

    if (groups.isEmpty())
        return "! ERROR: Select at least one Wynn AP group for the Cisco generator.";

    if (companyName.trimmed().isEmpty())
        return "! ERROR: Please enter a Company Name.";

    if (removalDate.trimmed().isEmpty())
        return "! ERROR: Please enter a Removal Date.";

    if (wlanId.trimmed().isEmpty())
        return "! ERROR: Please enter a WLAN ID.";

    if (maxClients.trimmed().isEmpty())
        return "! ERROR: Please enter Max Clients.";

    if (vlan.trimmed().isEmpty())
        return "! ERROR: Please select a VLAN or interface.";

    if (!splashPage && psk.length() < 8)
        return "! ERROR: WPA2-PSK requires a password of at least 8 characters.";

    const QString trimmedWlanId = wlanId.trimmed();
    const QString profileLabel = companyName.trimmed() + " " + removalDate.trimmed();
    const QString interfaceName = resolveCiscoInterfaceName(vlan);

    QStringList config;
    config << "! ==========================================";
    config << "! CISCO WYNN WLAN TEMPLATE";
    config << "! Review the company/date label, interface/VLAN, and selected AP groups before deployment.";
    config << "! TARGET AP GROUPS (" + QString::number(groups.size()) + " Total):";
    for (const QString& group : groups)
        config << "!   - " + group;
    config << "! ==========================================";
    config << "";
    config << "config wlan create " + trimmedWlanId + " \"" + profileLabel + "\" \"" + ssid + "\"";
    config << "config wlan interface " + trimmedWlanId + " \"" + interfaceName + "\"";
    config << "config wlan max-associated-clients " + maxClients.trimmed() + " " + trimmedWlanId;
    config << "config wlan exclusionlist " + trimmedWlanId + " disabled";
    if (splashPage) {
        config << "config wlan security wpa disable " + trimmedWlanId;
        config << "config wlan security wpa akm 802.1x disable " + trimmedWlanId;
        config << "config wlan security wpa akm psk disable " + trimmedWlanId;
        config << "config wlan security wpa akm ft psk disable " + trimmedWlanId;
        config << "config wlan security splash-page-web-redir enable " + trimmedWlanId;
    } else {
        config << "config wlan security ft enable " + trimmedWlanId;
        config << "y";
        config << "config wlan security ft over-the-ds disable " + trimmedWlanId;
        config << "config wlan security wpa wpa2 ciphers aes enable " + trimmedWlanId;
        config << "config wlan security wpa akm 802.1x disable " + trimmedWlanId;
        config << "config wlan security wpa akm ft 802.1x disable " + trimmedWlanId;
        config << "config wlan security wpa akm psk enable " + trimmedWlanId;
        config << "config wlan security wpa akm ft psk enable " + trimmedWlanId;
        config << "config wlan security wpa akm psk set-key ascii \"" + psk + "\" " + trimmedWlanId;
        config << "config wlan security splash-page-web-redir disable " + trimmedWlanId;
    }
    config << "config wlan band-select allow enable " + trimmedWlanId;
    config << "y";
    config << "config wlan assisted-roaming neighbor-list enable " + trimmedWlanId;
    config << "config wlan ccx aironetieSupport disable " + trimmedWlanId;
    config << "config wlan override-rate-limit " + trimmedWlanId + " average-data-rate per-client downstream 51000";
    config << "config wlan override-rate-limit " + trimmedWlanId + " average-data-rate per-client upstream 51000";
    config << "config wlan override-rate-limit " + trimmedWlanId + " average-realtime-rate per-client downstream 51000";
    config << "config wlan override-rate-limit " + trimmedWlanId + " average-realtime-rate per-client upstream 51000";
    config << "config wlan override-rate-limit " + trimmedWlanId + " burst-data-rate per-client downstream 52000";
    config << "config wlan override-rate-limit " + trimmedWlanId + " burst-data-rate per-client upstream 52000";
    config << "config wlan override-rate-limit " + trimmedWlanId + " burst-realtime-rate per-client downstream 52000";
    config << "config wlan override-rate-limit " + trimmedWlanId + " burst-realtime-rate per-client upstream 52000";
    config << "config wlan enable " + trimmedWlanId;
    config << "save config";
    config << "y";

    for (const QString& group : groups)
        config << "config wlan apgroup interface-mapping add " + group + " " + trimmedWlanId + " \"" + interfaceName + "\"";

    config << "save config";
    config << "y";

    return config.join("\n");
}

// ====================================================
// NAME MASKING HELPER
// ====================================================

// FIX (C++ Code): Replaced 14 chained replace() calls with a static QMap.
// Adding or editing a mapping is now one line instead of a hunt-and-paste.
QString getCleanName(const QString& raw) {
    static const QList<QPair<QString, QString>> replacements = {
        {"ACS-RR-Office",                  "ACS Office"},
        {"ACS_GVR_Office",                 "ACS Office"},
        {"WYNN|ENCORE-THEATRE|LOBBY",      "Theater Lobby"},
        {"WYNN|ENCORE-THEATRE",            "Theater"},
        {".Boulder-Convention",            "Boulder Conv"},
        {".FiestaHenderson-Convention",    "Fiesta Henderson Conv"},
        {".Palace-Convention",             "Palace Conv"},
        {".SantaFe-Convention",            "Santa Fe Conv"},
        {".Sunset-Convention",             "Sunset Conv"},
        {".Texas-Convention",              "Texas Conv"},
        {"RedRock",                        "Red Rock"},
        {"RR-",                            ""},
        {"RR_",                            ""},
        {"GVR-",                           ""},
        {"DUR-",                           ""},
        {"_",                              " "},
    };

    QString clean = raw;
    for (const auto& pair : replacements)
        clean.replace(pair.first, pair.second);
    return clean;
}

QStringList defaultCiscoInterfaceList() {
    return {
        "wynn-acs-1",
        "wynn-acs-2",
        "wynn-acs-3",
        "wynn-acs-4",
        "wynn-acs-5",
        "wynn-acs-6",
        "convention_vl321_public",
        "convention_vl322_public",
        "convention_vl323_public",
        "convention_vl325_public",
        "convention_vl326_public",
        "convention_vl327_public",
        "convention_vl328_public",
        "convention_vl350_private",
        "convention_vl351_private",
        "convention_vl352_private",
        "convention_vl353_private",
        "convention_vl354_private",
        "convention_vl355_private",
        "convention_vl356_private",
        "convention_vl357_private",
        "convention_vl358_private",
        "convention_vl359_private",
        "convention_vl360_private",
        "dry650",
        "dry651",
        "dry652",
        "dry653",
        "dry654",
        "dry655",
        "dry656",
        "dry657",
        "dry658",
        "dry659",
        "dry660",
        "wynn_convention_wireless",
        "encore_convention_wireless",
        "encore_wired"
    };
}

QString resolveCiscoInterfaceName(const QString& selection) {
    const QString trimmed = selection.trimmed();
    if (trimmed.isEmpty())
        return QString();

    const int separatorIndex = trimmed.indexOf(" - ");
    if (separatorIndex > 0)
        return trimmed.mid(separatorIndex + 3).trimmed();

    bool isNumeric = false;
    const int vlan = trimmed.toInt(&isNumeric);
    if (isNumeric)
        return QString("convention_vl%1_private").arg(vlan);

    return trimmed;
}

QString formatCiscoInterfaceLabel(const QString& interfaceName) {
    const QString trimmed = interfaceName.trimmed();
    if (trimmed.isEmpty())
        return QString();

    QRegularExpression conventionRegex("^convention_vl(\\d+)_(public|private)$");
    QRegularExpressionMatch conventionMatch = conventionRegex.match(trimmed);
    if (conventionMatch.hasMatch())
        return conventionMatch.captured(1) + " - " + trimmed;

    QRegularExpression dryRegex("^dry(\\d+)$");
    QRegularExpressionMatch dryMatch = dryRegex.match(trimmed);
    if (dryMatch.hasMatch())
        return dryMatch.captured(1) + " - " + trimmed;

    QRegularExpression acsRegex("^wynn-acs-(\\d+)$");
    QRegularExpressionMatch acsMatch = acsRegex.match(trimmed);
    if (acsMatch.hasMatch()) {
        bool ok = false;
        const int suffix = acsMatch.captured(1).toInt(&ok);
        if (ok)
            return QString::number(311 + suffix) + " - " + trimmed;
    }

    if (trimmed.compare("wynn_convention_wireless", Qt::CaseInsensitive) == 0)
        return "Wynn-Convention - " + trimmed;

    if (trimmed.compare("encore_convention_wireless", Qt::CaseInsensitive) == 0)
        return "Encore-Convention - " + trimmed;

    if (trimmed.compare("encore_wired", Qt::CaseInsensitive) == 0)
        return "encore_wired - " + trimmed;

    return trimmed;
}

QStringList ciscoWizardMiscGroups() {
    return {
        "C4",
        "B10AP",
        "Catering_Office",
        "Delilah",
        "Encore-Rooms-Wireless",
        "EncoreBusinessCenter",
        "Spa-Villa-Wireless",
        "Wing-Lei",
        "WYNN|ENCORE-THEATRE",
        "WYNN|ENCORE-THEATRE|LOBBY",
        "New_Wynn_BOH",
        "Pavillion/Garden",
        "Wynn-Catwalk-Wireless",
        "Wynn-Roof-Wireless",
        "WynnBusinessCenter",
        "Wynn_Convention",
        "Wynn_Expansion_test",
        "XS Encore Beachclub"
    };
}

bool ensureTrustedHost(QWidget* parent, const QString& ip, const QString& user,
    const DeploymentOptions& deployOptions, QString* errorMessage)
{
    if (errorMessage)
        errorMessage->clear();

    ssh_session session = ssh_new();
    if (!session) {
        if (errorMessage)
            *errorMessage = "Unable to create SSH session for host trust check.";
        return false;
    }

    const QByteArray hostUtf8 = ip.toUtf8();
    const QByteArray userUtf8 = user.toUtf8();
    const int sshPort = 22;
    int sshTimeoutSeconds = deployOptions.useCiscoShellLogin ? 120 : 60;

    ssh_options_set(session, SSH_OPTIONS_HOST, hostUtf8.constData());
    if (!userUtf8.isEmpty())
        ssh_options_set(session, SSH_OPTIONS_USER, userUtf8.constData());
    ssh_options_set(session, SSH_OPTIONS_PORT, &sshPort);
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &sshTimeoutSeconds);

    if (deployOptions.useCiscoShellLogin) {
        const char* preferredHostKeys = "ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519";
        const char* preferredKex = "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256";
        const char* preferredCiphers = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc";
        const char* preferredHmacs = "hmac-sha1,hmac-sha2-256,hmac-sha2-512";
        ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, preferredHostKeys);
        ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, preferredKex);
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, preferredCiphers);
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, preferredCiphers);
        ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, preferredHmacs);
        ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, preferredHmacs);
    }

    const auto cleanupSession = [&]() {
        ssh_disconnect(session);
        ssh_free(session);
    };

    if (ssh_connect(session) != SSH_OK) {
        if (errorMessage)
            *errorMessage = QString("Connection failed during host trust check: %1").arg(ssh_get_error(session));
        cleanupSession();
        return false;
    }

    const int knownState = ssh_session_is_known_server(session);
    if (knownState == SSH_KNOWN_HOSTS_OK) {
        cleanupSession();
        return true;
    }

    ssh_key serverKey = nullptr;
    unsigned char* hash = nullptr;
    size_t hashLen = 0;
    QString fingerprint = "<unavailable>";

    if (ssh_get_server_publickey(session, &serverKey) == SSH_OK) {
        if (ssh_get_publickey_hash(serverKey, SSH_PUBLICKEY_HASH_SHA256, &hash, &hashLen) == SSH_OK && hash && hashLen > 0) {
            fingerprint = QString::fromUtf8(ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hashLen));
        }
    }

    QString stateLabel;
    switch (knownState) {
    case SSH_KNOWN_HOSTS_CHANGED:
        stateLabel = "The controller host key has changed.";
        break;
    case SSH_KNOWN_HOSTS_OTHER:
        stateLabel = "A different host key type is already stored for this controller.";
        break;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
        stateLabel = "No known_hosts file was found for this Windows profile yet.";
        break;
    case SSH_KNOWN_HOSTS_UNKNOWN:
        stateLabel = "This controller is not present in known_hosts.";
        break;
    case SSH_KNOWN_HOSTS_ERROR:
    default:
        stateLabel = QString("Unable to verify the controller host key: %1").arg(ssh_get_error(session));
        break;
    }

    QMessageBox trustPrompt(parent);
    trustPrompt.setIcon(QMessageBox::Warning);
    trustPrompt.setWindowTitle("Trust Controller Host Key");
    trustPrompt.setText(QString("Trust this %1 controller?").arg(deployOptions.useCiscoShellLogin ? "Cisco" : "Aruba"));
    trustPrompt.setInformativeText(
        QString("Controller: %1\nStatus: %2\nSHA-256 fingerprint: %3")
        .arg(ip, stateLabel, fingerprint));
    QPushButton* trustButton = trustPrompt.addButton("Trust", QMessageBox::AcceptRole);
    trustPrompt.addButton(QMessageBox::Cancel);
    trustPrompt.exec();

    const bool accepted = (trustPrompt.clickedButton() == trustButton);
    if (!accepted) {
        if (errorMessage)
            *errorMessage = "Host trust was cancelled.";
        if (hash)
            ssh_clean_pubkey_hash(&hash);
        if (serverKey)
            ssh_key_free(serverKey);
        cleanupSession();
        return false;
    }

    if (ssh_session_update_known_hosts(session) != SSH_OK) {
        if (errorMessage)
            *errorMessage = QString("Failed to save trusted host key: %1").arg(ssh_get_error(session));
        if (hash)
            ssh_clean_pubkey_hash(&hash);
        if (serverKey)
            ssh_key_free(serverKey);
        cleanupSession();
        return false;
    }

    if (hash)
        ssh_clean_pubkey_hash(&hash);
    if (serverKey)
        ssh_key_free(serverKey);
    cleanupSession();
    return true;
}

bool fetchCiscoWlanSummary(QWidget* parent, const QString& ip, const QString& user, const QString& pass,
    QString* output, QString* errorMessage)
{
    if (output)
        output->clear();
    if (errorMessage)
        errorMessage->clear();

    DeploymentOptions deployOptions;
    deployOptions.sendInitialEnter = true;
    deployOptions.useCiscoShellLogin = true;
    deployOptions.testOnly = true;

    QString trustError;
    if (!ensureTrustedHost(parent, ip, user, deployOptions, &trustError)) {
        if (errorMessage)
            *errorMessage = trustError;
        return false;
    }

    ssh_session session = ssh_new();
    if (!session) {
        if (errorMessage)
            *errorMessage = "Unable to create SSH session for Cisco WLAN ID lookup.";
        return false;
    }

    ssh_channel channel = nullptr;
    const QByteArray hostUtf8 = ip.toUtf8();
    const QByteArray userUtf8 = user.toUtf8();
    const int sshPort = 22;
    int sshTimeoutSeconds = 120;

    ssh_options_set(session, SSH_OPTIONS_HOST, hostUtf8.constData());
    ssh_options_set(session, SSH_OPTIONS_USER, userUtf8.constData());
    ssh_options_set(session, SSH_OPTIONS_PORT, &sshPort);
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &sshTimeoutSeconds);

    const char* preferredHostKeys = "ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519";
    const char* preferredKex = "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256";
    const char* preferredCiphers = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc";
    const char* preferredHmacs = "hmac-sha1,hmac-sha2-256,hmac-sha2-512";
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, preferredHostKeys);
    ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, preferredKex);
    ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, preferredCiphers);
    ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, preferredCiphers);
    ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, preferredHmacs);
    ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, preferredHmacs);

    const auto cleanup = [&]() {
        if (channel) {
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            channel = nullptr;
        }
        ssh_disconnect(session);
        ssh_free(session);
    };

    if (ssh_connect(session) != SSH_OK) {
        if (errorMessage)
            *errorMessage = QString("Connection failed: %1").arg(ssh_get_error(session));
        cleanup();
        return false;
    }

    if (ssh_userauth_none(session, nullptr) == SSH_AUTH_ERROR) {
        if (errorMessage)
            *errorMessage = QString("Authentication probe failed: %1").arg(ssh_get_error(session));
        cleanup();
        return false;
    }

    channel = ssh_channel_new(session);
    if (!channel || ssh_channel_open_session(channel) != SSH_OK || ssh_channel_request_pty(channel) != SSH_OK || ssh_channel_request_shell(channel) != SSH_OK) {
        if (errorMessage)
            *errorMessage = QString("Failed to open Cisco shell: %1").arg(ssh_get_error(session));
        cleanup();
        return false;
    }

    char readBuf[4096];
    auto readNonBlocking = [&](QString* collected) {
        bool receivedData = false;
        int n = 0;
        while ((n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0)) > 0) {
            readBuf[n] = '\0';
            const QString chunk = QString::fromLocal8Bit(readBuf, n);
            if (collected)
                collected->append(chunk);
            receivedData = true;
        }
        return receivedData;
    };
    auto waitForPrompt = [&](const QStringList& prompts, int timeoutMs, QString* transcript, const QString& stageLabel) {
        QString collected = transcript ? *transcript : QString();
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            const bool receivedData = readNonBlocking(&collected);
            const QString lowered = collected.toLower();
            for (const QString& prompt : prompts) {
                if (lowered.contains(prompt.toLower())) {
                    if (transcript)
                        *transcript = collected;
                    return true;
                }
            }
            if (!receivedData)
                QThread::msleep(100);
        }

        if (errorMessage) {
            QString snippet = collected.simplified();
            if (snippet.length() > 220)
                snippet = snippet.left(220) + "...";
            if (snippet.isEmpty())
                snippet = "(no controller output received)";
            *errorMessage = QString("Timed out during %1. Last output: %2").arg(stageLabel, snippet);
        }
        return false;
    };
    auto writeShellLine = [&](const QString& line) {
        const QByteArray payload = (line + "\n").toUtf8();
        return ssh_channel_write(channel, payload.constData(), static_cast<uint32_t>(payload.size()));
    };
    auto waitForCiscoPrompt = [&](const QStringList& prompts, const QString& stageLabel, QString* transcript) {
        if (waitForPrompt(prompts, 20000, transcript, stageLabel))
            return true;
        writeShellLine(QString());
        if (waitForPrompt(prompts, 20000, transcript, stageLabel + " retry"))
            return true;
        writeShellLine(QString());
        return waitForPrompt(prompts, 20000, transcript, stageLabel + " final retry");
    };

    ssh_channel_write(channel, "\n", 1);
    QThread::msleep(300);

    QString transcript;
    if (!waitForCiscoPrompt({ "login as:", "please enter the user", "user:", "password:", ">", "#" }, "initial Cisco controller prompt", &transcript)) {
        cleanup();
        return false;
    }

    QString loweredTranscript = transcript.toLower();
    if (loweredTranscript.contains("login as:")) {
        writeShellLine(QString());
        transcript.clear();
        if (!waitForCiscoPrompt({ "please enter the user", "user:", "password:", ">", "#" }, "blank login name handoff", &transcript)) {
            cleanup();
            return false;
        }
        loweredTranscript = transcript.toLower();
    }

    if (loweredTranscript.contains("user:")) {
        writeShellLine(user);
        transcript.clear();
        if (!waitForCiscoPrompt({ "password:", "user:", ">", "#" }, "username submission", &transcript)) {
            cleanup();
            return false;
        }
        loweredTranscript = transcript.toLower();
        if (loweredTranscript.contains("user:")) {
            writeShellLine(user);
            transcript.clear();
            if (!waitForCiscoPrompt({ "password:", ">", "#" }, "username resubmission", &transcript)) {
                cleanup();
                return false;
            }
            loweredTranscript = transcript.toLower();
        }
    }

    if (loweredTranscript.contains("password:")) {
        writeShellLine(pass);
        transcript.clear();
        if (!waitForPrompt({ ">", "#", "save config", "config wlan" }, 20000, &transcript, "password submission")) {
            cleanup();
            return false;
        }
    }

    writeShellLine("config paging disable");
    QThread::msleep(250);
    if (writeShellLine("show wlan summary") == SSH_ERROR) {
        if (errorMessage)
            *errorMessage = "Failed to send 'show wlan summary' to the Cisco controller.";
        cleanup();
        return false;
    }

    auto sendPagerContinue = [&]() {
        const char space = ' ';
        return ssh_channel_write(channel, &space, 1);
    };

    QString summaryOutput;
    QElapsedTimer totalTimer;
    QElapsedTimer quietTimer;
    totalTimer.start();
    quietTimer.start();

    while (totalTimer.elapsed() < 15000) {
        bool receivedData = false;
        int n = 0;
        while ((n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0)) > 0) {
            readBuf[n] = '\0';
            QString chunk = QString::fromLocal8Bit(readBuf, n);
            while (chunk.contains("--More--", Qt::CaseInsensitive) || chunk.contains("(q)uit", Qt::CaseInsensitive)) {
                chunk.replace("--More-- or (q)uit", "", Qt::CaseInsensitive);
                chunk.replace("--More--", "", Qt::CaseInsensitive);
                chunk.replace("(q)uit", "", Qt::CaseInsensitive);
                if (sendPagerContinue() == SSH_ERROR) {
                    if (errorMessage)
                        *errorMessage = "Cisco paging prompt appeared, but the app could not continue reading.";
                    cleanup();
                    return false;
                }
            }
            summaryOutput.append(chunk);
            receivedData = true;
        }

        if (receivedData) {
            quietTimer.restart();
        } else if (quietTimer.elapsed() >= 1200 && !sanitizeCiscoWlanSummaryTranscript(summaryOutput).isEmpty()) {
            break;
        }
        QThread::msleep(100);
    }

    if (sanitizeCiscoWlanSummaryTranscript(summaryOutput).isEmpty()) {
        if (errorMessage)
            *errorMessage = "No WLAN summary was returned from 'show wlan summary'.";
        cleanup();
        return false;
    }

    if (output)
        *output = summarizeCiscoWlanIds(summaryOutput);
    cleanup();
    return true;
}

QString buildAppStyleSheet(bool darkMode) {
    if (darkMode) {
        return R"(
        QMainWindow, QWidget#centralWidget {
            background-color: #07111F;
            border: 1px solid #10233E;
        }
        #titleBar { background-color: #030712; border-bottom: 1px solid #374151; }
        #titleLabel { color: #62C8FF; font-family: 'Segoe UI Variable', 'Segoe UI'; font-size: 13px; font-weight: 700; letter-spacing: 1.2px; padding-left: 10px; }
        #titleBar QPushButton { background-color: transparent; border: none; padding: 6px 14px; color: #9CA3AF; }
        #titleBar QPushButton:hover { background-color: #374151; color: #FFFFFF; }
        #btn_close:hover { background-color: #EF4444; color: #FFFFFF; }
        QLabel {
            color: #C7D4E7;
            font-family: 'Segoe UI Variable';
            font-size: 12px;
            font-weight: 600;
            background: transparent;
        }
        QFrame {
            background-color: #0D182B;
            border: 1px solid #183252;
            border-radius: 14px;
        }
        QFrame#heroCard {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 #102748, stop:0.55 #0B1830, stop:1 #08111E);
            border: 1px solid #234C7F;
            border-radius: 22px;
        }
        QLabel#heroTitle {
            color: #F4FAFF;
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 0.4px;
        }
        QLabel#heroSubtitle {
            color: #A9BED6;
            font-size: 13px;
            font-weight: 500;
        }
        QLabel[badgeRole="chip"] {
            background-color: rgba(14, 37, 68, 0.95);
            color: #D8EEFF;
            border: 1px solid #2F6FA6;
            border-radius: 999px;
            padding: 7px 14px;
            font-size: 11px;
            font-weight: 700;
        }
        QFrame#toolbarCard,
        QFrame#apGroupSelectorFrame,
        QFrame#buyoutOptionsFrame,
        QFrame#ciscoFrame,
        QFrame#card1,
        QFrame#card4,
        QTabWidget#siteTabs,
        QFrame#outputPanel {
            background-color: rgba(10, 24, 43, 0.96);
            border: 1px solid #183252;
            border-radius: 18px;
        }
        QLabel#panelTitle {
            color: #F4FAFF;
            font-size: 15px;
            font-weight: 800;
        }
        QLabel#panelSubtitle {
            color: #91A8C4;
            font-size: 11px;
            font-weight: 500;
        }
        QLineEdit, QPlainTextEdit, QTreeWidget, QListWidget, QComboBox {
            background-color: #060D19;
            border: 1px solid #26486F;
            border-radius: 12px;
            color: #F9FAFB;
            padding: 8px 12px;
            font-family: 'Consolas', 'Segoe UI';
            font-size: 12px;
            selection-background-color: #1F6DB2;
        }
        QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
            border: 1px solid #62C8FF;
            background-color: #081425;
        }
        QComboBox QAbstractItemView {
            background-color: #081425;
            color: #F9FAFB;
            selection-background-color: #1F6DB2;
            border: 1px solid #26486F;
            outline: none;
            padding: 6px;
        }
        QPlainTextEdit#text_output {
            background-color: #050B14;
            border: 1px solid #24486F;
            border-radius: 16px;
            padding: 14px;
            selection-background-color: #1F6DB2;
        }
        QTreeWidget::item {
            padding: 5px 6px;
            margin: 2px 0;
            border-radius: 6px;
        }
        QTreeWidget::item:hover {
            background-color: rgba(56, 107, 164, 0.18);
        }
        QCheckBox {
            color: #D9E5F4;
            font-family: 'Segoe UI';
            font-size: 12px;
            font-weight: 600;
            spacing: 9px;
            background: transparent;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 5px;
            border: 2px solid #7BA8D1;
            background-color: #060D19;
        }
        QCheckBox::indicator:hover {
            border: 2px solid #62C8FF;
            background-color: #0E1E33;
        }
        QCheckBox::indicator:checked {
            background-color: #1F6DB2;
            border: 2px solid #62C8FF;
        }
        QPushButton#btn_wizard, QPushButton#btn_generate, QPushButton#btn_generate_cisco, QPushButton#btn_test_ssh, QPushButton#btn_open_mremote, QPushButton#btn_deploy, QPushButton#btn_update_app {
            background-color: #1F6DB2;
            color: #FFFFFF;
            font-weight: 800;
            border: 1px solid #4EA6E4;
            border-radius: 12px;
            padding: 10px 16px;
        }
        QPushButton#btn_wizard:hover, QPushButton#btn_generate:hover, QPushButton#btn_generate_cisco:hover, QPushButton#btn_test_ssh:hover, QPushButton#btn_open_mremote:hover, QPushButton#btn_deploy:hover, QPushButton#btn_update_app:hover {
            background-color: #2A84D5;
            border: 1px solid #71D0FF;
        }
        QPushButton#btn_deploy:disabled, QPushButton#btn_test_ssh:disabled, QPushButton#btn_open_mremote:disabled, QPushButton#btn_update_app:disabled {
            background-color: #22364E;
            color: #5D7895;
            border: 1px solid #2A415C;
        }
        QPushButton#btn_remove, QPushButton#btn_copy, QPushButton#btn_reset {
            background-color: #132942;
            color: #EAF5FF;
            font-weight: 700;
            border: 1px solid #2A4C74;
            border-radius: 12px;
            padding: 10px 16px;
        }
        QPushButton#btn_remove:hover { background-color: #B93B47; border: 1px solid #F77D86; }
        QPushButton#btn_copy:hover, QPushButton#btn_reset:hover {
            background-color: #1A3552;
            border: 1px solid #4E80AF;
        }
        QTabWidget::pane {
            border: 1px solid #224468;
            border-radius: 16px;
            background: rgba(6, 13, 25, 0.72);
            top: 0px;
        }
        QTabBar#modeSwitcher::tab {
            background-color: rgba(8, 20, 37, 0.95);
            color: #95ABC4;
            padding: 8px 18px;
            font-weight: 800;
            border: 1px solid #294B72;
            border-radius: 999px;
            margin-right: 8px;
            min-width: 88px;
        }
        QTabBar#modeSwitcher::tab:selected {
            background-color: #1F6DB2;
            color: #FFFFFF;
            border: 1px solid #62C8FF;
        }
        QTabBar#modeSwitcher::tab:hover:!selected {
            background-color: #112540;
            color: #E5F5FF;
        }
        QTabBar::tab {
            background-color: transparent;
            color: #9FB5CD;
            padding: 10px 20px;
            font-weight: 700;
            border-bottom: 2px solid transparent;
        }
        QTabBar::tab:selected {
            color: #F5FAFF;
            border-bottom: 2px solid #62C8FF;
        }
        QStatusBar {
            color: #8AD7FF;
            background-color: #050B14;
            border-top: 1px solid #17304D;
            font-weight: 700;
        }
        )";
    }

    return R"(
        QMainWindow, QWidget#centralWidget {
            background-color: #F3F7FD;
            border: 1px solid #D6E0ED;
        }
        #titleBar { background-color: #E8EEF7; border-bottom: 1px solid #C8D2E1; }
        #titleLabel { color: #005DAA; font-family: 'Segoe UI Variable', 'Segoe UI'; font-size: 13px; font-weight: 700; letter-spacing: 1.0px; padding-left: 10px; }
        #titleBar QPushButton { background-color: transparent; border: none; padding: 6px 14px; color: #4B5563; }
        #titleBar QPushButton:hover { background-color: #D6E3F5; color: #111827; }
        #btn_close:hover { background-color: #D64545; color: #FFFFFF; }
        QLabel {
            color: #31465F;
            font-family: 'Segoe UI Variable';
            font-size: 12px;
            font-weight: 600;
            background: transparent;
        }
        QFrame {
            background-color: #FFFFFF;
            border: 1px solid #D5DEEA;
            border-radius: 14px;
        }
        QFrame#heroCard {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 #FFFFFF, stop:0.52 #F5FAFF, stop:1 #E7F1FB);
            border: 1px solid #C3D7EC;
            border-radius: 22px;
        }
        QLabel#heroTitle {
            color: #15314F;
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 0.4px;
        }
        QLabel#heroSubtitle {
            color: #5D7187;
            font-size: 13px;
            font-weight: 500;
        }
        QLabel[badgeRole="chip"] {
            background-color: #EEF6FF;
            color: #13416E;
            border: 1px solid #C6DCF3;
            border-radius: 999px;
            padding: 7px 14px;
            font-size: 11px;
            font-weight: 700;
        }
        QFrame#toolbarCard,
        QFrame#apGroupSelectorFrame,
        QFrame#buyoutOptionsFrame,
        QFrame#ciscoFrame,
        QFrame#card1,
        QFrame#card4,
        QTabWidget#siteTabs,
        QFrame#outputPanel {
            background-color: #FFFFFF;
            border: 1px solid #D7E4F0;
            border-radius: 18px;
        }
        QLabel#panelTitle {
            color: #15314F;
            font-size: 15px;
            font-weight: 800;
        }
        QLabel#panelSubtitle {
            color: #697D92;
            font-size: 11px;
            font-weight: 500;
        }
        QLineEdit, QPlainTextEdit, QTreeWidget, QListWidget, QComboBox {
            background-color: #FFFFFF;
            border: 1px solid #C7D6E7;
            border-radius: 12px;
            color: #102033;
            padding: 8px 12px;
            font-family: 'Consolas', 'Segoe UI';
            font-size: 12px;
            selection-background-color: #CFE6FF;
        }
        QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
            border: 1px solid #2D85D3;
            background-color: #FBFDFF;
        }
        QComboBox QAbstractItemView {
            background-color: #FFFFFF;
            color: #111827;
            selection-background-color: #D6EAFB;
            border: 1px solid #C7D2E0;
            outline: none;
            padding: 6px;
        }
        QPlainTextEdit#text_output {
            background-color: #FBFDFF;
            border: 1px solid #C9DDEF;
            border-radius: 16px;
            padding: 14px;
        }
        QTreeWidget::item {
            padding: 5px 6px;
            margin: 2px 0;
            border-radius: 6px;
        }
        QTreeWidget::item:hover {
            background-color: #EDF5FD;
        }
        QCheckBox {
            color: #203244;
            font-family: 'Segoe UI';
            font-size: 12px;
            font-weight: 600;
            spacing: 9px;
            background: transparent;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 5px;
            border: 2px solid #7C8AA0;
            background-color: #FFFFFF;
        }
        QCheckBox::indicator:hover {
            border: 2px solid #0F6CBD;
            background-color: #F3F8FD;
        }
        QCheckBox::indicator:checked {
            background-color: #0F6CBD;
            border: 2px solid #0F6CBD;
        }
        QPushButton#btn_wizard, QPushButton#btn_generate, QPushButton#btn_generate_cisco, QPushButton#btn_test_ssh, QPushButton#btn_open_mremote, QPushButton#btn_deploy, QPushButton#btn_update_app {
            background-color: #1673C5;
            color: #FFFFFF;
            font-weight: 800;
            border: 1px solid #4D98DA;
            border-radius: 12px;
            padding: 10px 16px;
        }
        QPushButton#btn_wizard:hover, QPushButton#btn_generate:hover, QPushButton#btn_generate_cisco:hover, QPushButton#btn_test_ssh:hover, QPushButton#btn_open_mremote:hover, QPushButton#btn_deploy:hover, QPushButton#btn_update_app:hover {
            background-color: #0F64AE;
            border: 1px solid #2D85D3;
        }
        QPushButton#btn_deploy:disabled, QPushButton#btn_test_ssh:disabled, QPushButton#btn_open_mremote:disabled, QPushButton#btn_update_app:disabled {
            background-color: #DFE6EF;
            color: #7C8AA0;
            border: 1px solid #D1DAE5;
        }
        QPushButton#btn_remove, QPushButton#btn_copy, QPushButton#btn_reset {
            background-color: #F2F6FA;
            color: #203244;
            font-weight: 700;
            border: 1px solid #D5E1ED;
            border-radius: 12px;
            padding: 10px 16px;
        }
        QPushButton#btn_remove:hover { background-color: #FAD9DC; border: 1px solid #E5ABB2; }
        QPushButton#btn_copy:hover, QPushButton#btn_reset:hover {
            background-color: #EAF1F7;
            border: 1px solid #C1D2E4;
        }
        QTabWidget::pane {
            border: 1px solid #D5DEEA;
            border-radius: 16px;
            background: #FDFEFF;
            top: 0px;
        }
        QTabBar#modeSwitcher::tab {
            background-color: #FFFFFF;
            color: #4A5E72;
            padding: 8px 18px;
            font-weight: 800;
            border: 1px solid #D3E0EC;
            border-radius: 999px;
            margin-right: 8px;
            min-width: 88px;
        }
        QTabBar#modeSwitcher::tab:selected {
            background-color: #1673C5;
            color: #FFFFFF;
            border: 1px solid #2D85D3;
        }
        QTabBar#modeSwitcher::tab:hover:!selected {
            background-color: #EAF2FB;
            color: #0F172A;
        }
        QTabBar::tab {
            background-color: transparent;
            color: #53687D;
            padding: 10px 20px;
            font-weight: 700;
            border-bottom: 2px solid transparent;
        }
        QTabBar::tab:selected {
            color: #14304E;
            border-bottom: 2px solid #2D85D3;
        }
        QStatusBar {
            color: #0F6CBD;
            background-color: #EAF1F9;
            border-top: 1px solid #D3DDE8;
            font-weight: 700;
        }
    )";
}

// ====================================================
// TREE HELPER
// ====================================================

void addTreeCategory(QTreeWidget* tree, const QString& title,
    const QStringList& items, const QString& color)
{
    QTreeWidgetItem* header = new QTreeWidgetItem(tree);
    header->setText(0, title);
    header->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
    header->setFont(0, QFont("Segoe UI", 10, QFont::Bold));
    header->setForeground(0, QColor(color));

    for (const QString& name : items) {
        if (name.isEmpty()) continue;
        QTreeWidgetItem* item = new QTreeWidgetItem(header);
        item->setText(0, getCleanName(name));
        item->setData(0, Qt::UserRole, name);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsSelectable);
        item->setCheckState(0, Qt::Unchecked);
    }
}

// ====================================================
// SSH WORKER
// ====================================================

SshWorker::SshWorker(QString ip, QString user, QString pass,
    QString script, DeploymentOptions options, QObject* parent)
    : QThread(parent), targetIp(ip), username(user),
    password(pass), configScript(script), deployOptions(options) {}

void SshWorker::run() {
    emit updateLog(">>> Initializing SSH Connection to " + targetIp + "...");

    ssh_session session = ssh_new();
    if (!session) {
        emit updateLog(">>> ERROR: Failed to create SSH session.");
        emit deployFinished();
        return;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, targetIp.toStdString().c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, username.toStdString().c_str());
    const int sshPort = 22;
    const bool isCiscoDeploy = deployOptions.useCiscoShellLogin;
    const long sshTimeoutSeconds = isCiscoDeploy ? 60 : 10;
    const int promptTimeoutMs = isCiscoDeploy ? 20000 : 10000;
    ssh_options_set(session, SSH_OPTIONS_PORT, &sshPort);
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &sshTimeoutSeconds);

    if (isCiscoDeploy) {
        const char* preferredHostKeys = "ssh-rsa,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256";
        const char* preferredKex = "diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group1-sha1,ecdh-sha2-nistp256,curve25519-sha256";
        const char* preferredCiphers = "aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-cbc";
        const char* preferredHmacs = "hmac-sha1,hmac-sha2-256,hmac-sha2-512";

        ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, preferredHostKeys);
        ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, preferredKex);
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, preferredCiphers);
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, preferredCiphers);
        ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, preferredHmacs);
        ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, preferredHmacs);

        emit updateLog(">>> Cisco SSH compatibility mode enabled (port 22, legacy ciphers/kex allowed).");
        emit updateLog(">>> Cisco SSH connect timeout set to 60 seconds.");
    }

    emit updateLog(">>> Stage: opening SSH transport...");
    if (ssh_connect(session) != SSH_OK) {
        emit updateLog(">>> ERROR: SSH transport failed before authentication: " + QString(ssh_get_error(session)));
        ssh_free(session);
        emit deployFinished();
        return;
    }

    emit updateLog(">>> Stage: SSH transport established.");
    emit updateLog(">>> Stage: authenticating...");
    int rc = ssh_userauth_password(session, nullptr, password.toStdString().c_str());

    if (rc != SSH_AUTH_SUCCESS) {
        emit updateLog(">>> ERROR: Authentication failed: " + QString(ssh_get_error(session)));
        password.fill('0');
        password.clear();
        ssh_disconnect(session);
        ssh_free(session);
        emit deployFinished();
        return;
    }

    emit updateLog(">>> Stage: authentication successful. Opening shell...");

    ssh_channel channel = ssh_channel_new(session);
    if (!channel || ssh_channel_open_session(channel) != SSH_OK) {
        emit updateLog(">>> ERROR: Failed to open channel.");
        ssh_disconnect(session);
        ssh_free(session);
        emit deployFinished();
        return;
    }

    ssh_channel_request_pty(channel);
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        emit updateLog(">>> ERROR: Failed to request shell.");
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        emit deployFinished();
        return;
    }

    emit updateLog(">>> Stage: interactive shell ready.");

    char readBuf[4096];
    auto drainShellOutput = [&](int timeoutMs, QString* combinedOutput = nullptr) {
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            bool receivedData = false;
            int n = 0;
            while ((n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0)) > 0) {
                readBuf[n] = '\0';
                const QString chunk = QString::fromLocal8Bit(readBuf, n);
                emit updateLog(chunk);
                if (combinedOutput)
                    combinedOutput->append(chunk);
                receivedData = true;
            }
            if (!receivedData)
                QThread::msleep(100);
        }
    };
    auto waitForPrompt = [&](const QStringList& prompts, int timeoutMs, QString* combinedOutput = nullptr, const QString& stageLabel = QString()) {
        QString collected = combinedOutput ? *combinedOutput : QString();
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            int n = 0;
            bool receivedData = false;
            while ((n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0)) > 0) {
                readBuf[n] = '\0';
                const QString chunk = QString::fromLocal8Bit(readBuf, n);
                emit updateLog(chunk);
                collected.append(chunk);
                receivedData = true;
            }

            const QString lowered = collected.toLower();
            for (const QString& prompt : prompts) {
                if (lowered.contains(prompt.toLower())) {
                    if (combinedOutput)
                        *combinedOutput = collected;
                    return true;
                }
            }

            if (!receivedData)
                QThread::msleep(100);
        }

        if (combinedOutput)
            *combinedOutput = collected;
        if (!stageLabel.isEmpty()) {
            QString snippet = collected.simplified();
            if (snippet.length() > 220)
                snippet = snippet.left(220) + "...";
            if (snippet.isEmpty())
                snippet = "(no controller output received)";
            emit updateLog(">>> ERROR: Timed out during " + stageLabel + " after " + QString::number(timeoutMs / 1000.0, 'f', 0) + " seconds. Last output: " + snippet);
        }
        return false;
    };
    auto writeShellLine = [&](const QString& line) {
        const QByteArray payload = (line + "\n").toUtf8();
        ssh_channel_write(channel, payload.constData(), static_cast<uint32_t>(payload.size()));
    };
    auto drainUntilQuiet = [&](int quietWindowMs, int maxWaitMs) {
        QElapsedTimer totalTimer;
        QElapsedTimer quietTimer;
        totalTimer.start();
        quietTimer.start();

        while (totalTimer.elapsed() < maxWaitMs) {
            bool receivedData = false;
            int n = 0;
            while ((n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0)) > 0) {
                readBuf[n] = '\0';
                emit updateLog(QString::fromLocal8Bit(readBuf, n));
                receivedData = true;
            }

            if (receivedData) {
                quietTimer.restart();
            }
            else if (quietTimer.elapsed() >= quietWindowMs) {
                return true;
            }

            QThread::msleep(100);
        }

        return false;
    };

    if (deployOptions.sendInitialEnter) {
        const QByteArray initialEnter("\n");
        ssh_channel_write(channel, initialEnter.constData(),
            static_cast<uint32_t>(initialEnter.size()));
        drainShellOutput(400);
    }

    if (deployOptions.useCiscoShellLogin) {
        emit updateLog(">>> Cisco shell login: waiting for controller prompts...");
        auto waitForCiscoPrompt = [&](const QStringList& prompts, const QString& stageLabel, QString* transcript) {
            if (waitForPrompt(prompts, promptTimeoutMs, transcript, stageLabel))
                return true;

            emit updateLog(">>> Cisco shell login: no prompt detected, sending another Enter...");
            writeShellLine(QString());
            if (waitForPrompt(prompts, promptTimeoutMs, transcript, stageLabel + " retry"))
                return true;

            emit updateLog(">>> Cisco shell login: still waiting, sending one final Enter...");
            writeShellLine(QString());
            return waitForPrompt(prompts, promptTimeoutMs, transcript, stageLabel + " final retry");
        };

        QString loginTranscript;
        if (!waitForCiscoPrompt({ "login as:", "please enter the user", "user:", "password:", ">", "#" }, "initial Cisco controller prompt", &loginTranscript)) {
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            emit deployFinished();
            return;
        }
        QString loweredTranscript = loginTranscript.toLower();

        if (loweredTranscript.contains("login as:")) {
            emit updateLog(">>> Cisco shell login: sending blank login name...");
            writeShellLine(QString());
            loginTranscript.clear();
            if (!waitForCiscoPrompt({ "please enter the user", "user:", "password:", ">", "#" }, "blank login name handoff", &loginTranscript)) {
                ssh_channel_send_eof(channel);
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                ssh_disconnect(session);
                ssh_free(session);
                emit deployFinished();
                return;
            }
            loweredTranscript = loginTranscript.toLower();
        }

        if (loweredTranscript.contains("user:")) {
            emit updateLog(">>> Cisco shell login: sending username...");
            writeShellLine(username);
            loginTranscript.clear();
            if (!waitForCiscoPrompt({ "password:", "user:", ">", "#" }, "username submission", &loginTranscript)) {
                ssh_channel_send_eof(channel);
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                ssh_disconnect(session);
                ssh_free(session);
                emit deployFinished();
                return;
            }
            loweredTranscript = loginTranscript.toLower();
            if (loweredTranscript.contains("user:")) {
                emit updateLog(">>> Cisco shell login: controller repeated user prompt, sending username again...");
                writeShellLine(username);
                loginTranscript.clear();
                if (!waitForCiscoPrompt({ "password:", ">", "#" }, "username resubmission", &loginTranscript)) {
                    ssh_channel_send_eof(channel);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    ssh_disconnect(session);
                    ssh_free(session);
                    emit deployFinished();
                    return;
                }
                loweredTranscript = loginTranscript.toLower();
            }
        }

        if (loweredTranscript.contains("password:")) {
            emit updateLog(">>> Cisco shell login: sending password...");
            writeShellLine(password);
            loginTranscript.clear();
            if (!waitForPrompt({ ">", "#", "save config", "config wlan" }, promptTimeoutMs, &loginTranscript, "password submission")) {
                ssh_channel_send_eof(channel);
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                ssh_disconnect(session);
                ssh_free(session);
                emit deployFinished();
                return;
            }
        }

        emit updateLog(">>> Cisco shell login: controller prompt confirmed.");
        drainShellOutput(1200);
    }

    // FIX (Security): Wipe the password from memory after any shell-level login steps.
    password.fill('0');
    password.clear();

    if (deployOptions.testOnly) {
        emit updateLog(">>> SUCCESS: SSH connectivity test completed. Controller accepted the session and shell access is ready.");
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        emit deployFinished();
        return;
    }

    emit updateLog(">>> Pushing configuration to controller...\n");

    // FIX (C++ Code): Send one command at a time instead of one giant write
    // followed by a hardcoded 4-second sleep. The Aruba shell can drop or
    // interleave lines when fed the entire script at once.
    QString cleanScript = configScript;
    cleanScript.replace("\r\n", "\n");
    QStringList lines = cleanScript.split('\n', Qt::SkipEmptyParts);

    for (const QString& line : lines) {
        const QByteArray payload = (line + "\n").toUtf8();
        if (ssh_channel_write(channel, payload.constData(),
            static_cast<uint32_t>(payload.size())) == SSH_ERROR) {
            emit updateLog(">>> ERROR: Failed while sending command: " + line);
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            emit deployFinished();
            return;
        }

        // Wait for the controller to go quiet before sending the next line.
        drainUntilQuiet(250, 2000);
    }

    // Final drain after the last command: only report completion once the
    // controller has been quiet for a moment or the safety timeout expires.
    if (!drainUntilQuiet(1200, 10000)) {
        emit updateLog(">>> WARNING: Controller output did not go quiet before the final timeout. Review the last response carefully.");
    }

    emit updateLog("\n>>> DEPLOYMENT COMPLETE. Disconnecting...");

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    emit deployFinished();
}

ControllerSessionManager::ControllerSessionManager(QObject* parent)
    : QObject(parent) {}

ControllerSessionManager::~ControllerSessionManager() {
    closeSession();
}

void ControllerSessionManager::closeSession() {
    if (channel) {
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        channel = nullptr;
    }
    if (session) {
        ssh_disconnect(session);
        ssh_free(session);
        session = nullptr;
    }
    connected = false;
    currentIp.clear();
    currentUser.clear();
}

void ControllerSessionManager::disconnectPersistent() {
    if (connected)
        emit logMessage(">>> Controller session disconnected.");
    closeSession();
    emit connectionStateChanged(false, currentCiscoMode, QString(), QString());
}

void ControllerSessionManager::connectPersistent(QString ip, QString user, QString pass, bool isCiscoMode) {
    if (connected && currentIp == ip && currentUser == user && currentCiscoMode == isCiscoMode) {
        emit connectFinished(true, (isCiscoMode ? "Cisco" : "Aruba") + QString(" controller session is already connected."));
        emit connectionStateChanged(true, currentCiscoMode, currentIp, currentUser);
        return;
    }

    closeSession();

    const QString controllerLabel = isCiscoMode ? "Cisco" : "Aruba";
    emit logMessage(">>> Connecting persistent " + controllerLabel + " session to " + ip + "...");

    session = ssh_new();
    if (!session) {
        emit connectFinished(false, "Failed to create " + controllerLabel + " SSH session.");
        emit connectionStateChanged(false, isCiscoMode, QString(), QString());
        return;
    }

    const int sshPort = 22;
    const long sshTimeoutSeconds = 60;
    ssh_options_set(session, SSH_OPTIONS_HOST, ip.toStdString().c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, user.toStdString().c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, &sshPort);
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &sshTimeoutSeconds);

    if (isCiscoMode) {
        const char* preferredHostKeys = "ssh-rsa,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256";
        const char* preferredKex = "diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group1-sha1,ecdh-sha2-nistp256,curve25519-sha256";
        const char* preferredCiphers = "aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-cbc";
        const char* preferredHmacs = "hmac-sha1,hmac-sha2-256,hmac-sha2-512";
        ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, preferredHostKeys);
        ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, preferredKex);
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, preferredCiphers);
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, preferredCiphers);
        ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, preferredHmacs);
        ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, preferredHmacs);
    }

    if (ssh_connect(session) != SSH_OK) {
        const QString error = controllerLabel + " SSH transport failed before authentication: " + QString(ssh_get_error(session));
        closeSession();
        emit connectFinished(false, error);
        emit connectionStateChanged(false, isCiscoMode, QString(), QString());
        return;
    }

    if (ssh_userauth_password(session, nullptr, pass.toStdString().c_str()) != SSH_AUTH_SUCCESS) {
        const QString error = controllerLabel + " authentication failed: " + QString(ssh_get_error(session));
        closeSession();
        emit connectFinished(false, error);
        emit connectionStateChanged(false, isCiscoMode, QString(), QString());
        return;
    }

    channel = ssh_channel_new(session);
    if (!channel || ssh_channel_open_session(channel) != SSH_OK) {
        const QString error = controllerLabel + " session failed to open a shell channel.";
        closeSession();
        emit connectFinished(false, error);
        emit connectionStateChanged(false, isCiscoMode, QString(), QString());
        return;
    }

    ssh_channel_request_pty(channel);
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        const QString error = controllerLabel + " session failed to request shell access.";
        closeSession();
        emit connectFinished(false, error);
        emit connectionStateChanged(false, isCiscoMode, QString(), QString());
        return;
    }

    char readBuf[4096];
    auto readNonBlocking = [&](QString* collected) {
        bool receivedData = false;
        int n = 0;
        while ((n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0)) > 0) {
            readBuf[n] = '\0';
            const QString chunk = QString::fromLocal8Bit(readBuf, n);
            emit logMessage(chunk);
            if (collected)
                collected->append(chunk);
            receivedData = true;
        }
        return receivedData;
    };
    auto waitForPrompt = [&](const QStringList& prompts, int timeoutMs, QString* transcript, const QString& stageLabel) {
        QString collected = transcript ? *transcript : QString();
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            const bool receivedData = readNonBlocking(&collected);
            const QString lowered = collected.toLower();
            for (const QString& prompt : prompts) {
                if (lowered.contains(prompt.toLower())) {
                    if (transcript)
                        *transcript = collected;
                    return true;
                }
            }
            if (!receivedData)
                QThread::msleep(100);
        }

        QString snippet = collected.simplified();
        if (snippet.length() > 220)
            snippet = snippet.left(220) + "...";
        if (snippet.isEmpty())
            snippet = "(no controller output received)";
        emit connectFinished(false, controllerLabel + " session timed out during " + stageLabel + ". Last output: " + snippet);
        return false;
    };
    auto writeShellLine = [&](const QString& line) {
        const QByteArray payload = (line + "\n").toUtf8();
        ssh_channel_write(channel, payload.constData(), static_cast<uint32_t>(payload.size()));
    };

    if (isCiscoMode) {
        const QByteArray initialEnter("\n");
        ssh_channel_write(channel, initialEnter.constData(), static_cast<uint32_t>(initialEnter.size()));
        QThread::msleep(300);
        auto waitForCiscoPrompt = [&](const QStringList& prompts, const QString& stageLabel, QString* transcript) {
            if (waitForPrompt(prompts, 20000, transcript, stageLabel))
                return true;

            emit logMessage(">>> Cisco persistent session: no prompt detected, sending another Enter...");
            writeShellLine(QString());
            if (waitForPrompt(prompts, 20000, transcript, stageLabel + " retry"))
                return true;

            emit logMessage(">>> Cisco persistent session: still waiting, sending one final Enter...");
            writeShellLine(QString());
            return waitForPrompt(prompts, 20000, transcript, stageLabel + " final retry");
        };
        QString transcript;
        if (!waitForCiscoPrompt({ "login as:", "please enter the user", "user:", "password:", ">", "#" }, "initial Cisco controller prompt", &transcript)) {
            closeSession();
            emit connectionStateChanged(false, isCiscoMode, QString(), QString());
            return;
        }

        QString loweredTranscript = transcript.toLower();
        if (loweredTranscript.contains("login as:")) {
            emit logMessage(">>> Cisco persistent session: sending blank login name...");
            writeShellLine(QString());
            transcript.clear();
            if (!waitForCiscoPrompt({ "please enter the user", "user:", "password:", ">", "#" }, "blank login name handoff", &transcript)) {
                closeSession();
                emit connectionStateChanged(false, isCiscoMode, QString(), QString());
                return;
            }
            loweredTranscript = transcript.toLower();
        }

        if (loweredTranscript.contains("user:")) {
            emit logMessage(">>> Cisco persistent session: sending username...");
            writeShellLine(user);
            transcript.clear();
            if (!waitForCiscoPrompt({ "password:", "user:", ">", "#" }, "username submission", &transcript)) {
                closeSession();
                emit connectionStateChanged(false, isCiscoMode, QString(), QString());
                return;
            }
            loweredTranscript = transcript.toLower();
            if (loweredTranscript.contains("user:")) {
                emit logMessage(">>> Cisco persistent session: controller repeated user prompt, sending username again...");
                writeShellLine(user);
                transcript.clear();
                if (!waitForCiscoPrompt({ "password:", ">", "#" }, "username resubmission", &transcript)) {
                    closeSession();
                    emit connectionStateChanged(false, isCiscoMode, QString(), QString());
                    return;
                }
                loweredTranscript = transcript.toLower();
            }
        }

        if (loweredTranscript.contains("password:")) {
            emit logMessage(">>> Cisco persistent session: sending password...");
            writeShellLine(pass);
            transcript.clear();
            if (!waitForPrompt({ ">", "#", "save config", "config wlan" }, 20000, &transcript, "password submission")) {
                closeSession();
                emit connectionStateChanged(false, isCiscoMode, QString(), QString());
                return;
            }
        }
    }

    connected = true;
    currentCiscoMode = isCiscoMode;
    currentIp = ip;
    currentUser = user;
    currentPassword = pass;
    emit logMessage(">>> SUCCESS: " + controllerLabel + " controller session is connected and ready to reuse.");
    emit connectionStateChanged(true, isCiscoMode, currentIp, currentUser);
    emit connectFinished(true, controllerLabel + " controller session is connected.");
}

void ControllerSessionManager::deployPersistent(QString script) {
    deployPersistentInternal(script, true);
}

void ControllerSessionManager::deployPersistentInternal(QString script, bool allowReconnect) {
    auto reconnectAndRetry = [&]() -> bool {
        if (!allowReconnect || currentIp.trimmed().isEmpty() || currentUser.trimmed().isEmpty() || currentPassword.isEmpty())
            return false;

        const QString reconnectIp = currentIp;
        const QString reconnectUser = currentUser;
        const QString reconnectPassword = currentPassword;
        const bool reconnectCiscoMode = currentCiscoMode;
        const QString controllerLabel = reconnectCiscoMode ? "Cisco" : "Aruba";

        emit logMessage(">>> " + controllerLabel + " session is stale. Reconnecting and retrying deployment...");
        closeSession();
        emit connectionStateChanged(false, reconnectCiscoMode, QString(), QString());
        connectPersistent(reconnectIp, reconnectUser, reconnectPassword, reconnectCiscoMode);
        if (!connected || currentIp != reconnectIp || currentUser != reconnectUser || currentCiscoMode != reconnectCiscoMode)
            return false;

        emit logMessage(">>> " + controllerLabel + " session restored. Retrying deployment on the active session...");
        deployPersistentInternal(script, false);
        return true;
    };

    if (!connected || !session || !channel || !ssh_channel_is_open(channel) || ssh_channel_is_eof(channel)) {
        emit deployFinished(false, "No active controller session is available. Click CONNECT first.");
        return;
    }

    const QString controllerLabel = currentCiscoMode ? "Cisco" : "Aruba";
    emit logMessage(">>> Reusing active " + controllerLabel + " session for deployment...");

    char readBuf[4096];
    QString cleanScript = script;
    cleanScript.replace("\r\n", "\n");
    const QStringList lines = cleanScript.split('\n', Qt::SkipEmptyParts);
    for (const QString& line : lines) {
        const QByteArray payload = (line + "\n").toUtf8();
        if (ssh_channel_write(channel, payload.constData(), static_cast<uint32_t>(payload.size())) == SSH_ERROR) {
            if (reconnectAndRetry())
                return;

            closeSession();
            emit connectionStateChanged(false, currentCiscoMode, QString(), QString());
            emit deployFinished(false, controllerLabel + " session write failed. Please reconnect.");
            return;
        }

        QThread::msleep(150);
        int n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0);
        if (n > 0) {
            readBuf[n] = '\0';
            emit logMessage(QString::fromLocal8Bit(readBuf, n));
        }
    }

    QThread::msleep(500);
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < 1500) {
        bool receivedData = false;
        int n = 0;
        while ((n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0)) > 0) {
            readBuf[n] = '\0';
            emit logMessage(QString::fromLocal8Bit(readBuf, n));
            receivedData = true;
        }
        if (!receivedData)
            QThread::msleep(100);
    }

    if (!ssh_channel_is_open(channel) || ssh_channel_is_eof(channel)) {
        const QString reconnectIp = currentIp;
        const QString reconnectUser = currentUser;
        const QString reconnectPassword = currentPassword;
        const bool reconnectCiscoMode = currentCiscoMode;

        emit logMessage(">>> " + controllerLabel + " shell closed after deployment. Reconnecting persistent session...");
        connectPersistent(reconnectIp, reconnectUser, reconnectPassword, reconnectCiscoMode);

        if (connected && currentIp == reconnectIp && currentUser == reconnectUser && currentCiscoMode == reconnectCiscoMode) {
            emit logMessage(">>> " + controllerLabel + " session restored after deployment.");
            emit deployFinished(true, controllerLabel + " deployment complete. Session reconnected and ready.");
            return;
        }

        emit deployFinished(false, controllerLabel + " deployment completed, but the session could not be restored automatically.");
        return;
    }

    emit logMessage(">>> " + controllerLabel + " deployment finished on active session.");
    emit deployFinished(true, controllerLabel + " deployment complete on active session.");
}

void ControllerSessionManager::checkWlanIdsPersistent() {
    checkWlanIdsPersistentInternal(true);
}

void ControllerSessionManager::checkWlanIdsPersistentInternal(bool allowReconnect) {
    auto reconnectAndRetry = [&]() -> bool {
        if (!allowReconnect || !currentCiscoMode || currentIp.trimmed().isEmpty() || currentUser.trimmed().isEmpty() || currentPassword.isEmpty())
            return false;

        const QString reconnectIp = currentIp;
        const QString reconnectUser = currentUser;
        const QString reconnectPassword = currentPassword;
        const bool reconnectCiscoMode = currentCiscoMode;

        emit logMessage(">>> Cisco session dropped during WLAN ID check. Attempting automatic reconnect...");
        closeSession();
        emit connectionStateChanged(false, reconnectCiscoMode, QString(), QString());
        connectPersistent(reconnectIp, reconnectUser, reconnectPassword, reconnectCiscoMode);
        if (!connected || !currentCiscoMode)
            return false;

        emit logMessage(">>> Cisco session restored. Retrying WLAN ID check...");
        checkWlanIdsPersistentInternal(false);
        return true;
        };

    if (!connected || !session || !channel || !ssh_channel_is_open(channel) || ssh_channel_is_eof(channel)) {
        if (reconnectAndRetry())
            return;

        emit wlanIdCheckFinished(false, "No active Cisco session is available. Connect first.", QString());
        return;
    }

    if (!currentCiscoMode) {
        emit wlanIdCheckFinished(false, "WLAN ID checks are only available for the Cisco controller session.", QString());
        return;
    }

    auto writeShellLine = [&](const QString& line) {
        const QByteArray payload = (line + "\n").toUtf8();
        return ssh_channel_write(channel, payload.constData(), static_cast<uint32_t>(payload.size()));
    };
    auto sendPagerContinue = [&]() {
        const char space = ' ';
        return ssh_channel_write(channel, &space, 1);
    };

    emit logMessage(">>> Disabling Cisco paging for WLAN ID check...");
    if (writeShellLine("config paging disable") != SSH_ERROR)
        QThread::msleep(250);

    emit logMessage(">>> Running 'show wlan summary' on active Cisco session...");
    if (writeShellLine("show wlan summary") == SSH_ERROR) {
        if (reconnectAndRetry())
            return;

        closeSession();
        emit connectionStateChanged(false, currentCiscoMode, QString(), QString());
        emit wlanIdCheckFinished(false, "Failed to send 'show wlan summary' to the Cisco controller. Please reconnect.", QString());
        return;
    }

    char readBuf[4096];
    QString transcript;
    QElapsedTimer totalTimer;
    QElapsedTimer quietTimer;
    totalTimer.start();
    quietTimer.start();

    while (totalTimer.elapsed() < 12000) {
        bool receivedData = false;
        int n = 0;
        while ((n = ssh_channel_read_nonblocking(channel, readBuf, sizeof(readBuf) - 1, 0)) > 0) {
            readBuf[n] = '\0';
            QString chunk = QString::fromLocal8Bit(readBuf, n);

            while (chunk.contains("--More--", Qt::CaseInsensitive) || chunk.contains("(q)uit", Qt::CaseInsensitive)) {
                chunk.replace("--More-- or (q)uit", "", Qt::CaseInsensitive);
                chunk.replace("--More--", "", Qt::CaseInsensitive);
                chunk.replace("(q)uit", "", Qt::CaseInsensitive);
                if (sendPagerContinue() == SSH_ERROR) {
                    if (reconnectAndRetry())
                        return;

                    closeSession();
                    emit connectionStateChanged(false, currentCiscoMode, QString(), QString());
                    emit wlanIdCheckFinished(false, "Cisco paging prompt appeared, but the app could not continue reading. Please reconnect.", QString());
                    return;
                }
                emit logMessage(">>> Cisco pager detected. Continuing output...");
            }

            transcript.append(chunk);
            emit logMessage(chunk);
            receivedData = true;
        }

        if (receivedData) {
            quietTimer.restart();
        }
        else if (quietTimer.elapsed() >= 1200 && !sanitizeCiscoWlanSummaryTranscript(transcript).isEmpty()) {
            break;
        }

        QThread::msleep(100);
    }

    if (sanitizeCiscoWlanSummaryTranscript(transcript).isEmpty()) {
        emit wlanIdCheckFinished(false, "No WLAN summary was returned from 'show wlan summary'.", QString());
        return;
    }

    emit wlanIdCheckFinished(true, "Cisco WLAN ID summary retrieved.", summarizeCiscoWlanIds(transcript));
}

// ====================================================
// WIZARD — PAGE 1: Network Basics
// ====================================================

WizardPage1::WizardPage1(QWidget* parent) : QWizardPage(parent) {
    setTitle("Step 1: Network Basics");
    QVBoxLayout* l = new QVBoxLayout(this);
    QLineEdit* le = new QLineEdit(this);
    registerField("ssid*", le);
    l->addWidget(new QLabel("Broadcast SSID:"));
    l->addWidget(le);
    setLayout(l);
}

// ====================================================
// WIZARD — PAGE 2: Security & Networking
// ====================================================

WizardPage2::WizardPage2(QWidget* parent) : QWizardPage(parent) {
    setTitle("Step 2: Security & Networking");
    QVBoxLayout* l = new QVBoxLayout(this);
    QComboBox* cb = new QComboBox(this);
    cb->addItems({ "WPA2-PSK", "Open" });
    QLineEdit* lp = new QLineEdit(this);
    lp->setEchoMode(QLineEdit::Password);   // mask PSK in wizard too
    QLineEdit* lv = new QLineEdit(this);
    QCheckBox* splashPage = new QCheckBox("This WLAN uses a splash page (no password required)", this);
    registerField("auth", cb, "currentText");
    registerField("psk", lp);
    registerField("vlan*", lv);
    registerField("splash_page_aruba", splashPage, "checked");
    l->addWidget(new QLabel("Auth Type:"));   l->addWidget(cb);
    l->addWidget(new QLabel("PSK:"));         l->addWidget(lp);
    l->addWidget(new QLabel("VLAN:"));        l->addWidget(lv);
    l->addWidget(splashPage);

    connect(splashPage, &QCheckBox::toggled, this, [cb, lp](bool checked) {
        cb->setCurrentText(checked ? "Open" : "WPA2-PSK");
        cb->setEnabled(!checked);
        lp->setEnabled(!checked);
        if (checked)
            lp->clear();
    });
    setLayout(l);
}

// ====================================================
// WIZARD — PAGE SITE: Property Selection
// ====================================================

WizardPageSite::WizardPageSite(QWidget* parent) : QWizardPage(parent) {
    setTitle("Step 3: Property Selection");
    QVBoxLayout* l = new QVBoxLayout(this);
    QComboBox* cb = new QComboBox(this);
    cb->addItems({ "Wynn & Encore", "Stations Casinos" });
    registerField("site", cb, "currentIndex");
    l->addWidget(new QLabel("Select Property:"));
    l->addWidget(cb);
    setLayout(l);
}

// ====================================================
// CISCO WIZARD - CONNECTION PAGE
// ====================================================

CiscoConnectWizardPage::CiscoConnectWizardPage(ACS_Wynn_Builder* owner, QString title, QWidget* parent)
    : QWizardPage(parent), wizardOwner(owner), pageTitle(std::move(title))
{
    setTitle(pageTitle);

    QVBoxLayout* layout = new QVBoxLayout(this);
    ipField = new QLineEdit(this);
    userField = new QLineEdit(this);
    passField = new QLineEdit(this);
    passField->setEchoMode(QLineEdit::Password);
    statusLabel = new QLabel(this);
    statusLabel->setWordWrap(true);
    connectButton = new QPushButton("CONNECT", this);

    registerField("ip*", ipField);
    registerField("user*", userField);
    registerField("pass*", passField);

    layout->addWidget(new QLabel("Controller IP:", this));
    layout->addWidget(ipField);
    layout->addWidget(new QLabel("Username:", this));
    layout->addWidget(userField);
    layout->addWidget(new QLabel("Password:", this));
    layout->addWidget(passField);
    layout->addWidget(connectButton, 0, Qt::AlignLeft);
    layout->addWidget(statusLabel);
    layout->addStretch(1);

    connect(connectButton, &QPushButton::clicked, this, [this]() {
        if (!wizardOwner || wizardOwner->hasActiveCiscoSession())
            return;

        wizardOwner->setCiscoSessionCredentials(
            ipField ? ipField->text().trimmed() : QString(),
            userField ? userField->text().trimmed() : QString(),
            passField ? passField->text() : QString()
        );
        QMetaObject::invokeMethod(wizardOwner, "on_btn_test_ssh_clicked", Qt::DirectConnection);
        refreshState();
        });

    if (wizardOwner) {
        connect(wizardOwner, &ACS_Wynn_Builder::ciscoSessionStateChanged, this, [this]() {
            refreshState();
            emit completeChanged();
            });
        connect(wizardOwner, &ACS_Wynn_Builder::ciscoSuggestedWlanIdChanged, this, [this](const QString& wlanId) {
            if (wizard())
                wizard()->setField("cisco_wlan_id", wlanId);
        });
    }
}

void CiscoConnectWizardPage::initializePage() {
    if (!wizardOwner)
        return;

    const QString activeIp = wizardOwner->activeCiscoSessionIp();
    ipField->setText(activeIp.isEmpty() ? wizardOwner->defaultCiscoControllerIp() : activeIp);
    userField->setText(wizardOwner->activeCiscoSessionUser());
    refreshState();
}

bool CiscoConnectWizardPage::isComplete() const {
    return wizardOwner && wizardOwner->hasActiveCiscoSession();
}

void CiscoConnectWizardPage::refreshState() {
    const bool connected = wizardOwner && wizardOwner->hasActiveCiscoSession();
    if (statusLabel) {
        statusLabel->setText(connected
            ? QString("Cisco controller connected to %1 as %2. Continue to the WLAN form.")
            .arg(wizardOwner->activeCiscoSessionIp(),
                wizardOwner->activeCiscoSessionUser().isEmpty() ? QString("<unknown user>") : wizardOwner->activeCiscoSessionUser())
            : "Connect to the Cisco controller before continuing.");
    }
    if (connectButton) {
        connectButton->setText(connected ? "CONNECTED" : "CONNECT");
        connectButton->setEnabled(!connected);
    }
}

// ====================================================
// CISCO WIZARD — PAGE 1: WLAN DETAILS
// ====================================================

CiscoWizardPage1::CiscoWizardPage1(const QStringList& interfaces, QString title, QWidget* parent) : QWizardPage(parent) {
    setTitle(title);

    QGridLayout* layout = new QGridLayout(this);
    int row = 0;

    QLineEdit* company = new QLineEdit(this);
    QLineEdit* removal = new QLineEdit(this);
    QLineEdit* ssid = new QLineEdit(this);
    QLineEdit* password = new QLineEdit(this);
    password->setEchoMode(QLineEdit::Password);
    QLineEdit* wlanId = new QLineEdit(this);
    wlanId->setValidator(new QIntValidator(1, 512, this));
    QLineEdit* maxClients = new QLineEdit(this);
    maxClients->setValidator(new QIntValidator(1, 5000, this));
    maxClients->setText("10");

    QComboBox* vlan = new QComboBox(this);
    vlan->setEditable(true);
    vlan->setMinimumContentsLength(14);
    vlan->setInsertPolicy(QComboBox::NoInsert);
    for (const QString& interfaceName : interfaces)
        vlan->addItem(formatCiscoInterfaceLabel(interfaceName), interfaceName);
    if (vlan->lineEdit())
        vlan->lineEdit()->setPlaceholderText("Select Interface or VLAN");

    QCheckBox* splashPage = new QCheckBox("This WLAN uses a splash page (no password required)", this);

    registerField("cisco_company*", company);
    registerField("cisco_removal*", removal);
    registerField("cisco_ssid*", ssid);
    registerField("cisco_psk*", password);
    registerField("cisco_wlan_id*", wlanId);
    registerField("cisco_max_clients*", maxClients);
    registerField("cisco_vlan*", vlan, "currentText");
    registerField("cisco_splash_page", splashPage, "checked");

    layout->addWidget(new QLabel("Company Name:"), row, 0);
    layout->addWidget(company, row++, 1);
    layout->addWidget(new QLabel("Removal Date:"), row, 0);
    layout->addWidget(removal, row++, 1);
    layout->addWidget(new QLabel("Broadcast SSID:"), row, 0);
    layout->addWidget(ssid, row++, 1);
    layout->addWidget(new QLabel("Password:"), row, 0);
    layout->addWidget(password, row++, 1);
    layout->addWidget(splashPage, row++, 0, 1, 2);
    layout->addWidget(new QLabel("WLAN ID:"), row, 0);
    layout->addWidget(wlanId, row++, 1);
    layout->addWidget(new QLabel("Max Clients:"), row, 0);
    layout->addWidget(maxClients, row++, 1);
    layout->addWidget(new QLabel("Interface / VLAN:"), row, 0);
    layout->addWidget(vlan, row++, 1);

    connect(splashPage, &QCheckBox::toggled, this, [password](bool checked) {
        password->setEnabled(!checked);
        if (checked)
            password->clear();
    });
}

// ====================================================
// CISCO WIZARD — PAGE 2: AP GROUP SELECTION
// ====================================================

CiscoWizardPage2::CiscoWizardPage2(ApGroupData data, QString title, QWidget* parent)
    : QWizardPage(parent), apData(std::move(data))
{
    setTitle(title);

    QVBoxLayout* layout = new QVBoxLayout(this);
    QGridLayout* bulkLayout = new QGridLayout();

    chkLegacy = new QCheckBox("Legacy Buyout", this);
    chkEncore = new QCheckBox("Encore Buyout", this);
    chkExpansion = new QCheckBox("Expansion Buyout", this);
    bulkLayout->addWidget(chkLegacy, 0, 0);
    bulkLayout->addWidget(chkEncore, 0, 1);
    bulkLayout->addWidget(chkExpansion, 1, 0);
    layout->addLayout(bulkLayout);

    searchBox = new QLineEdit(this);
    searchBox->setPlaceholderText("Search Cisco AP Groups...");
    layout->addWidget(searchBox);

    apTreeWidget = new QTreeWidget(this);
    apTreeWidget->setHeaderHidden(true);
    layout->addWidget(apTreeWidget);

    connect(searchBox, &QLineEdit::textChanged, [this](const QString& text) {
        for (int i = 0; i < apTreeWidget->topLevelItemCount(); ++i) {
            QTreeWidgetItem* parent = apTreeWidget->topLevelItem(i);
            bool parentMatches = parent->text(0).contains(text, Qt::CaseInsensitive);
            bool hasVisibleChild = false;
            for (int j = 0; j < parent->childCount(); ++j) {
                QTreeWidgetItem* child = parent->child(j);
                bool childMatches = child->text(0).contains(text, Qt::CaseInsensitive);
                child->setHidden(!(parentMatches || childMatches));
                if (!child->isHidden())
                    hasVisibleChild = true;
            }
            parent->setHidden(!(parentMatches || hasVisibleChild));
            if (!text.isEmpty())
                parent->setExpanded(true);
        }
    });

    connect(chkLegacy, &QCheckBox::toggled, this, [this]() { applyBulkSelections(); });
    connect(chkEncore, &QCheckBox::toggled, this, [this]() { applyBulkSelections(); });
    connect(chkExpansion, &QCheckBox::toggled, this, [this]() { applyBulkSelections(); });
}

void CiscoWizardPage2::initializePage() {
    apTreeWidget->clear();
    addTreeCategory(apTreeWidget, "--- WYNN LEGACY ---", apData.wynnLegacy, "#0078D4");
    addTreeCategory(apTreeWidget, "--- ENCORE ---", apData.encoreMain, "#0078D4");
    addTreeCategory(apTreeWidget, "--- EXPANSION ---", apData.wynnExpansion, "#60A5FA");
    addTreeCategory(apTreeWidget, "--- MISC ---", ciscoWizardMiscGroups(), "#60A5FA");
    applyBulkSelections();

    if (!initialCheckedGroups.isEmpty()) {
        for (int i = 0; i < apTreeWidget->topLevelItemCount(); ++i) {
            QTreeWidgetItem* parent = apTreeWidget->topLevelItem(i);
            for (int j = 0; j < parent->childCount(); ++j) {
                QTreeWidgetItem* child = parent->child(j);
                if (initialCheckedGroups.contains(child->data(0, Qt::UserRole).toString()))
                    child->setCheckState(0, Qt::Checked);
            }
        }
    }
}

void CiscoWizardPage2::applyBulkSelections() {
    auto applyList = [&](const QStringList& groups, bool checked) {
        for (int i = 0; i < apTreeWidget->topLevelItemCount(); ++i) {
            QTreeWidgetItem* parent = apTreeWidget->topLevelItem(i);
            for (int j = 0; j < parent->childCount(); ++j) {
                QTreeWidgetItem* child = parent->child(j);
                if (groups.contains(child->data(0, Qt::UserRole).toString()))
                    child->setCheckState(0, checked ? Qt::Checked : Qt::Unchecked);
            }
        }
    };

    applyList(apData.wynnLegacy, chkLegacy->isChecked());
    applyList(apData.encoreMain, chkEncore->isChecked());
    applyList(apData.wynnExpansion, chkExpansion->isChecked());
}

// ====================================================
// WIZARD — PAGE 4: AP Group Selection
// ====================================================

// FIX (Architecture): Accepts ApGroupData instead of casting to main window.
WizardPage4::WizardPage4(ApGroupData data, QWidget* parent)
    : QWizardPage(parent), apData(std::move(data))
{
    setTitle("Step 4: AP Group Selection");
    QVBoxLayout* l = new QVBoxLayout(this);

    searchBox = new QLineEdit(this);
    searchBox->setPlaceholderText("Search AP Groups...");
    l->addWidget(searchBox);

    apTreeWidget = new QTreeWidget(this);
    apTreeWidget->setHeaderHidden(true);
    l->addWidget(apTreeWidget);
    setLayout(l);

    connect(searchBox, &QLineEdit::textChanged, [this](const QString& text) {
        for (int i = 0; i < apTreeWidget->topLevelItemCount(); ++i) {
            QTreeWidgetItem* parent = apTreeWidget->topLevelItem(i);
            bool parentMatches = parent->text(0).contains(text, Qt::CaseInsensitive);
            bool hasVisibleChild = false;
            for (int j = 0; j < parent->childCount(); ++j) {
                QTreeWidgetItem* child = parent->child(j);
                bool childMatches = child->text(0).contains(text, Qt::CaseInsensitive);
                child->setHidden(!(parentMatches || childMatches));
                if (!child->isHidden()) hasVisibleChild = true;
            }
            parent->setHidden(!(parentMatches || hasVisibleChild));
            if (!text.isEmpty()) parent->setExpanded(true);
        }
        });
}

void WizardPage4::initializePage() {
    apTreeWidget->clear();
    int siteIndex = field("site").toInt();

    if (siteIndex == 0) {
        addTreeCategory(apTreeWidget, "--- WYNN LEGACY ---", apData.wynnLegacy, "#0078D4");
        addTreeCategory(apTreeWidget, "--- ENCORE ---", apData.encoreMain, "#0078D4");
        addTreeCategory(apTreeWidget, "--- EXPANSION ---", apData.wynnExpansion, "#60A5FA");
        addTreeCategory(apTreeWidget, "--- MISC ---", apData.wynnMisc, "#60A5FA");
    }
    else {
        addTreeCategory(apTreeWidget, "--- RED ROCK ---", apData.redRock, "#EF4444");
        addTreeCategory(apTreeWidget, "--- GVR ---", apData.gvr, "#EF4444");
        addTreeCategory(apTreeWidget, "--- DURANGO ---", apData.durango, "#EF4444");
        addTreeCategory(apTreeWidget, "--- OTHER SITES ---", apData.stationsMisc, "#F87171");
    }
}

// ====================================================
// WIZARD — PAGE TARGET: Controller Credentials
// ====================================================

// FIX (Architecture): Reads IPs from ApGroupData, not from hardcoded literals.
WizardPageTarget::WizardPageTarget(ApGroupData data, QString explicitIp, QString explicitUser, QString title, QWidget* parent)
    : QWizardPage(parent), apData(std::move(data)),
    configuredIp(std::move(explicitIp)), configuredUser(std::move(explicitUser)), pageTitle(std::move(title))
{
    setTitle(pageTitle);
    enableCiscoTools = pageTitle.contains("Cisco", Qt::CaseInsensitive);
    QVBoxLayout* l = new QVBoxLayout(this);
    leIP = new QLineEdit(this);
    leUser = new QLineEdit(this);
    leUser->setText(configuredUser);
    lePass = new QLineEdit(this);
    lePass->setEchoMode(QLineEdit::Password);
    registerField("ip*", leIP);
    registerField("user*", leUser);
    registerField("pass*", lePass);
    l->addWidget(new QLabel("Controller IP:"));  l->addWidget(leIP);
    l->addWidget(new QLabel("Username:"));       l->addWidget(leUser);
    l->addWidget(new QLabel("Password:"));       l->addWidget(lePass);

    if (enableCiscoTools) {
        btnCheckWlanIds = new QPushButton("CHECK WLAN IDS", this);
        wlanSummaryOutput = new QPlainTextEdit(this);
        wlanSummaryOutput->setReadOnly(true);
        wlanSummaryOutput->setMinimumHeight(180);
        l->addWidget(btnCheckWlanIds);
        l->addWidget(new QLabel("Cisco WLAN ID Summary:"));
        l->addWidget(wlanSummaryOutput);

        connect(btnCheckWlanIds, &QPushButton::clicked, this, [this]() {
            const QString ip = leIP->text().trimmed();
            const QString user = leUser->text().trimmed();
            const QString pass = lePass->text();

            if (ip.isEmpty() || user.isEmpty() || pass.isEmpty()) {
                QMessageBox::warning(this, "Missing Cisco Credentials",
                    "Enter the controller IP, username, and password before checking WLAN IDs.");
                return;
            }

            btnCheckWlanIds->setEnabled(false);
            wlanSummaryOutput->setPlainText("Checking Cisco WLAN IDs...");
            qApp->processEvents();

            QString summary;
            QString error;
            if (fetchCiscoWlanSummary(this, ip, user, pass, &summary, &error))
                wlanSummaryOutput->setPlainText(summary);
            else
                wlanSummaryOutput->setPlainText(">>> ERROR: " + error);

            btnCheckWlanIds->setEnabled(true);
        });
    }
    setLayout(l);
}

void WizardPageTarget::initializePage() {
    if (!configuredIp.isEmpty()) {
        leIP->setText(configuredIp);
        return;
    }
    int idx = field("site").toInt();
    leIP->setText(idx == 0 ? apData.wynnControllerIp : apData.stationsControllerIp);
}

// ====================================================
// WIZARD — PAGE 5: Config Preview
// ====================================================

WizardPage5::WizardPage5(WizardPage4* apPage, ApGroupData data, QWidget* parent)
    : QWizardPage(parent), p4(apPage), apData(std::move(data))
{
    setTitle("Step 6: Configuration Preview");
    QVBoxLayout* l = new QVBoxLayout(this);
    configPreview = new QPlainTextEdit(this);
    new ArubaHighlighter(configPreview->document());
    l->addWidget(configPreview);
    setLayout(l);
    setCommitPage(true);
}

void WizardPage5::initializePage() {
    QString ssid = field("ssid").toString();
    QString vlan = field("vlan").toString();
    QString psk = field("psk").toString();
    QString auth = field("auth").toString();
    int     idx = field("site").toInt();

    QStringList selectedGroups = { "default" };
    for (int i = 0; i < p4->apTreeWidget->topLevelItemCount(); ++i) {
        QTreeWidgetItem* parent = p4->apTreeWidget->topLevelItem(i);
        for (int j = 0; j < parent->childCount(); ++j) {
            if (parent->child(j)->checkState(0) == Qt::Checked)
                selectedGroups << parent->child(j)->data(0, Qt::UserRole).toString();
        }
    }
    selectedGroups.removeDuplicates();
    selectedGroups.sort();

    // FIX (C++ Code): Uses the shared buildArubaConfig() — no duplicated logic.
    configPreview->setPlainText(
        buildArubaConfig(ssid, vlan, auth, psk, "50Mbps-Per-User", false,
            field("splash_page_aruba").toBool(),
            idx, selectedGroups, apData)
    );
}

// ====================================================
// CISCO WIZARD — PAGE 3: CONFIG PREVIEW
// ====================================================

CiscoWizardPage3::CiscoWizardPage3(CiscoWizardPage2* apPage, QString title, QWidget* parent)
    : QWizardPage(parent), p2(apPage)
{
    setTitle(title);
    QVBoxLayout* l = new QVBoxLayout(this);
    configPreview = new QPlainTextEdit(this);
    new ArubaHighlighter(configPreview->document());
    l->addWidget(configPreview);
    setLayout(l);
    setCommitPage(true);
}

void CiscoWizardPage3::initializePage() {
    QStringList selectedGroups;
    for (int i = 0; i < p2->apTreeWidget->topLevelItemCount(); ++i) {
        QTreeWidgetItem* parent = p2->apTreeWidget->topLevelItem(i);
        for (int j = 0; j < parent->childCount(); ++j) {
            if (parent->child(j)->checkState(0) == Qt::Checked)
                selectedGroups << parent->child(j)->data(0, Qt::UserRole).toString();
        }
    }
    selectedGroups.removeDuplicates();
    selectedGroups.sort();

    configPreview->setPlainText(
        buildCiscoWlanConfig(
            field("cisco_ssid").toString().trimmed(),
            field("cisco_vlan").toString().trimmed(),
            field("cisco_psk").toString(),
            field("cisco_wlan_id").toString().trimmed(),
            field("cisco_company").toString().trimmed(),
            field("cisco_removal").toString().trimmed(),
            field("cisco_max_clients").toString().trimmed(),
            field("cisco_splash_page").toBool(),
            selectedGroups
        )
    );
}

// ====================================================
// WIZARD — PAGE 6: Deployment
// ====================================================

WizardPage6::WizardPage6(QPlainTextEdit* preview, ACS_Wynn_Builder* owner, DeploymentOptions options, QString title, QWidget* parent)
    : QWizardPage(parent), wizardOwner(owner), previewOutput(preview), deployComplete(false),
    deployOptions(options), pageTitle(std::move(title))
{
    setTitle(pageTitle);
    QVBoxLayout* l = new QVBoxLayout(this);
    sshLogOutput = new QPlainTextEdit(this);
    sshLogOutput->setReadOnly(true);
    l->addWidget(new QLabel("Deployment Logs:"));
    l->addWidget(sshLogOutput);
    setLayout(l);
}

void WizardPage6::initializePage() {
    sshLogOutput->clear();
    deployComplete = false;
    waitingForPersistentConnect = false;
    persistentDeployStarted = false;
    pendingScript.clear();
    emit completeChanged();

    QString script = previewOutput ? previewOutput->toPlainText() : QString();
    QString ip = field("ip").toString();
    QString user = field("user").toString();
    QString pass = field("pass").toString();

    if (logConnection)
        disconnect(logConnection);
    if (connectFinishedConnection)
        disconnect(connectFinishedConnection);
    if (deployFinishedConnection)
        disconnect(deployFinishedConnection);

    if (wizardOwner && wizardOwner->controllerSessionManager()) {
        ControllerSessionManager* manager = wizardOwner->controllerSessionManager();
        pendingScript = script;

        logConnection = connect(manager, &ControllerSessionManager::logMessage, this,
            [this](const QString& msg) {
                sshLogOutput->appendPlainText(msg);
            });

        connectFinishedConnection = connect(manager, &ControllerSessionManager::connectFinished, this,
            [this, manager](bool success, const QString& message) {
                if (!waitingForPersistentConnect)
                    return;

                waitingForPersistentConnect = false;
                if (!success) {
                    sshLogOutput->appendPlainText(">>> ERROR: " + message);
                    deployComplete = true;
                    emit completeChanged();
                    return;
                }

                if (!persistentDeployStarted) {
                    persistentDeployStarted = true;
                    QMetaObject::invokeMethod(manager, "deployPersistent", Qt::QueuedConnection,
                        Q_ARG(QString, pendingScript));
                }
            });

        deployFinishedConnection = connect(manager, &ControllerSessionManager::deployFinished, this,
            [this](bool success, const QString& message) {
                if (!success)
                    sshLogOutput->appendPlainText(">>> ERROR: " + message);
                deployComplete = true;
                emit completeChanged();
            });

        if (wizardOwner->hasActiveControllerSession(deployOptions.useCiscoShellLogin)) {
            sshLogOutput->appendPlainText(
                deployOptions.useCiscoShellLogin
                ? ">>> Using the active Cisco session from CONNECT. No new login will be attempted."
                : ">>> Using the active Aruba session. No new login will be attempted.");
            persistentDeployStarted = true;
            QMetaObject::invokeMethod(manager, "deployPersistent", Qt::QueuedConnection,
                Q_ARG(QString, pendingScript));
            return;
        }

        QString trustError;
        if (!ensureTrustedHost(this, ip, user, deployOptions, &trustError)) {
            sshLogOutput->appendPlainText(">>> ERROR: " + trustError);
            deployComplete = true;
            emit completeChanged();
            return;
        }

        waitingForPersistentConnect = true;
        QMetaObject::invokeMethod(manager, "connectPersistent", Qt::QueuedConnection,
            Q_ARG(QString, ip),
            Q_ARG(QString, user),
            Q_ARG(QString, pass),
            Q_ARG(bool, deployOptions.useCiscoShellLogin));
        return;
    }

    QString trustError;
    if (!ensureTrustedHost(this, ip, user, deployOptions, &trustError)) {
        sshLogOutput->appendPlainText(">>> ERROR: " + trustError);
        deployComplete = true;
        emit completeChanged();
        return;
    }

    SshWorker* worker = new SshWorker(ip, user, pass, script, deployOptions, this);
    connect(worker, &SshWorker::updateLog, this, [this](const QString& msg) {
        sshLogOutput->appendPlainText(msg);
        });
    connect(worker, &SshWorker::deployFinished, this, [this, worker]() {
        deployComplete = true;
        emit completeChanged();
        worker->deleteLater();
        });
    worker->start();
}

bool WizardPage6::isComplete() const { return deployComplete; }
bool WizardPage6::validatePage() { return true; }

// ====================================================
// MAIN WINDOW
// ====================================================

ACS_Wynn_Builder::ACS_Wynn_Builder(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::ACS_Wynn_BuilderClass)
{
    ui->setupUi(this);
    setWindowIcon(QIcon(":/logo.png"));
    setWindowTitle("ACS Hotel WiFi Builder");
    if (QWidget* contentRoot = takeCentralWidget()) {
        QScrollArea* workspaceScrollArea = new QScrollArea(this);
        workspaceScrollArea->setWidgetResizable(true);
        workspaceScrollArea->setFrameShape(QFrame::NoFrame);
        workspaceScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        workspaceScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        workspaceScrollArea->setWidget(contentRoot);
        setCentralWidget(workspaceScrollArea);
    }

    const QRect available = screen() ? screen()->availableGeometry() : QRect(0, 0, 1280, 720);
    const int targetWidth = qBound(980, available.width() - 60, 1140);
    const int targetHeight = qBound(680, available.height() - 60, 760);
    resize(targetWidth, targetHeight);
    setMinimumSize(980, 680);
    setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
    applyAdaptiveTheme();

    this->setWindowFlags(Qt::Window
        | Qt::WindowSystemMenuHint
        | Qt::WindowMinimizeButtonHint
        | Qt::WindowMaximizeButtonHint
        | Qt::WindowCloseButtonHint);

    if (ui->titleBar)
        ui->titleBar->hide();
    if (ui->btn_close)
        connect(ui->btn_close, &QPushButton::clicked, this, &QWidget::close);
    if (ui->btn_minimize)
        connect(ui->btn_minimize, &QPushButton::clicked, this, &QWidget::showMinimized);

    if (ui->mainLayout) {
        ui->mainLayout->setContentsMargins(18, 18, 18, 18);
        ui->mainLayout->setSpacing(16);
    }

    auto detachWidgetFromLayout = [&](QLayout* layout, QWidget* widget, const auto& self) -> bool {
        if (!layout || !widget)
            return false;

        for (int i = 0; i < layout->count(); ++i) {
            QLayoutItem* item = layout->itemAt(i);
            if (!item)
                continue;

            if (item->widget() == widget) {
                layout->removeWidget(widget);
                return true;
            }

            if (QLayout* childLayout = item->layout()) {
                if (self(childLayout, widget, self))
                    return true;
            }
        }

        return false;
    };

    if (ui->text_output)
        ui->text_output->setVisible(true);
    if (ui->text_output) {
        ui->text_output->setMinimumHeight(180);
        ui->text_output->setLineWrapMode(QPlainTextEdit::NoWrap);
        ui->text_output->setTabStopDistance(28);
        ui->text_output->setPlaceholderText("Your live preview, generated script, and deployment transcript will appear here.");
    }

    const QList<QPushButton*> primaryButtons = { ui->btn_wizard, ui->btn_generate, ui->btn_generate_cisco, ui->btn_test_ssh, ui->btn_open_mremote, ui->btn_deploy };
    for (QPushButton* button : primaryButtons) {
        if (!button)
            continue;
        button->setMinimumHeight(42);
        button->setMinimumWidth(132);
    }
    if (ui->btn_open_mremote)
        ui->btn_open_mremote->hide();
    const QList<QPushButton*> secondaryButtons = { ui->btn_remove, ui->btn_copy, ui->btn_reset };
    for (QPushButton* button : secondaryButtons) {
        if (!button)
            continue;
        button->setMinimumHeight(38);
        button->setMinimumWidth(122);
    }

    QFrame* outputPanel = new QFrame(this);
    outputPanel->setObjectName("outputPanel");
    QVBoxLayout* outputPanelLayout = new QVBoxLayout(outputPanel);
    outputPanelLayout->setContentsMargins(22, 20, 22, 22);
    outputPanelLayout->setSpacing(14);

    outputTitleLabel = new QLabel("Command Preview", outputPanel);
    outputTitleLabel->setObjectName("panelTitle");
    outputSubtitleLabel = new QLabel("Selections update instantly here before you generate or deploy anything.", outputPanel);
    outputSubtitleLabel->setObjectName("panelSubtitle");
    outputSubtitleLabel->setWordWrap(true);

    QWidget* primaryActionsRow = new QWidget(outputPanel);
    QHBoxLayout* primaryActionsLayout = new QHBoxLayout(primaryActionsRow);
    primaryActionsLayout->setContentsMargins(0, 0, 0, 0);
    primaryActionsLayout->setSpacing(10);

    QWidget* secondaryActionsRow = new QWidget(outputPanel);
    QHBoxLayout* secondaryActionsLayout = new QHBoxLayout(secondaryActionsRow);
    secondaryActionsLayout->setContentsMargins(0, 0, 0, 0);
    secondaryActionsLayout->setSpacing(10);

    if (ui->buttonLayout)
        ui->mainLayout->removeItem(ui->buttonLayout);

    for (QPushButton* button : { ui->btn_wizard, ui->btn_generate, ui->btn_generate_cisco, ui->btn_test_ssh, ui->btn_deploy }) {
        if (ui->buttonLayout)
            ui->buttonLayout->removeWidget(button);
        primaryActionsLayout->addWidget(button);
    }
    primaryActionsLayout->addStretch(1);

    for (QPushButton* button : { ui->btn_remove, ui->btn_copy, ui->btn_reset, ui->btn_open_mremote }) {
        if (ui->buttonLayout)
            ui->buttonLayout->removeWidget(button);
        secondaryActionsLayout->addWidget(button);
    }
    secondaryActionsLayout->addStretch(1);

    outputPanelLayout->addWidget(outputTitleLabel);
    outputPanelLayout->addWidget(outputSubtitleLabel);
    outputPanelLayout->addWidget(primaryActionsRow);
    outputPanelLayout->addWidget(secondaryActionsRow);
    if (ui->text_output)
        ui->mainLayout->removeWidget(ui->text_output);
    outputPanelLayout->addWidget(ui->text_output, 1);
    ui->mainLayout->addWidget(outputPanel, 1);

    // FIX (Architecture): Two separate QNetworkAccessManagers so the
    // version-check finished signal never fires for download replies.
    versionCheckManager = new QNetworkAccessManager(this);
    downloadManager = new QNetworkAccessManager(this);
    connect(versionCheckManager, &QNetworkAccessManager::finished,
        this, &ACS_Wynn_Builder::onVersionCheckComplete);

    ui->entry_vlan->setValidator(new QIntValidator(1, 4094, this));
    ui->entry_path->setReadOnly(true);
    ui->entry_path->setToolTip("Controller configuration path is managed by site policy.");
    ui->entry_essid->setPlaceholderText("Broadcast SSID");
    ui->entry_vlan->setPlaceholderText("VLAN");
    ui->entry_role->setPlaceholderText("50Mbps-Per-User");
    ui->entry_user->setPlaceholderText("Username");
    ui->entry_ip->setPlaceholderText("Controller IP");
    ui->entry_ssh_pass->setPlaceholderText("Controller password");
    ui->entry_psk->setPlaceholderText("Minimum 8 characters");
    ui->entry_psk->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    ui->entry_psk->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase);
    ui->entry_ssh_pass->setEchoMode(QLineEdit::Password);
    ui->entry_ssh_pass->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase);
    if (QGridLayout* networkLayout = qobject_cast<QGridLayout*>(ui->card1->layout())) {
        chkHideSsid = new QCheckBox("Hide SSID", ui->card1);
        chkArubaSplashPage = new QCheckBox("Splash page (open WLAN)", ui->card1);
        networkLayout->addWidget(chkHideSsid, 3, 0, 1, 2);
        networkLayout->addWidget(chkArubaSplashPage, 3, 2, 1, 2);
    }
    {
        QSettings settings("ACS", "ACS Tool");
        mRemoteExecutablePath = settings.value("mremote/exe_path").toString();
    }
    loadApGroupsFromJson();

    modeTabs = new QTabBar(this);
    modeTabs->setObjectName("modeSwitcher");
    modeTabs->addTab("Aruba");
    modeTabs->addTab("Cisco");
    modeTabs->setExpanding(false);
    modeTabs->setDocumentMode(true);
    modeTabs->setDrawBase(false);
    modeTabs->setUsesScrollButtons(false);
    connect(modeTabs, &QTabBar::currentChanged, this, &ACS_Wynn_Builder::on_modeTabs_currentChanged);

    profilePresetFrame = new QFrame(this);
    profilePresetFrame->setObjectName("toolbarCard");
    QHBoxLayout* profilePresetLayout = new QHBoxLayout(profilePresetFrame);
    profilePresetLayout->setContentsMargins(0, 0, 0, 0);
    profilePresetLayout->setSpacing(8);
    QLabel* profilePresetLabel = new QLabel("Profile:", profilePresetFrame);
    profilePresetCombo = new QComboBox(profilePresetFrame);
    profilePresetCombo->addItem("Custom");
    profilePresetCombo->addItem("Aruba - Wynn");
    profilePresetCombo->addItem("Aruba - Stations");
    profilePresetCombo->addItem("Cisco - Wynn");
    profilePresetCombo->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    profilePresetCombo->setMinimumContentsLength(18);
    profilePresetLayout->addWidget(profilePresetLabel);
    profilePresetLayout->addWidget(profilePresetCombo, 0);
    profilePresetLayout->addStretch(1);
    connect(profilePresetCombo, &QComboBox::currentIndexChanged, this, &ACS_Wynn_Builder::on_profilePreset_currentIndexChanged);
    profilePresetFrame->hide();

    QFrame* toolbarCard = new QFrame(this);
    toolbarCard->setObjectName("toolbarCard");
    QVBoxLayout* toolbarCardLayout = new QVBoxLayout(toolbarCard);
    toolbarCardLayout->setContentsMargins(20, 18, 20, 18);
    toolbarCardLayout->setSpacing(10);
    QLabel* workflowTitle = new QLabel("Workflow", toolbarCard);
    workflowTitle->setObjectName("panelTitle");
    QLabel* workflowSubtitle = new QLabel("Choose the controller family, load a preset, and move through one consistent build flow.", toolbarCard);
    workflowSubtitle->setObjectName("panelSubtitle");
    workflowSubtitle->setWordWrap(true);

    QWidget* toolbarControlsRow = new QWidget(toolbarCard);
    QHBoxLayout* toolbarControlsLayout = new QHBoxLayout(toolbarControlsRow);
    toolbarControlsLayout->setContentsMargins(0, 0, 0, 0);
    toolbarControlsLayout->setSpacing(14);
    toolbarControlsLayout->addWidget(modeTabs, 0, Qt::AlignLeft);
    toolbarControlsLayout->addWidget(profilePresetFrame, 1);
    btnUpdateApp = new QPushButton("CHECK UPDATES", toolbarCard);
    btnUpdateApp->setObjectName("btn_update_app");
    btnUpdateApp->setToolTip("Check GitHub for the latest published release and install it into this folder.");
    toolbarControlsLayout->addWidget(btnUpdateApp, 0, Qt::AlignRight);
    toolbarControlsLayout->addStretch(1);

    toolbarCardLayout->addWidget(workflowTitle);
    toolbarCardLayout->addWidget(workflowSubtitle);
    toolbarCardLayout->addWidget(toolbarControlsRow);
    ui->mainLayout->insertWidget(ui->mainLayout->indexOf(ui->card1), toolbarCard);
    connect(btnUpdateApp, &QPushButton::clicked, this, &ACS_Wynn_Builder::on_btn_update_app_clicked);

    apGroupSelectorFrame = new QFrame(this);
    apGroupSelectorFrame->setObjectName("apGroupSelectorFrame");
    QHBoxLayout* apGroupSelectorLayout = new QHBoxLayout(apGroupSelectorFrame);
    apGroupSelectorLayout->setContentsMargins(18, 14, 18, 14);
    apGroupSelectorLayout->setSpacing(12);
    btnSelectApGroups = new QPushButton("SELECT AP GROUPS", apGroupSelectorFrame);
    apGroupSummaryLabel = new QLabel("Selected AP groups: 0", apGroupSelectorFrame);
    apGroupSummaryLabel->setWordWrap(true);
    apGroupSelectorLayout->addWidget(btnSelectApGroups, 0);
    apGroupSelectorLayout->addWidget(apGroupSummaryLabel, 1);
    ui->mainLayout->insertWidget(ui->mainLayout->indexOf(ui->card4), apGroupSelectorFrame);
    connect(btnSelectApGroups, &QPushButton::clicked, this, &ACS_Wynn_Builder::on_btn_select_ap_groups_clicked);

    buyoutOptionsFrame = new QFrame(this);
    buyoutOptionsFrame->setObjectName("buyoutOptionsFrame");
    QVBoxLayout* buyoutOptionsFrameLayout = new QVBoxLayout(buyoutOptionsFrame);
    buyoutOptionsFrameLayout->setContentsMargins(18, 8, 18, 8);
    buyoutOptionsFrameLayout->setSpacing(0);

    auto createCenteredBuyoutRow = [&](QWidget*& rowWidget) {
        rowWidget = new QWidget(buyoutOptionsFrame);
        QHBoxLayout* rowLayout = new QHBoxLayout(rowWidget);
        rowLayout->setContentsMargins(0, 0, 0, 0);
        rowLayout->setSpacing(28);
        rowLayout->addStretch(1);
        buyoutOptionsFrameLayout->addWidget(rowWidget);
        return rowLayout;
        };

    QHBoxLayout* wynnBuyoutRowLayout = createCenteredBuyoutRow(wynnBuyoutOptionsRow);
    detachWidgetFromLayout(ui->mainLayout, ui->chk_wynn_legacy, detachWidgetFromLayout);
    detachWidgetFromLayout(ui->mainLayout, ui->chk_encore_conv, detachWidgetFromLayout);
    detachWidgetFromLayout(ui->mainLayout, ui->chk_wynn_exp, detachWidgetFromLayout);
    wynnBuyoutRowLayout->addWidget(ui->chk_wynn_legacy);
    wynnBuyoutRowLayout->addWidget(ui->chk_encore_conv);
    wynnBuyoutRowLayout->addWidget(ui->chk_wynn_exp);
    wynnBuyoutRowLayout->addStretch(1);

    QHBoxLayout* stationsBuyoutRowLayout = createCenteredBuyoutRow(stationsBuyoutOptionsRow);
    detachWidgetFromLayout(ui->mainLayout, ui->chk_s_redrock, detachWidgetFromLayout);
    detachWidgetFromLayout(ui->mainLayout, ui->chk_s_gvr, detachWidgetFromLayout);
    detachWidgetFromLayout(ui->mainLayout, ui->chk_s_durango, detachWidgetFromLayout);
    stationsBuyoutRowLayout->addWidget(ui->chk_s_redrock);
    stationsBuyoutRowLayout->addWidget(ui->chk_s_gvr);
    stationsBuyoutRowLayout->addWidget(ui->chk_s_durango);
    stationsBuyoutRowLayout->addStretch(1);

    QHBoxLayout* ciscoBuyoutRowLayout = createCenteredBuyoutRow(ciscoBuyoutOptionsRow);
    buyoutOptionsFrameLayout->addStretch(0);
    ui->mainLayout->insertWidget(ui->mainLayout->indexOf(ui->card4), buyoutOptionsFrame);

    ciscoFrame = new QFrame(this);
    ciscoFrame->setObjectName("ciscoFrame");
    QGridLayout* ciscoLayout = new QGridLayout(ciscoFrame);
    ciscoLayout->setContentsMargins(20, 18, 20, 18);
    ciscoLayout->setHorizontalSpacing(10);
    ciscoLayout->setVerticalSpacing(10);

    QLabel* ciscoConnectHeader = new QLabel("Cisco Controller Session", ciscoFrame);
    ciscoConnectHeader->setObjectName("panelTitle");
    ciscoLayout->addWidget(ciscoConnectHeader, 0, 0, 1, 4);

    ciscoConnectionStatusLabel = new QLabel("Cisco Session Status: Disconnected", ciscoFrame);
    ciscoConnectionStatusLabel->setWordWrap(true);
    ciscoConnectionStatusLabel->setObjectName("ciscoConnectionStatusLabel");
    ciscoLayout->addWidget(ciscoConnectionStatusLabel, 1, 0, 1, 4);

    QGridLayout* ciscoConnectionLayout = new QGridLayout();
    ciscoConnectionLayout->setHorizontalSpacing(8);
    ciscoConnectionLayout->setVerticalSpacing(6);
    QLabel* ciscoIpLabel = new QLabel("IP:", ciscoFrame);
    ciscoControllerIpField = new QLineEdit(ciscoFrame);
    ciscoControllerIpField->setPlaceholderText("Cisco controller IP");
    ciscoControllerIpField->setMaximumWidth(160);
    QLabel* ciscoUserLabel = new QLabel("USER:", ciscoFrame);
    ciscoControllerUserField = new QLineEdit(ciscoFrame);
    ciscoControllerUserField->setPlaceholderText("Username");
    ciscoControllerUserField->setMaximumWidth(120);
    QLabel* ciscoPassLabel = new QLabel("PASS:", ciscoFrame);
    ciscoControllerPassField = new QLineEdit(ciscoFrame);
    ciscoControllerPassField->setPlaceholderText("Controller password");
    ciscoControllerPassField->setEchoMode(QLineEdit::Password);
    ciscoControllerPassField->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase);
    ciscoConnectionLayout->addWidget(ciscoIpLabel, 0, 0);
    ciscoConnectionLayout->addWidget(ciscoControllerIpField, 0, 1);
    ciscoConnectionLayout->addWidget(ciscoUserLabel, 0, 2);
    ciscoConnectionLayout->addWidget(ciscoControllerUserField, 0, 3);
    ciscoConnectionLayout->addWidget(ciscoPassLabel, 0, 4);
    ciscoConnectionLayout->addWidget(ciscoControllerPassField, 0, 5);
    ciscoConnectionLayout->addWidget(ui->btn_test_ssh, 0, 6);
    ciscoConnectionLayout->setColumnStretch(7, 1);
    ciscoLayout->addLayout(ciscoConnectionLayout, 2, 0, 1, 4);

    QLabel* ciscoDetailsHeader = new QLabel("WLAN Configuration", ciscoFrame);
    ciscoDetailsHeader->setObjectName("ciscoSectionHeader");
    ciscoLayout->addWidget(ciscoDetailsHeader, 3, 0, 1, 4);

    ciscoDetailsFrame = new QFrame(ciscoFrame);
    QGridLayout* ciscoDetailsLayout = new QGridLayout(ciscoDetailsFrame);
    ciscoDetailsLayout->setContentsMargins(0, 0, 0, 0);
    ciscoDetailsLayout->setHorizontalSpacing(8);
    ciscoDetailsLayout->setVerticalSpacing(6);

    auto addCiscoField = [&](int row, int column, const QString& labelText, QLineEdit*& field, const QString& placeholder) {
        QLabel* label = new QLabel(labelText, ciscoDetailsFrame);
        field = new QLineEdit(ciscoDetailsFrame);
        field->setPlaceholderText(placeholder);
        ciscoDetailsLayout->addWidget(label, row, column);
        ciscoDetailsLayout->addWidget(field, row, column + 1);
    };

    addCiscoField(0, 0, "Company Name:", ciscoCompanyName, "Example Client");
    addCiscoField(0, 2, "Removal Date:", ciscoRemovalDate, "MM/DD/YYYY");
    addCiscoField(1, 0, "SSID:", ciscoSsid, "Broadcast SSID");
    addCiscoField(1, 2, "WLAN ID:", ciscoWlanId, "62");
    addCiscoField(2, 0, "Password:", ciscoPassword, "Minimum 8 characters");
    chkCiscoSplashPage = new QCheckBox("Splash page (open WLAN)", ciscoDetailsFrame);
    ciscoDetailsLayout->addWidget(chkCiscoSplashPage, 2, 2, 1, 2);
    btnCheckWlanIds = new QPushButton("CHECK WLAN IDS", ciscoDetailsFrame);
    btnCheckWlanIds->setMinimumWidth(132);
    btnCheckWlanIds->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    ciscoDetailsLayout->addWidget(btnCheckWlanIds, 4, 2, 1, 2);
    connect(btnCheckWlanIds, &QPushButton::clicked, this, &ACS_Wynn_Builder::on_btn_check_wlan_ids_clicked);

    QLabel* ciscoMaxClientsLabel = new QLabel("Max Clients:", ciscoDetailsFrame);
    ciscoMaxClients = new QLineEdit(ciscoDetailsFrame);
    ciscoMaxClients->setPlaceholderText("10");
    ciscoDetailsLayout->addWidget(ciscoMaxClientsLabel, 3, 2);
    ciscoDetailsLayout->addWidget(ciscoMaxClients, 3, 3);

    QLabel* ciscoVlanLabel = new QLabel("VLAN:", ciscoDetailsFrame);
    ciscoVlan = new QComboBox(ciscoDetailsFrame);
    ciscoVlan->setEditable(true);
    ciscoVlan->setInsertPolicy(QComboBox::NoInsert);
    ciscoVlan->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    ciscoVlan->setMinimumContentsLength(10);
    ciscoVlan->setPlaceholderText("Select Interface or VLAN");
    ciscoDetailsLayout->addWidget(ciscoVlanLabel, 4, 0);
    ciscoDetailsLayout->addWidget(ciscoVlan, 4, 1);

    chk_cisco_legacy = new QCheckBox("Legacy Buyout", ciscoDetailsFrame);
    chk_cisco_encore = new QCheckBox("Encore Buyout", ciscoDetailsFrame);
    chk_cisco_expansion = new QCheckBox("Expansion Buyout", ciscoDetailsFrame);
    if (QHBoxLayout* rowLayout = qobject_cast<QHBoxLayout*>(ciscoBuyoutOptionsRow ? ciscoBuyoutOptionsRow->layout() : nullptr)) {
        rowLayout->addWidget(chk_cisco_legacy);
        rowLayout->addWidget(chk_cisco_encore);
        rowLayout->addWidget(chk_cisco_expansion);
        rowLayout->addStretch(1);
    }

    search_cisco_wynn = new QLineEdit(ciscoDetailsFrame);
    search_cisco_wynn->setPlaceholderText("Search Cisco AP Groups...");
    ciscoDetailsLayout->addWidget(search_cisco_wynn, 5, 0, 1, 4);

    tree_cisco_wynn = new QTreeWidget(ciscoDetailsFrame);
    tree_cisco_wynn->setHeaderHidden(true);
    tree_cisco_wynn->setMinimumHeight(150);
    ciscoDetailsLayout->addWidget(tree_cisco_wynn, 6, 0, 1, 4);
    ciscoDetailsLayout->setRowStretch(6, 1);
    ciscoDetailsLayout->setColumnStretch(0, 0);
    ciscoDetailsLayout->setColumnStretch(1, 1);
    ciscoDetailsLayout->setColumnStretch(2, 0);
    ciscoDetailsLayout->setColumnStretch(3, 1);
    ciscoLayout->addWidget(ciscoDetailsFrame, 4, 0, 1, 4);
    ciscoLayout->setRowStretch(4, 1);

    ciscoPassword->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    ciscoPassword->setInputMethodHints(Qt::ImhSensitiveData | Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase);
    ciscoWlanId->setValidator(new QIntValidator(1, 512, this));
    ciscoMaxClients->setValidator(new QIntValidator(1, 5000, this));
    if (ciscoVlan->lineEdit()) {
        ciscoVlan->lineEdit()->setValidator(new QIntValidator(1, 4094, this));
        ciscoVlan->lineEdit()->setPlaceholderText("Select Interface or VLAN");
    }
    QStringList interfaceOptions = apData.ciscoInterfaces;
    for (const QString& fallbackInterface : defaultCiscoInterfaceList()) {
        if (!interfaceOptions.contains(fallbackInterface))
            interfaceOptions << fallbackInterface;
    }
    interfaceOptions.sort();
    for (const QString& interfaceOption : interfaceOptions)
        ciscoVlan->addItem(formatCiscoInterfaceLabel(interfaceOption), interfaceOption);

    ui->mainLayout->insertWidget(ui->mainLayout->indexOf(ui->siteTabs), ciscoFrame);
    ciscoFrame->hide();

    auto mirrorLineEditText = [](QLineEdit* source, QLineEdit* target) {
        if (!source || !target)
            return;

        QObject::connect(source, &QLineEdit::textChanged, target, [source, target](const QString& text) {
            if (target->text() == text)
                return;
            QSignalBlocker blocker(target);
            target->setText(text);
            });
        };

    mirrorLineEditText(ciscoControllerIpField, ui->entry_ip);
    mirrorLineEditText(ui->entry_ip, ciscoControllerIpField);
    mirrorLineEditText(ciscoControllerUserField, ui->entry_user);
    mirrorLineEditText(ui->entry_user, ciscoControllerUserField);
    mirrorLineEditText(ciscoControllerPassField, ui->entry_ssh_pass);
    mirrorLineEditText(ui->entry_ssh_pass, ciscoControllerPassField);

    // Swap the placeholder QListWidgets from the .ui file for live QTreeWidgets.
    if (ui->list_wynn_aps->parentWidget() &&
        ui->list_wynn_aps->parentWidget()->layout())
    {
        QLayout* wynnLayout = ui->list_wynn_aps->parentWidget()->layout();
        search_wynn = new QLineEdit(this);
        search_wynn->setPlaceholderText("Search AP Groups...");
        tree_wynn = new QTreeWidget(this);
        tree_wynn->setHeaderHidden(true);
        wynnLayout->removeWidget(ui->list_wynn_aps);
        ui->list_wynn_aps->hide();
        wynnLayout->addWidget(search_wynn);
        wynnLayout->addWidget(tree_wynn);
        search_wynn->hide();
        tree_wynn->hide();
    }

    if (ui->list_stations_aps->parentWidget() &&
        ui->list_stations_aps->parentWidget()->layout())
    {
        QLayout* stationsLayout = ui->list_stations_aps->parentWidget()->layout();
        search_stations = new QLineEdit(this);
        search_stations->setPlaceholderText("Search AP Groups...");
        tree_stations = new QTreeWidget(this);
        tree_stations->setHeaderHidden(true);
        stationsLayout->removeWidget(ui->list_stations_aps);
        ui->list_stations_aps->hide();
        stationsLayout->addWidget(search_stations);
        stationsLayout->addWidget(tree_stations);
        search_stations->hide();
        tree_stations->hide();
    }

    highlighter = new ArubaHighlighter(ui->text_output->document());
    this->statusBar()->showMessage("System Ready", 5000);

    populateTree(tree_wynn, 0);
    populateTree(tree_stations, 1);
    addTreeCategory(tree_cisco_wynn, "--- WYNN LEGACY ---", apData.wynnLegacy, "#0078D4");
    addTreeCategory(tree_cisco_wynn, "--- ENCORE ---", apData.encoreMain, "#0078D4");
    addTreeCategory(tree_cisco_wynn, "--- EXPANSION ---", apData.wynnExpansion, "#60A5FA");
    addTreeCategory(tree_cisco_wynn, "--- MISC ---", getCiscoWynnMiscGroups(), "#60A5FA");

    connect(ui->entry_essid, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ui->entry_vlan, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ui->entry_psk, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ui->combo_auth, &QComboBox::currentTextChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    if (chkHideSsid)
        connect(chkHideSsid, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    if (chkArubaSplashPage) {
        connect(chkArubaSplashPage, &QCheckBox::toggled, this, [this](bool checked) {
            if (ui->combo_auth) {
                ui->combo_auth->setCurrentText(checked ? "Open" : "WPA2-PSK");
                ui->combo_auth->setEnabled(!checked);
            }
            if (ui->entry_psk) {
                if (checked)
                    ui->entry_psk->clear();
                ui->entry_psk->setEnabled(!checked);
            }
            updateLivePreview();
        });
    }

    connect(ui->chk_wynn_legacy, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ui->chk_encore_conv, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ui->chk_wynn_exp, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ui->chk_s_redrock, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ui->chk_s_gvr, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ui->chk_s_durango, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);

    connect(ciscoCompanyName, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ciscoRemovalDate, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ciscoSsid, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ciscoPassword, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ciscoWlanId, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ciscoMaxClients, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(ciscoVlan, &QComboBox::currentTextChanged, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(chk_cisco_legacy, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(chk_cisco_encore, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    connect(chk_cisco_expansion, &QCheckBox::toggled, this, &ACS_Wynn_Builder::updateLivePreview);
    if (chkCiscoSplashPage) {
        connect(chkCiscoSplashPage, &QCheckBox::toggled, this, [this](bool checked) {
            if (ciscoPassword) {
                if (checked)
                    ciscoPassword->clear();
                ciscoPassword->setEnabled(!checked);
            }
            updateLivePreview();
        });
    }

    connect(tree_wynn, &QTreeWidget::itemChanged, this, [this]() { updateLivePreview(); });
    connect(tree_stations, &QTreeWidget::itemChanged, this, [this]() { updateLivePreview(); });
    connect(tree_cisco_wynn, &QTreeWidget::itemChanged, this, [this]() { updateLivePreview(); });

    connect(search_wynn, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::onSearchWynn);
    connect(search_stations, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::onSearchStations);
    connect(search_cisco_wynn, &QLineEdit::textChanged, this, &ACS_Wynn_Builder::onSearchCiscoWynn);
    search_cisco_wynn->hide();
    tree_cisco_wynn->hide();

    persistentSessionThread = new QThread(this);
    persistentSessionManager = new ControllerSessionManager();
    persistentSessionManager->moveToThread(persistentSessionThread);
    connect(persistentSessionThread, &QThread::finished, persistentSessionManager, &QObject::deleteLater);
    connect(persistentSessionManager, &ControllerSessionManager::logMessage, this, &ACS_Wynn_Builder::handleSshLog);
    connect(persistentSessionManager, &ControllerSessionManager::connectionStateChanged, this,
        [this](bool connected, bool isCiscoMode, const QString& ip, const QString& user) {
            ciscoSessionConnected = connected;
            ciscoSessionIsCiscoMode = isCiscoMode;
            ciscoSessionIp = connected ? ip : QString();
            ciscoSessionUser = connected ? user : QString();
            if (sshSessionStatus) {
                sshSessionStatus->setText(connected
                    ? ((isCiscoMode ? "Cisco" : "Aruba") + QString(" controller session is connected."))
                    : "No active controller session.");
            }
            updateCiscoConnectionUi();
            emit ciscoSessionStateChanged();
        });
    connect(persistentSessionManager, &ControllerSessionManager::connectFinished, this,
        [this](bool success, const QString& message) {
            ui->btn_test_ssh->setEnabled(true);
            if (!success) {
                pendingAutoCiscoWlanIdSelection = false;
                pendingPersistentDeploy = false;
                pendingPersistentDeployScript.clear();
                appendOutputText(">>> ERROR: " + message, "Deployment Console");
            }
            else if (pendingPersistentDeploy && ciscoSessionIsCiscoMode == pendingPersistentDeployIsCiscoMode) {
                const QString script = pendingPersistentDeployScript;
                pendingPersistentDeploy = false;
                pendingPersistentDeployIsCiscoMode = false;
                pendingPersistentDeployScript.clear();
                QMetaObject::invokeMethod(persistentSessionManager, "deployPersistent", Qt::QueuedConnection,
                    Q_ARG(QString, script));
            } else if (pendingPersistentDeploy) {
                pendingPersistentDeploy = false;
                pendingPersistentDeployIsCiscoMode = false;
                pendingPersistentDeployScript.clear();
                appendOutputText(">>> ERROR: Session mode changed before deployment could start.", "Deployment Console");
            }

            if (success && pendingAutoCiscoWlanIdSelection && ciscoSessionIsCiscoMode) {
                if (btnCheckWlanIds)
                    btnCheckWlanIds->setEnabled(false);
                QMetaObject::invokeMethod(persistentSessionManager, "checkWlanIdsPersistent", Qt::QueuedConnection);
            }

            updateCiscoConnectionUi();
            this->statusBar()->showMessage(message, 5000);
        });
    connect(persistentSessionManager, &ControllerSessionManager::deployFinished, this,
        [this](bool success, const QString& message) {
            ui->btn_deploy->setEnabled(true);
            ui->btn_deploy->setText("DEPLOY");
            if (!success)
                appendOutputText(">>> ERROR: " + message, "Deployment Console");
            else if (ciscoSessionConnected && ciscoSessionIsCiscoMode) {
                pendingPostDeployCiscoWlanRefresh = true;
                if (btnCheckWlanIds)
                    btnCheckWlanIds->setEnabled(false);
                appendOutputText(">>> Refreshing Cisco WLAN ID summary after deployment...", "Output");
                QMetaObject::invokeMethod(persistentSessionManager, "checkWlanIdsPersistent", Qt::QueuedConnection);
            }
            this->statusBar()->showMessage(message, 5000);
        });
    connect(persistentSessionManager, &ControllerSessionManager::wlanIdCheckFinished, this,
        [this](bool success, const QString& message, const QString& output) {
            if (!output.isEmpty())
                setOutputText(output, "Output");
            else if (!success)
                appendOutputText(">>> ERROR: " + message, "Output");

            if (success && pendingAutoCiscoWlanIdSelection && ciscoWlanId) {
                const int suggestedId = extractSuggestedCiscoWlanId(output);
                if (suggestedId > 0) {
                    ciscoWlanId->setText(QString::number(suggestedId));
                    emit ciscoSuggestedWlanIdChanged(QString::number(suggestedId));
                    QMessageBox::information(
                        this,
                        "WLAN ID Selected",
                        QString("WLAN ID %1 has been selected and filled into the form.").arg(suggestedId));
                    this->statusBar()->showMessage(
                        QString("Cisco connected. Lowest available WLAN ID above 59 is %1.").arg(suggestedId),
                        7000);
                } else {
                    this->statusBar()->showMessage(message, 5000);
                }
            } else if (success && pendingPostDeployCiscoWlanRefresh) {
                this->statusBar()->showMessage("Cisco deployment complete. WLAN summary refreshed.", 7000);
            } else {
                this->statusBar()->showMessage(message, 5000);
            }
            pendingAutoCiscoWlanIdSelection = false;
            pendingPostDeployCiscoWlanRefresh = false;
            if (btnCheckWlanIds)
                btnCheckWlanIds->setEnabled(true);
        });
    persistentSessionThread->start();

    connect(ui->siteTabs, SIGNAL(currentChanged(int)),
        this, SLOT(on_siteTabs_currentChanged(int)));

    on_btn_reset_clicked();
    syncModeUi();
    on_siteTabs_currentChanged(ui->siteTabs->currentIndex());

    if (ui->mainLayout) {
        ui->mainLayout->setStretch(ui->mainLayout->indexOf(apGroupSelectorFrame), 0);
        ui->mainLayout->setStretch(ui->mainLayout->indexOf(ui->siteTabs), 0);
        ui->mainLayout->setStretch(ui->mainLayout->indexOf(ciscoFrame), 2);
        ui->mainLayout->setStretch(ui->mainLayout->indexOf(outputPanel), 3);
    }
    if (ui->siteTabs) {
        ui->siteTabs->setMinimumHeight(52);
        ui->siteTabs->setMaximumHeight(60);
        ui->siteTabs->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    }
    if (ciscoFrame)
        ciscoFrame->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::MinimumExpanding);
    updateApGroupSelectionSummary();
    refreshWorkspaceSummary();
    QTimer::singleShot(1200, this, [this]() { checkForUpdates(); });
}

ACS_Wynn_Builder::~ACS_Wynn_Builder() {
    if (persistentSessionManager)
        QMetaObject::invokeMethod(persistentSessionManager, "disconnectPersistent", Qt::BlockingQueuedConnection);
    if (persistentSessionThread) {
        persistentSessionThread->quit();
        persistentSessionThread->wait();
    }
    delete ui;
}

bool ACS_Wynn_Builder::hasActiveCiscoSession() const {
    return ciscoSessionConnected && ciscoSessionIsCiscoMode;
}

bool ACS_Wynn_Builder::hasActiveControllerSession(bool isCiscoMode) const {
    return ciscoSessionConnected && ciscoSessionIsCiscoMode == isCiscoMode;
}

QString ACS_Wynn_Builder::activeCiscoSessionIp() const {
    return ciscoSessionIp;
}

QString ACS_Wynn_Builder::activeCiscoSessionUser() const {
    return ciscoSessionUser;
}

QString ACS_Wynn_Builder::defaultCiscoControllerIp() const {
    return apData.ciscoControllerIp;
}

void ACS_Wynn_Builder::setCiscoSessionCredentials(const QString& ip, const QString& user, const QString& pass) {
    if (ciscoControllerIpField)
        ciscoControllerIpField->setText(ip);
    if (ciscoControllerUserField)
        ciscoControllerUserField->setText(user);
    if (ciscoControllerPassField)
        ciscoControllerPassField->setText(pass);

    if (ui->entry_ip)
        ui->entry_ip->setText(ip);
    if (ui->entry_user)
        ui->entry_user->setText(user);
    if (ui->entry_ssh_pass)
        ui->entry_ssh_pass->setText(pass);
}

ControllerSessionManager* ACS_Wynn_Builder::controllerSessionManager() const {
    return persistentSessionManager;
}

QString ACS_Wynn_Builder::resolveMRemotePath() {
    if (!mRemoteExecutablePath.isEmpty() && QFileInfo::exists(mRemoteExecutablePath))
        return mRemoteExecutablePath;

    const QString selectedPath = QFileDialog::getOpenFileName(
        this,
        "Locate mRemoteNG",
        QDir::homePath(),
        "Executable Files (*.exe)"
    );

    if (selectedPath.isEmpty())
        return QString();

    mRemoteExecutablePath = selectedPath;
    QSettings settings("ACS", "ACS Tool");
    settings.setValue("mremote/exe_path", mRemoteExecutablePath);
    return mRemoteExecutablePath;
}

void ACS_Wynn_Builder::ensureSshSessionDialog(const QString& title, const QString& statusText, bool clearLog) {
    Q_UNUSED(title);
    Q_UNUSED(statusText);
    Q_UNUSED(clearLog);
}

void ACS_Wynn_Builder::ensureOutputDialog(const QString& title, bool clearOutput) {
    Q_UNUSED(title);
    Q_UNUSED(clearOutput);

    // The builder now uses the embedded output panel exclusively.
    // If an older session created the detached dialog, make sure it stays hidden.
    if (outputDialog && outputDialog->isVisible())
        outputDialog->hide();
}

void ACS_Wynn_Builder::setOutputText(const QString& text, const QString& title) {
    if (outputTitleLabel)
        outputTitleLabel->setText(title.isEmpty() ? "Command Preview" : title);
    if (outputSubtitleLabel) {
        QString subtitle = "Selections update instantly here before you generate or deploy anything.";
        const QString normalizedTitle = title.trimmed().toLower();
        if (normalizedTitle.contains("deployment")) {
            subtitle = "Live controller transcript. Watch connection, validation, and deployment events as they happen.";
        } else if (normalizedTitle.contains("generated") || normalizedTitle == "output") {
            subtitle = text.contains("PREVIEW", Qt::CaseInsensitive)
                ? "This is a live draft based on the current form values and AP-group selections."
                : "Generated commands are ready for review, copy, or deployment.";
        }
        outputSubtitleLabel->setText(subtitle);
    }
    if (ui->text_output)
        ui->text_output->setPlainText(text);
    if (outputDialogText && outputDialog && outputDialog->isVisible())
        outputDialogText->setPlainText(text);
}

void ACS_Wynn_Builder::appendOutputText(const QString& text, const QString& title) {
    if (outputTitleLabel && !title.trimmed().isEmpty())
        outputTitleLabel->setText(title);
    if (outputSubtitleLabel && title.contains("deployment", Qt::CaseInsensitive))
        outputSubtitleLabel->setText("Live controller transcript. Watch connection, validation, and deployment events as they happen.");
    if (ui->text_output)
        ui->text_output->appendPlainText(text);
    if (outputDialogText && outputDialog && outputDialog->isVisible())
        outputDialogText->appendPlainText(text);
}

void ACS_Wynn_Builder::refreshWorkspaceSummary() {
    const bool isCiscoMode = modeTabs && modeTabs->currentIndex() == 1;
    const QString siteName = isCiscoMode
        ? QString("Wynn Cisco")
        : (ui->siteTabs && ui->siteTabs->currentIndex() == 0 ? QString("Wynn & Encore") : QString("Stations Casinos"));
    const int selectedGroupCount = isCiscoMode
        ? getCiscoWynnApGroups().size()
        : qMax(0, getSelectedGroups().size() - 1);

    if (modeBadgeLabel)
        modeBadgeLabel->setText(isCiscoMode ? "Mode  Cisco workflow" : "Mode  Aruba workflow");
    if (siteBadgeLabel)
        siteBadgeLabel->setText(QString("Scope  %1  |  %2 groups").arg(siteName).arg(selectedGroupCount));
    if (sessionBadgeLabel) {
        QString sessionText = isCiscoMode
            ? (hasActiveCiscoSession() ? "Session  Connected" : "Session  Awaiting controller connect")
            : "Session  Direct Aruba deploy";
        sessionBadgeLabel->setText(sessionText);
    }
}

void ACS_Wynn_Builder::updateCiscoConnectionUi() {
    const bool isCiscoMode = modeTabs && modeTabs->currentIndex() == 1;
    const bool hasCiscoSession = isCiscoMode && ciscoSessionConnected && ciscoSessionIsCiscoMode;

    if (ui->btn_test_ssh) {
        ui->btn_test_ssh->setVisible(isCiscoMode);
        ui->btn_test_ssh->setText(hasCiscoSession ? "DISCONNECT" : "CONNECT");
    }
    if (btnCheckWlanIds) {
        btnCheckWlanIds->setVisible(isCiscoMode);
        btnCheckWlanIds->setEnabled(hasCiscoSession);
    }
    if (btnSelectApGroups) {
        btnSelectApGroups->setVisible(true);
        btnSelectApGroups->setEnabled(true);
    }
    if (ui->btn_generate_cisco) {
        ui->btn_generate_cisco->setEnabled(true);
    }
    if (ui->btn_deploy) {
        ui->btn_deploy->setEnabled(isCiscoMode ? hasCiscoSession : true);
    }
    if (ciscoDetailsFrame) {
        ciscoDetailsFrame->setEnabled(true);
    }
    if (ciscoConnectionStatusLabel) {
        ciscoConnectionStatusLabel->setVisible(isCiscoMode);
        if (hasCiscoSession) {
            ciscoConnectionStatusLabel->setText(
                "Cisco Session Status: Connected to " + ciscoSessionIp +
                " as " + (ciscoSessionUser.isEmpty() ? QString("<unknown user>") : ciscoSessionUser));
        } else if (isCiscoMode) {
            ciscoConnectionStatusLabel->setText("Cisco Session Status: Disconnected. Connect to auto-fill the next available WLAN ID or deploy.");
        }
    }
    refreshWorkspaceSummary();
}

// ====================================================
// SEARCH
// ====================================================

void ACS_Wynn_Builder::onSearchWynn(const QString& text) { executeSearch(tree_wynn, text); }
void ACS_Wynn_Builder::onSearchStations(const QString& text) { executeSearch(tree_stations, text); }
void ACS_Wynn_Builder::onSearchCiscoWynn(const QString& text) { executeSearch(tree_cisco_wynn, text); }

void ACS_Wynn_Builder::executeSearch(QTreeWidget* tree, const QString& text) {
    for (int i = 0; i < tree->topLevelItemCount(); ++i) {
        QTreeWidgetItem* parent = tree->topLevelItem(i);
        bool parentMatches = parent->text(0).contains(text, Qt::CaseInsensitive);
        bool hasVisibleChild = false;

        for (int j = 0; j < parent->childCount(); ++j) {
            QTreeWidgetItem* child = parent->child(j);
            bool childMatches = child->text(0).contains(text, Qt::CaseInsensitive);
            child->setHidden(!(parentMatches || childMatches));
            if (!child->isHidden()) hasVisibleChild = true;
        }
        parent->setHidden(!hasVisibleChild && !parentMatches);
        if (!text.isEmpty()) parent->setExpanded(true);
    }
}

// ====================================================
// SELECTION HELPERS
// ====================================================

QStringList ACS_Wynn_Builder::getSelectedGroups() {
    int idx = ui->siteTabs->currentIndex();
    QTreeWidget* activeTree = (idx == 0) ? tree_wynn : tree_stations;
    QStringList selectedGroups = { "default" };

    for (int i = 0; i < activeTree->topLevelItemCount(); ++i) {
        QTreeWidgetItem* parent = activeTree->topLevelItem(i);
        for (int j = 0; j < parent->childCount(); ++j) {
            if (parent->child(j)->checkState(0) == Qt::Checked)
                selectedGroups << parent->child(j)->data(0, Qt::UserRole).toString();
        }
    }

    if (idx == 0) {
        if (ui->chk_wynn_legacy->isChecked()) selectedGroups << apData.wynnLegacy;
        if (ui->chk_encore_conv->isChecked()) selectedGroups << apData.encoreMain;
        if (ui->chk_wynn_exp->isChecked())    selectedGroups << apData.wynnExpansion;
    }
    else {
        if (ui->chk_s_redrock->isChecked())   selectedGroups << apData.redRock;
        if (ui->chk_s_gvr->isChecked())       selectedGroups << apData.gvr;
        if (ui->chk_s_durango->isChecked())   selectedGroups << apData.durango;
    }

    selectedGroups.removeDuplicates();
    selectedGroups.sort();
    return selectedGroups;
}

QString ACS_Wynn_Builder::buildPreviewList() {
    QStringList groups = getSelectedGroups();
    QStringList preview;
    const bool splashPage = chkArubaSplashPage && chkArubaSplashPage->isChecked();
    preview << "! ==========================================";
    preview << "! LIVE PREVIEW: TARGET AP GROUPS (" + QString::number(groups.size()) + ")";
    preview << "! ==========================================";
    preview << "! Security: " + QString(splashPage ? "Splash page / open WLAN" : ui->combo_auth->currentText());
    for (const QString& g : groups) preview << "!  -> " + g;
    preview << "!";
    preview << "! Verify your selection above.";
    preview << "! Click [GENERATE] to build the full Aruba CLI script.";
    return preview.join("\n");
}

QStringList ACS_Wynn_Builder::getCiscoWynnApGroups() const {
    QStringList groups;

    auto appendUnique = [&groups](const QStringList& source) {
        for (const QString& group : source) {
            if (!group.isEmpty() && group != "default" && !groups.contains(group))
                groups << group;
        }
    };

    if (chk_cisco_legacy && chk_cisco_legacy->isChecked()) appendUnique(apData.wynnLegacy);
    if (chk_cisco_expansion && chk_cisco_expansion->isChecked()) appendUnique(apData.wynnExpansion);
    if (chk_cisco_encore && chk_cisco_encore->isChecked()) appendUnique(apData.encoreMain);

    if (tree_cisco_wynn) {
        for (int i = 0; i < tree_cisco_wynn->topLevelItemCount(); ++i) {
            QTreeWidgetItem* parent = tree_cisco_wynn->topLevelItem(i);
            for (int j = 0; j < parent->childCount(); ++j) {
                QTreeWidgetItem* child = parent->child(j);
                if (child->checkState(0) == Qt::Checked)
                    appendUnique({ child->data(0, Qt::UserRole).toString() });
            }
        }
    }

    return groups;
}

QStringList ACS_Wynn_Builder::getCiscoWynnMiscGroups() const {
    return ciscoWizardMiscGroups();
}

QString ACS_Wynn_Builder::buildCiscoPreview() const {
    const QStringList groups = getCiscoWynnApGroups();
    const bool splashPage = chkCiscoSplashPage && chkCiscoSplashPage->isChecked();
    QStringList preview;
    preview << "! ==========================================";
    preview << "! CISCO WYNN WLAN PREVIEW";
    preview << "! ==========================================";
    preview << "! Company Name: " + (ciscoCompanyName->text().trimmed().isEmpty() ? "<required>" : ciscoCompanyName->text().trimmed());
    preview << "! Removal Date: " + (ciscoRemovalDate->text().trimmed().isEmpty() ? "<required>" : ciscoRemovalDate->text().trimmed());
    preview << "! SSID: " + (ciscoSsid->text().trimmed().isEmpty() ? "<required>" : ciscoSsid->text().trimmed());
    preview << "! WLAN ID: " + (ciscoWlanId->text().trimmed().isEmpty() ? "<required>" : ciscoWlanId->text().trimmed());
    preview << "! Max Clients: " + (ciscoMaxClients->text().trimmed().isEmpty() ? "<required>" : ciscoMaxClients->text().trimmed());
    preview << "! Interface/VLAN: " + (ciscoVlan->currentText().trimmed().isEmpty() ? "<required>" : ciscoVlan->currentText().trimmed());
    preview << "! Security: " + QString(splashPage ? "Splash page / open WLAN" : "WPA2-PSK");
    preview << "! AP GROUPS (" + QString::number(groups.size()) + " Total):";
    for (const QString& group : groups)
        preview << "!  -> " + group;
    preview << "!";
    preview << "! Click [GEN CISCO] to build the full Cisco WLAN script.";
    return preview.join("\n");
}

// FIX (C++ Code): Delegates to the shared buildArubaConfig() free function.
QString ACS_Wynn_Builder::buildConfigScript() {
    QString ssid = ui->entry_essid->text().trimmed();
    if (ssid.isEmpty()) return "! ERROR: Please enter a Broadcast SSID.";

    const bool splashPage = chkArubaSplashPage && chkArubaSplashPage->isChecked();
    QString auth = splashPage ? "Open" : ui->combo_auth->currentText();
    QString psk = ui->entry_psk->text();
    if (!splashPage && auth == "WPA2-PSK" && psk.length() < 8)
        return "! ERROR: WPA2-PSK requires a password of at least 8 characters.";

    return buildArubaConfig(ssid,
        ui->entry_vlan->text(),
        auth, psk,
        ui->entry_role->text(),
        chkHideSsid && chkHideSsid->isChecked(),
        splashPage,
        ui->siteTabs->currentIndex(),
        getSelectedGroups(),
        apData);
}

QString ACS_Wynn_Builder::buildCiscoConfigScript() {
    return buildCiscoWlanConfig(
        ciscoSsid->text().trimmed(),
        ciscoVlan->currentText().trimmed(),
        ciscoPassword->text(),
        ciscoWlanId->text().trimmed(),
        ciscoCompanyName->text().trimmed(),
        ciscoRemovalDate->text().trimmed(),
        ciscoMaxClients->text().trimmed(),
        chkCiscoSplashPage && chkCiscoSplashPage->isChecked(),
        getCiscoWynnApGroups()
    );
}

// ====================================================
// BUTTON SLOTS
// ====================================================

void ACS_Wynn_Builder::updateLivePreview() {
    if (modeTabs && modeTabs->currentIndex() == 1)
        setOutputText(buildCiscoPreview(), "Live Preview");
    else
        setOutputText(buildPreviewList(), "Live Preview");
    updateApGroupSelectionSummary();
}

void ACS_Wynn_Builder::on_btn_generate_clicked() {
    setOutputText(buildConfigScript(), "Generated Output");
    this->statusBar()->showMessage("Script Generated.", 3000);
}

void ACS_Wynn_Builder::on_btn_generate_cisco_clicked() {
    setOutputText(buildCiscoConfigScript(), "Generated Output");
    this->statusBar()->showMessage("Cisco WLAN script generated.", 3000);
}

void ACS_Wynn_Builder::on_modeTabs_currentChanged(int) {
    syncModeUi();
    updateLivePreview();
}

void ACS_Wynn_Builder::on_profilePreset_currentIndexChanged(int) {
    if (!profilePresetCombo)
        return;

    applyProfilePreset(profilePresetCombo->currentText(), true);
}

void ACS_Wynn_Builder::on_btn_update_app_clicked() {
    checkForUpdates(true);
}

void ACS_Wynn_Builder::on_btn_select_ap_groups_clicked() {
    const bool isCiscoMode = modeTabs && modeTabs->currentIndex() == 1;
    if (isCiscoMode) {
        showApGroupSelectorDialog("Select Cisco AP Groups", tree_cisco_wynn);
        return;
    }

    const bool isWynnSite = ui->siteTabs->currentIndex() == 0;
    showApGroupSelectorDialog(
        isWynnSite ? "Select Wynn AP Groups" : "Select Stations AP Groups",
        isWynnSite ? tree_wynn : tree_stations
    );
}

void ACS_Wynn_Builder::on_btn_remove_clicked() {
    QString ssid = ui->entry_essid->text().trimmed();
    if (ssid.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please specify the SSID you want to remove.");
        return;
    }

    int     idx = ui->siteTabs->currentIndex();
    QString path = (idx == 0) ? apData.wynnConfigPath : apData.stationsConfigPath;
    QStringList groups = getSelectedGroups();

    QStringList config;
    config << "! === REMOVAL SCRIPT FOR: " + ssid + " ===";
    if (idx == 1) config << "change-config-node " + path;
    else          config << "cd " + path;
    config << "configure terminal";

    for (const QString& g : groups) {
        config << "ap-group \"" + g + "\"" << "  no virtual-ap \"" + ssid + "\"" << "!";
    }
    config << "no wlan virtual-ap \"" + ssid + "\"";
    config << "no wlan ssid-profile \"" + ssid + "\"";
    config << "no wlan ht-ssid-profile \"" + ssid + "-HT\"";
    config << "no aaa profile \"" + ssid + "\"";
    config << "no aaa authentication dot1x \"" + ssid + "\"";
    config << "end";
    config << "configuration commit";
    config << "write memory";

    setOutputText(config.join("\n"), "Output");
    this->statusBar()->showMessage("Removal Script Generated.", 3000);
}

void ACS_Wynn_Builder::handleSshLog(QString message) {
    appendOutputText(message, "Deployment Console");
}

void ACS_Wynn_Builder::on_btn_deploy_clicked() {
    const bool isCiscoMode = modeTabs && modeTabs->currentIndex() == 1;
    const bool hasReusableSession = hasActiveControllerSession(isCiscoMode);
    QString script = ui->text_output->toPlainText();
    if (script.isEmpty() || script.contains("PREVIEW")) {
        QMessageBox::warning(this, "Wait!",
            "Please click Generate to view your full script before deploying.");
        return;
    }

    QString ip = ui->entry_ip->text();
    QString user = ui->entry_user->text().trimmed();
    QString pass = ui->entry_ssh_pass->text();
    if (!hasReusableSession && isCiscoMode && user.isEmpty()) {
        QMessageBox::warning(this, "SSH Error", "Please enter the Cisco controller username.");
        return;
    }

    if (!hasReusableSession && pass.isEmpty()) {
        QMessageBox::warning(this, "SSH Error", "Please enter the controller password.");
        return;
    }

    setOutputText(QString(), "Deployment Console");

    // FIX (UI/UX): Show "DEPLOYING..." while the operation is in progress
    // so the user has clear visual feedback that something is happening.
    ui->btn_deploy->setEnabled(false);
    ui->btn_deploy->setText("DEPLOYING...");
    this->statusBar()->showMessage(
        isCiscoMode
        ? "Deploying to Cisco controller..."
        : "Deploying to Aruba controller...",
        10000
    );

    if (hasReusableSession) {
        appendOutputText(
            isCiscoMode
            ? ">>> Using the active Cisco session from CONNECT. No new login will be attempted."
            : ">>> Using the active Aruba session. No new login will be attempted.",
            "Deployment Console");
        QMetaObject::invokeMethod(persistentSessionManager, "deployPersistent", Qt::QueuedConnection,
            Q_ARG(QString, script));
        return;
    }

    if (isCiscoMode) {
        appendOutputText(">>> ERROR: No active Cisco session is connected. Click CONNECT first, then deploy.", "Deployment Console");
        ui->btn_deploy->setText("DEPLOY");
        updateCiscoConnectionUi();
        this->statusBar()->showMessage("Connect to Cisco before deploying.", 5000);
        return;
    }

    QString trustError;
    DeploymentOptions deployOptions;
    deployOptions.sendInitialEnter = isCiscoMode;
    deployOptions.useCiscoShellLogin = isCiscoMode;
    if (!ensureTrustedHost(this, ip, user, deployOptions, &trustError)) {
        appendOutputText(">>> ERROR: " + trustError, "Deployment Console");
        ui->btn_deploy->setEnabled(true);
        ui->btn_deploy->setText("DEPLOY");
        updateCiscoConnectionUi();
        this->statusBar()->showMessage("Deployment cancelled.", 5000);
        return;
    }

    pendingPersistentDeploy = true;
    pendingPersistentDeployIsCiscoMode = isCiscoMode;
    pendingPersistentDeployScript = script;
    appendOutputText(isCiscoMode
        ? ">>> Connecting persistent Cisco session for deployment..."
        : ">>> Connecting persistent Aruba session for deployment...",
        "Deployment Console");
    this->statusBar()->showMessage(
        isCiscoMode ? "Connecting Cisco session for deployment..." : "Connecting Aruba session for deployment...",
        10000);
    QMetaObject::invokeMethod(persistentSessionManager, "connectPersistent", Qt::QueuedConnection,
        Q_ARG(QString, ip),
        Q_ARG(QString, user),
        Q_ARG(QString, pass),
        Q_ARG(bool, isCiscoMode));
}

void ACS_Wynn_Builder::on_btn_test_ssh_clicked() {
    const bool isCiscoMode = modeTabs && modeTabs->currentIndex() == 1;

    if (!isCiscoMode)
        return;

    if (ciscoSessionConnected && ciscoSessionIsCiscoMode == isCiscoMode) {
        pendingAutoCiscoWlanIdSelection = false;
        QMetaObject::invokeMethod(persistentSessionManager, "disconnectPersistent", Qt::QueuedConnection);
        updateCiscoConnectionUi();
        this->statusBar()->showMessage(isCiscoMode ? "Cisco controller disconnected." : "Aruba controller disconnected.", 5000);
        return;
    }

    const QString ip = ui->entry_ip->text().trimmed();
    const QString user = ui->entry_user->text().trimmed();
    const QString pass = ui->entry_ssh_pass->text();

    if (ip.isEmpty()) {
        QMessageBox::warning(this, "SSH Error", "Please enter the controller IP address.");
        return;
    }

    if (user.isEmpty()) {
        QMessageBox::warning(this, "SSH Error", "Please enter the Cisco controller username.");
        return;
    }

    if (pass.isEmpty()) {
        QMessageBox::warning(this, "SSH Error", "Please enter the controller password.");
        return;
    }

    setOutputText(QString(), "Deployment Console");
    ui->text_output->appendPlainText(isCiscoMode
        ? ">>> Starting Cisco controller connection..."
        : ">>> Starting SSH connectivity test...");

    ui->btn_test_ssh->setEnabled(false);
    ui->btn_test_ssh->setText(isCiscoMode ? "CONNECTING..." : "TESTING...");
    ui->btn_deploy->setEnabled(false);
    pendingAutoCiscoWlanIdSelection = isCiscoMode;
    this->statusBar()->showMessage(
        isCiscoMode ? "Connecting to Cisco controller..." : "Testing Aruba SSH connectivity...",
        10000
    );

    DeploymentOptions deployOptions;
    deployOptions.sendInitialEnter = isCiscoMode;
    deployOptions.useCiscoShellLogin = isCiscoMode;
    deployOptions.testOnly = true;

    QString trustError;
    if (!ensureTrustedHost(this, ip, user, deployOptions, &trustError)) {
        pendingAutoCiscoWlanIdSelection = false;
        appendOutputText(">>> ERROR: " + trustError, "Deployment Console");
        ui->btn_test_ssh->setEnabled(true);
        updateCiscoConnectionUi();
        this->statusBar()->showMessage(isCiscoMode ? "Cisco connection cancelled." : "SSH test cancelled.", 5000);
        return;
    }

    QMetaObject::invokeMethod(persistentSessionManager, "connectPersistent", Qt::QueuedConnection,
        Q_ARG(QString, ip),
        Q_ARG(QString, user),
        Q_ARG(QString, pass),
        Q_ARG(bool, isCiscoMode));
}

void ACS_Wynn_Builder::on_btn_check_wlan_ids_clicked() {
    if (!(modeTabs && modeTabs->currentIndex() == 1))
        return;

    if (!ciscoSessionConnected || !ciscoSessionIsCiscoMode) {
        QMessageBox::warning(this, "Cisco Session", "Connect to the Cisco controller first.");
        return;
    }

    setOutputText(QString(), "Output");
    if (btnCheckWlanIds)
        btnCheckWlanIds->setEnabled(false);
    this->statusBar()->showMessage("Checking Cisco WLAN IDs...", 10000);
    QMetaObject::invokeMethod(persistentSessionManager, "checkWlanIdsPersistent", Qt::QueuedConnection);
}

void ACS_Wynn_Builder::on_btn_copy_clicked() {
    QGuiApplication::clipboard()->setText(ui->text_output->toPlainText());
    ui->btn_copy->setText("COPIED!");
    this->statusBar()->showMessage("Script copied to clipboard!", 3000);
    QTimer::singleShot(2000, this, [=]() { ui->btn_copy->setText("COPY"); });
}

void ACS_Wynn_Builder::on_btn_open_mremote_clicked() {
    const QString mremotePath = resolveMRemotePath();
    if (mremotePath.isEmpty()) {
        this->statusBar()->showMessage("mRemoteNG path was not selected.", 5000);
        return;
    }

    const QString currentScript = ui->text_output->toPlainText().trimmed();
    if (!currentScript.isEmpty() && !currentScript.contains("PREVIEW")) {
        QGuiApplication::clipboard()->setText(currentScript);
        handleSshLog(">>> Current script copied to clipboard for mRemote paste.");
    }

    if (!QProcess::startDetached(mremotePath, QStringList())) {
        QMessageBox::warning(this, "mRemoteNG", "Unable to open mRemoteNG from:\n" + mremotePath);
        return;
    }

    this->statusBar()->showMessage("mRemoteNG opened.", 5000);
}

void ACS_Wynn_Builder::on_btn_reset_clicked() {
    ui->entry_essid->clear();
    ui->entry_vlan->clear();
    ui->entry_psk->clear();
    ui->entry_role->setText("50Mbps-Per-User");

    ui->combo_auth->clear();
    ui->combo_auth->addItems({ "WPA2-PSK", "Open" });
    ui->combo_auth->setCurrentIndex(0);

    for (int i = 0; i < tree_wynn->topLevelItemCount(); ++i) {
        QTreeWidgetItem* parent = tree_wynn->topLevelItem(i);
        for (int j = 0; j < parent->childCount(); ++j)
            parent->child(j)->setCheckState(0, Qt::Unchecked);
    }
    for (int i = 0; i < tree_stations->topLevelItemCount(); ++i) {
        QTreeWidgetItem* parent = tree_stations->topLevelItem(i);
        for (int j = 0; j < parent->childCount(); ++j)
            parent->child(j)->setCheckState(0, Qt::Unchecked);
    }

    search_wynn->clear();
    search_stations->clear();

    ui->chk_wynn_legacy->setChecked(false);
    ui->chk_encore_conv->setChecked(false);
    ui->chk_wynn_exp->setChecked(false);
    ui->chk_s_redrock->setChecked(false);
    ui->chk_s_gvr->setChecked(false);
    ui->chk_s_durango->setChecked(false);
    if (chkHideSsid) chkHideSsid->setChecked(false);
    if (chkArubaSplashPage) chkArubaSplashPage->setChecked(false);

    if (ciscoCompanyName) ciscoCompanyName->clear();
    if (ciscoRemovalDate) ciscoRemovalDate->clear();
    if (ciscoSsid) ciscoSsid->clear();
    if (ciscoPassword) ciscoPassword->clear();
    if (ciscoWlanId) ciscoWlanId->clear();
    if (ciscoMaxClients) ciscoMaxClients->setText("10");
    if (ciscoVlan) ciscoVlan->setCurrentText(QString());
    if (search_cisco_wynn) search_cisco_wynn->clear();
    if (chk_cisco_legacy) chk_cisco_legacy->setChecked(false);
    if (chk_cisco_encore) chk_cisco_encore->setChecked(false);
    if (chk_cisco_expansion) chk_cisco_expansion->setChecked(false);
    if (chkCiscoSplashPage) chkCiscoSplashPage->setChecked(false);
    if (tree_cisco_wynn) {
        for (int i = 0; i < tree_cisco_wynn->topLevelItemCount(); ++i) {
            QTreeWidgetItem* parent = tree_cisco_wynn->topLevelItem(i);
            for (int j = 0; j < parent->childCount(); ++j)
                parent->child(j)->setCheckState(0, Qt::Unchecked);
        }
    }

    on_siteTabs_currentChanged(ui->siteTabs->currentIndex());
    syncModeUi();
    if (profilePresetCombo && profilePresetCombo->currentText() != "Custom")
        applyProfilePreset(profilePresetCombo->currentText(), false);
    updateLivePreview();
    this->statusBar()->showMessage("Reset Complete.", 3000);
}

void ACS_Wynn_Builder::on_btn_wizard_clicked() {
    QWizard wizard(this);
    wizard.setWindowTitle((modeTabs && modeTabs->currentIndex() == 1)
        ? "Cisco Deployment Wizard"
        : "ACS Deployment Wizard");
    wizard.resize(650, 700);
    wizard.setWizardStyle(QWizard::ModernStyle);
    wizard.setButtonText(QWizard::CommitButton, "DEPLOY CONFIGURATION");

    wizard.setStyleSheet(R"(
        QWizard, QWizardPage { background-color: #111827; }
        QLabel { color: #E5E7EB; font-family: 'Segoe UI'; font-size: 14px; }
        QLineEdit, QComboBox, QPlainTextEdit, QTreeWidget {
            background-color: #030712; color: #F9FAFB;
            border: 1px solid #374151; border-radius: 4px;
            padding: 8px; font-family: 'Segoe UI';
        }
        QComboBox QAbstractItemView {
            background-color: #030712; color: #F9FAFB;
            selection-background-color: #0078D4;
            border: 1px solid #374151; outline: none;
        }
        QTreeWidget::item { padding: 5px; margin-bottom: 2px; border-radius: 4px; }
        QTreeWidget::item:hover { background-color: #374151; }
        QTreeWidget::item:selected { background-color: transparent; }
        QTreeWidget::indicator {
            margin-right: 8px; width: 16px; height: 16px;
            border: 1px solid #6B7280; background-color: #030712; border-radius: 3px;
        }
        QTreeWidget::indicator:checked { background-color: #0078D4; border: 1px solid #0078D4; }
        QPushButton {
            background-color: #374151; color: #FFFFFF;
            border: none; padding: 8px 20px; border-radius: 6px; font-weight: bold;
        }
        QPushButton:hover { background-color: #4B5563; }
    )");

    if (modeTabs && modeTabs->currentIndex() == 1) {
        const bool hasActiveCiscoConnection = hasActiveCiscoSession();
        QStringList interfaceOptions = apData.ciscoInterfaces;
        for (const QString& fallbackInterface : defaultCiscoInterfaceList()) {
            if (!interfaceOptions.contains(fallbackInterface))
                interfaceOptions << fallbackInterface;
        }
        interfaceOptions.sort();

        CiscoConnectWizardPage* connectPage = nullptr;
        const QString detailsTitle = hasActiveCiscoConnection
            ? "Step 1: Cisco WLAN Details"
            : "Step 2: Cisco WLAN Details";
        const QString groupsTitle = hasActiveCiscoConnection
            ? "Step 2: Cisco AP Group Selection"
            : "Step 3: Cisco AP Group Selection";
        const QString previewTitle = hasActiveCiscoConnection
            ? "Step 3: Cisco Configuration Preview"
            : "Step 4: Cisco Configuration Preview";
        const QString deployTitle = hasActiveCiscoConnection
            ? "Step 4: Cisco Deployment"
            : "Step 5: Cisco Deployment";

        if (!hasActiveCiscoConnection)
            connectPage = new CiscoConnectWizardPage(this, "Step 1: Cisco Controller Connection");

        CiscoWizardPage1* p1 = new CiscoWizardPage1(interfaceOptions, detailsTitle);
        CiscoWizardPage2* p2 = new CiscoWizardPage2(apData, groupsTitle);
        CiscoWizardPage3* p3 = new CiscoWizardPage3(p2, previewTitle);

        DeploymentOptions deployOptions;
        deployOptions.sendInitialEnter = true;
        deployOptions.useCiscoShellLogin = true;
        WizardPage6* deployPage = new WizardPage6(
            p3->configPreview,
            this,
            deployOptions,
            deployTitle
        );

        if (connectPage)
            wizard.addPage(connectPage);
        wizard.addPage(p1);
        wizard.addPage(p2);
        wizard.addPage(p3);
        wizard.addPage(deployPage);

        wizard.setField("cisco_company", ciscoCompanyName ? ciscoCompanyName->text() : QString());
        wizard.setField("cisco_removal", ciscoRemovalDate ? ciscoRemovalDate->text() : QString());
        wizard.setField("cisco_ssid", ciscoSsid ? ciscoSsid->text() : QString());
        wizard.setField("cisco_psk", ciscoPassword ? ciscoPassword->text() : QString());
        wizard.setField("cisco_wlan_id", ciscoWlanId ? ciscoWlanId->text() : QString());
        wizard.setField("cisco_max_clients", ciscoMaxClients ? ciscoMaxClients->text() : QString());
        wizard.setField("cisco_vlan", ciscoVlan ? ciscoVlan->currentText() : QString());
        wizard.setField("ip", apData.ciscoControllerIp);
        wizard.setField("user", ui->entry_user->text().trimmed());
        wizard.setField("pass", ui->entry_ssh_pass->text());

        if (chk_cisco_legacy) p2->chkLegacy->setChecked(chk_cisco_legacy->isChecked());
        if (chk_cisco_encore) p2->chkEncore->setChecked(chk_cisco_encore->isChecked());
        if (chk_cisco_expansion) p2->chkExpansion->setChecked(chk_cisco_expansion->isChecked());

        if (tree_cisco_wynn) {
            for (int i = 0; i < tree_cisco_wynn->topLevelItemCount(); ++i) {
                QTreeWidgetItem* sourceParent = tree_cisco_wynn->topLevelItem(i);
                for (int j = 0; j < sourceParent->childCount(); ++j) {
                    QTreeWidgetItem* sourceChild = sourceParent->child(j);
                    if (sourceChild->checkState(0) != Qt::Checked)
                        continue;
                    p2->initialCheckedGroups << sourceChild->data(0, Qt::UserRole).toString();
                }
            }
        }

        p2->initializePage();

        if (wizard.exec() == QDialog::Accepted)
            setOutputText(p3->configPreview->toPlainText(), "Output");
        return;
    }

    // FIX (Architecture): Pass apData copies so wizard pages are fully decoupled
    // from the main window — no qobject_cast, no public member access.
    WizardPage4* p4 = new WizardPage4(apData);
    WizardPage5* p5 = new WizardPage5(p4, apData);

    wizard.addPage(new WizardPage1);
    wizard.addPage(new WizardPage2);
    wizard.addPage(new WizardPageSite);
    wizard.addPage(p4);
    wizard.addPage(new WizardPageTarget(apData));
    wizard.addPage(p5);
    wizard.addPage(new WizardPage6(p5->configPreview, this));

    wizard.setField("site", ui->siteTabs->currentIndex());
    wizard.setField("ip", ui->entry_ip->text());
    wizard.setField("user", ui->entry_user->text().trimmed());
    wizard.setField("pass", ui->entry_ssh_pass->text());

    if (wizard.exec() == QDialog::Accepted)
        setOutputText(p5->configPreview->toPlainText(), "Output");
}

// ====================================================
// SITE TAB CHANGED
// ====================================================

void ACS_Wynn_Builder::on_siteTabs_currentChanged(int index) {
    // FIX (Architecture): IPs and paths come from apData (loaded from JSON),
    // not hardcoded string literals.
    if (index == 0) {
        ui->entry_ip->setText(apData.wynnControllerIp);
        ui->entry_path->setText(apData.wynnConfigPath);
    }
    else {
        ui->entry_ip->setText(apData.stationsControllerIp);
        ui->entry_path->setText(apData.stationsConfigPath);
    }

    QString siteTheme;
    if (index == 0) {
        siteTheme = R"(
            #siteTabs QWidget { background-color: #161412; }
            #siteTabs QTabBar::tab:selected { color: #D4AF37; border-bottom: 2px solid #D4AF37; }
            #siteTabs QTreeWidget, #siteTabs QListWidget { border: 1px solid #3A322B; background-color: #110F0E; }
            #siteTabs QTreeWidget::item:selected { background-color: rgba(212,175,55,0.15); color: #D4AF37; border-left: 2px solid #D4AF37; }
            #siteTabs QCheckBox::indicator:checked { background-color: #D4AF37; border: 1px solid #D4AF37; }
            #siteTabs QLabel { color: #8C734B; }
        )";
    }
    else {
        siteTheme = R"(
            #siteTabs QWidget { background-color: #0F1115; }
            #siteTabs QTabBar::tab:selected { color: #EF4444; border-bottom: 2px solid #EF4444; }
            #siteTabs QTreeWidget, #siteTabs QListWidget { border: 1px solid #2D1B1B; background-color: #0B0C0E; }
            #siteTabs QTreeWidget::item:selected { background-color: rgba(239,68,68,0.15); color: #F87171; border-left: 2px solid #EF4444; }
            #siteTabs QCheckBox::indicator:checked { background-color: #EF4444; border: 1px solid #EF4444; }
            #siteTabs QLabel { color: #9CA3AF; }
        )";
    }

    ui->siteTabs->setStyleSheet(siteTheme);
    updateBuyoutOptionsUi();
    if (!modeTabs || modeTabs->currentIndex() == 0)
        updateLivePreview();
    refreshWorkspaceSummary();
}

void ACS_Wynn_Builder::syncModeUi() {
    const bool isCiscoMode = modeTabs && modeTabs->currentIndex() == 1;
    const int minimumWindowHeight = isCiscoMode ? 680 : 640;

    ui->card1->setVisible(!isCiscoMode);
    ui->siteTabs->setVisible(!isCiscoMode);
    ui->card4->setVisible(true);
    ui->btn_wizard->setVisible(true);
    ui->btn_generate->setVisible(!isCiscoMode);
    ui->btn_remove->setVisible(!isCiscoMode);
    ui->btn_generate_cisco->setVisible(isCiscoMode);

    ui->btn_wizard->setText(isCiscoMode ? "CISCO WIZARD" : "WIZARD");
    ui->btn_generate_cisco->setText(isCiscoMode ? "GENERATE" : "GEN CISCO");
    ui->btn_copy->setText("COPY");
    ui->btn_deploy->setText("DEPLOY");
    ui->btn_deploy->setEnabled(true);
    if (ui->btn_open_mremote)
        ui->btn_open_mremote->hide();
    if (ui->label_ip) ui->label_ip->setVisible(!isCiscoMode);
    if (ui->entry_ip) ui->entry_ip->setVisible(!isCiscoMode);
    if (ui->label_user) ui->label_user->setVisible(!isCiscoMode);
    if (ui->entry_user) ui->entry_user->setVisible(!isCiscoMode);
    if (ui->label_pass) ui->label_pass->setVisible(!isCiscoMode);
    if (ui->entry_ssh_pass) ui->entry_ssh_pass->setVisible(!isCiscoMode);
    updateCiscoConnectionUi();

    if (ciscoFrame)
        ciscoFrame->setVisible(isCiscoMode);

    if (isCiscoMode) {
        ui->entry_ip->setText(apData.ciscoControllerIp);
        ui->entry_ip->setReadOnly(true);
        if (profilePresetFrame)
            profilePresetFrame->show();
    }
    else {
        ui->entry_ip->setReadOnly(false);
        on_siteTabs_currentChanged(ui->siteTabs->currentIndex());
        if (profilePresetFrame)
            profilePresetFrame->show();
    }
    setMinimumHeight(qMax(minimumHeight(), minimumWindowHeight));
    updateBuyoutOptionsUi();
    updateApGroupSelectionSummary();
    refreshWorkspaceSummary();
}

void ACS_Wynn_Builder::updateApGroupSelectionSummary() {
    if (!apGroupSummaryLabel)
        return;

    const bool isCiscoMode = modeTabs && modeTabs->currentIndex() == 1;
    if (isCiscoMode) {
        const QStringList groups = getCiscoWynnApGroups();
        apGroupSummaryLabel->setText("Cisco AP groups selected: " + QString::number(groups.size()));
    }
    else {
        QStringList groups = getSelectedGroups();
        groups.removeAll("default");
        const QString siteLabel = ui->siteTabs->currentIndex() == 0 ? "Wynn" : "Stations";
        apGroupSummaryLabel->setText(siteLabel + " AP groups selected: " + QString::number(groups.size()));
    }
    refreshWorkspaceSummary();
}

void ACS_Wynn_Builder::updateBuyoutOptionsUi() {
    const bool isCiscoMode = modeTabs && modeTabs->currentIndex() == 1;
    const bool isWynnSite = ui->siteTabs && ui->siteTabs->currentIndex() == 0;

    if (buyoutOptionsFrame)
        buyoutOptionsFrame->setVisible(true);
    if (wynnBuyoutOptionsRow)
        wynnBuyoutOptionsRow->setVisible(!isCiscoMode && isWynnSite);
    if (stationsBuyoutOptionsRow)
        stationsBuyoutOptionsRow->setVisible(!isCiscoMode && !isWynnSite);
    if (ciscoBuyoutOptionsRow)
        ciscoBuyoutOptionsRow->setVisible(isCiscoMode);
}

void ACS_Wynn_Builder::showApGroupSelectorDialog(const QString& title, QTreeWidget* sourceTree) {
    if (!sourceTree)
        return;

    QDialog dialog(this);
    dialog.setWindowTitle(title);
    dialog.resize(560, 620);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    QLineEdit* searchBox = new QLineEdit(&dialog);
    searchBox->setPlaceholderText("Search AP Groups...");
    QTreeWidget* dialogTree = new QTreeWidget(&dialog);
    dialogTree->setHeaderHidden(true);
    dialogTree->setAlternatingRowColors(sourceTree->alternatingRowColors());

    for (int i = 0; i < sourceTree->topLevelItemCount(); ++i) {
        QTreeWidgetItem* sourceParent = sourceTree->topLevelItem(i);
        QTreeWidgetItem* dialogParent = sourceParent->clone();
        dialogTree->addTopLevelItem(dialogParent);
        dialogParent->setHidden(false);
        dialogParent->setExpanded(false);
        for (int j = 0; j < dialogParent->childCount(); ++j)
            dialogParent->child(j)->setHidden(false);
    }

    connect(searchBox, &QLineEdit::textChanged, &dialog, [this, dialogTree](const QString& text) {
        executeSearch(dialogTree, text);
    });

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    layout->addWidget(searchBox);
    layout->addWidget(dialogTree, 1);
    layout->addWidget(buttonBox);

    if (dialog.exec() != QDialog::Accepted)
        return;

    for (int i = 0; i < sourceTree->topLevelItemCount() && i < dialogTree->topLevelItemCount(); ++i) {
        QTreeWidgetItem* sourceParent = sourceTree->topLevelItem(i);
        QTreeWidgetItem* dialogParent = dialogTree->topLevelItem(i);
        for (int j = 0; j < sourceParent->childCount() && j < dialogParent->childCount(); ++j) {
            sourceParent->child(j)->setCheckState(0, dialogParent->child(j)->checkState(0));
        }
    }

    updateLivePreview();
}

void ACS_Wynn_Builder::applyProfilePreset(const QString& presetName, bool persistSelection) {
    if (persistSelection) {
        QSettings settings("ACS", "ACS Tool");
        settings.setValue("profiles/selected_preset", presetName);
    }

    if (presetName == "Aruba - Wynn") {
        if (modeTabs)
            modeTabs->setCurrentIndex(0);
        ui->siteTabs->setCurrentIndex(0);
        ui->entry_ip->setText(apData.wynnControllerIp);
        ui->entry_path->setText(apData.wynnConfigPath);
        ui->entry_role->setText("50Mbps-Per-User");
    }
    else if (presetName == "Aruba - Stations") {
        if (modeTabs)
            modeTabs->setCurrentIndex(0);
        ui->siteTabs->setCurrentIndex(1);
        ui->entry_ip->setText(apData.stationsControllerIp);
        ui->entry_path->setText(apData.stationsConfigPath);
        ui->entry_role->setText("50Mbps-Per-User");
    }
    else if (presetName == "Cisco - Wynn") {
        if (modeTabs)
            modeTabs->setCurrentIndex(1);
        ui->entry_ip->setText(apData.ciscoControllerIp);
        ui->entry_ip->setReadOnly(true);
        if (ciscoMaxClients && ciscoMaxClients->text().trimmed().isEmpty())
            ciscoMaxClients->setText("10");
    }

    syncModeUi();
    updateLivePreview();
    refreshWorkspaceSummary();
}

void ACS_Wynn_Builder::applyAdaptiveTheme() {
    const QPalette palette = this->palette();
    const bool darkMode = palette.color(QPalette::Window).lightness() < 128;

    setStyleSheet(buildAppStyleSheet(darkMode));

    if (ui && ui->mainLayout) {
        ui->mainLayout->setSpacing(darkMode ? 12 : 10);
    }
}

// ====================================================
// JSON LOADER
// ====================================================

void ACS_Wynn_Builder::loadApGroupsFromJson() {
    QString configPath = apGroupsConfigPath();
    QFile file(configPath);

    if (file.exists() && file.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
        QJsonObject   obj = doc.object();

        auto extractList = [&](const QString& key) {
            QStringList list;
            for (const QJsonValue& val : obj[key].toArray())
                list << val.toString();
            return list;
            };

        apData.wynnLegacy = extractList("wynn_legacy");
        apData.encoreMain = extractList("encore_main");
        apData.wynnExpansion = extractList("wynn_expansion");
        apData.wynnMisc = extractList("wynn_misc");
        apData.redRock = extractList("red_rock");
        apData.gvr = extractList("gvr");
        apData.durango = extractList("durango");
        apData.stationsMisc = extractList("stations_misc");
        apData.ciscoInterfaces = extractList("cisco_interfaces");
        if (apData.ciscoInterfaces.isEmpty())
            apData.ciscoInterfaces = extractList("cisco_vlans");
        for (const QString& fallbackInterface : defaultCiscoInterfaceList()) {
            if (!apData.ciscoInterfaces.contains(fallbackInterface))
                apData.ciscoInterfaces << fallbackInterface;
        }
        apData.ciscoInterfaces.sort();

        // FIX (Architecture): Load IPs and paths from JSON if present;
        // fall back to the struct's default values if keys are absent.
        if (obj.contains("wynn_controller_ip"))
            apData.wynnControllerIp = obj["wynn_controller_ip"].toString();
        if (obj.contains("stations_controller_ip"))
            apData.stationsControllerIp = obj["stations_controller_ip"].toString();
        if (obj.contains("cisco_controller_ip"))
            apData.ciscoControllerIp = obj["cisco_controller_ip"].toString();
        if (obj.contains("wynn_config_path"))
            apData.wynnConfigPath = obj["wynn_config_path"].toString();
        if (obj.contains("stations_config_path"))
            apData.stationsConfigPath = obj["stations_config_path"].toString();
        if (obj.contains("updater_enabled"))
            updateConfig.enabled = obj["updater_enabled"].toBool(true);
        if (obj.contains("updater_metadata_url"))
            updateConfig.metadataUrl = QUrl(obj["updater_metadata_url"].toString().trimmed());
        if (obj.contains("updater_package_url"))
            updateConfig.packageUrl = QUrl(obj["updater_package_url"].toString().trimmed());
        if (obj.contains("updater_expected_sha256"))
            updateConfig.expectedSha256 = obj["updater_expected_sha256"].toString().trimmed().toLower();
        if (obj.contains("updater_allowed_hosts")) {
            for (const QJsonValue& val : obj["updater_allowed_hosts"].toArray()) {
                const QString host = val.toString().trimmed().toLower();
                if (!host.isEmpty())
                    updateConfig.allowedHosts << host;
            }
            updateConfig.allowedHosts.removeDuplicates();
        }

        file.close();
    }
    else {
        // Fallback defaults (same as before, but stored in apData).
        apData.wynnLegacy = { "Alsace", "Chambertin", "Lafite_1|2|3", "Lafite_4|7|9", "Lafite_5|Stage", "Lafite_6|8", "Lafite_GreenRoom", "Lafite_Latour|Hallways", "Lafleur", "Latache", "Latour_1|4", "Latour_2|Stage", "Latour_3", "Latour_5|6|7", "Latour_GreenRoom", "Margaux", "Montrachet", "Mouton", "Palmer", "Petrus", "Registration_1", "Registration_2", "Registration_3", "Registration_4", "St_Julian", "St_Pierre", "Sunset_Terrace", "Wing-Lei" };
        apData.encoreMain = { "Bach", "Beethoven", "Brahms", "Chopin", "Debussy", "Encore_B_1|2|3", "Encore_B_4|5|6", "Encore_B_7|5|8", "Encore_Ballroom_Hallway", "Handel", "Mozart", "Puccini", "Ravel", "Registration_5", "Registration_6", "Schubert", "Strauss", "Vivaldi" };
        apData.wynnExpansion = { "Avignon", "Avize", "Bandol", "Bollinger", "Castillon", "Convention_Lounge", "Cristal_1|3", "Cristal_2|4", "Cristal_5|7", "Cristal_6|8", "Cristal_GreenRoom", "Cristal_Hallway", "Cristal_Terrace", "Epernay", "Fleurie", "Hermitage", "Krug", "Meursault", "Moet", "Mumm", "Musigny", "New_Wynn_BOH", "Pavillion/Garden", "Pomerol", "Registration_Desk_A", "Registration_Desk_B", "Reims", "Roederer", "Rotunda_Down", "Rotunda_Up", "Ruinart" };
        apData.wynnMisc = { "ACS-Office-TestAPs", "B10AP", "C4", "Catering_Office", "Delilah", "EncoreBusinessCenter", "Graton-Convention", "NoAuthApGroup", "WYNN|ENCORE-THEATRE", "WYNN|ENCORE-THEATRE|LOBBY", "WynnBusinessCenter", "XS_Nightclub", "default" };
        apData.redRock = { "ACS-RR-Office", "RR-Charleston_Ballroom", "RR-Pavilion_Ballroom", "RR-RedRock_Ballroom", "RR-Registration Area", "RR-Strip_Canyon_View", "RR-Summerlin_Ballroom", "RR-Tbones_Crimson", "RR_Veranda_Rooms" };
        apData.gvr = { "ACS_GVR_Office", "GVR-8200Suite", "GVR-Boardroom", "GVR-Cielos", "GVR-Conv-Libraryrooms", "GVR-Convention", "GVR-DelRoomsandLuna", "GVR-ElViento", "GVR-EstanciaBallroom", "GVR-GrandBallroom", "GVR-GVR PRECON", "GVR-LaCascada", "GVR-LaSirena", "GVR-Tech-Office" };
        apData.durango = { "DUR-Agave-BR-A", "DUR-Agave-BR-B", "DUR-Agave-BR-C", "DUR-Agave-BR-D", "DUR-Agave-BR-E", "DUR-Agave-BR-F", "DUR-Boardroom", "DUR-Cactus", "DUR-Lantana-A", "DUR-Lantana-B", "DUR-Pre-Function", "DUR-Sauguaro", "DURANGO|ACS" };
        apData.stationsMisc = { ".Boulder-Convention", ".FiestaHenderson-Convention", ".Palace-Convention", ".SantaFe-Convention", ".Sunset-Convention", ".Texas-Convention", "Boulder-Convention", "Palace-Convention", "SantaFe-Convention", "Sunset-Convention", "default" };
        apData.ciscoInterfaces = defaultCiscoInterfaceList();
        updateConfig.enabled = true;
        updateConfig.metadataUrl = QUrl("https://api.github.com/repos/congiirepair/ACS_Wynn_Builder/releases/latest");
        updateConfig.packageUrl = QUrl("https://github.com/congiirepair/ACS_Wynn_Builder/releases/download/1.0.8/ACS_Wynn_Builder_Update.zip");
        updateConfig.expectedSha256 = "7232b492a7adb838841f8540d0a7618e957b7a933b44d9cbb6a6ef4dac2b0d0d";
        updateConfig.allowedHosts = {
            "api.github.com",
            "gist.githubusercontent.com",
            "github.com",
            "githubusercontent.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com"
        };

        // Write defaults out to JSON so future launches load from file,
        // including the new IP/path fields.
        QJsonObject obj;
        auto toArray = [](const QStringList& list) {
            QJsonArray arr;
            for (const auto& s : list) arr.append(s);
            return arr;
            };
        obj["wynn_legacy"] = toArray(apData.wynnLegacy);
        obj["encore_main"] = toArray(apData.encoreMain);
        obj["wynn_expansion"] = toArray(apData.wynnExpansion);
        obj["wynn_misc"] = toArray(apData.wynnMisc);
        obj["red_rock"] = toArray(apData.redRock);
        obj["gvr"] = toArray(apData.gvr);
        obj["durango"] = toArray(apData.durango);
        obj["stations_misc"] = toArray(apData.stationsMisc);
        obj["cisco_interfaces"] = toArray(apData.ciscoInterfaces);
        obj["cisco_vlans"] = toArray(apData.ciscoInterfaces);
        obj["wynn_controller_ip"] = apData.wynnControllerIp;
        obj["stations_controller_ip"] = apData.stationsControllerIp;
        obj["cisco_controller_ip"] = apData.ciscoControllerIp;
        obj["wynn_config_path"] = apData.wynnConfigPath;
        obj["stations_config_path"] = apData.stationsConfigPath;
        obj["updater_enabled"] = updateConfig.enabled;
        obj["updater_metadata_url"] = updateConfig.metadataUrl.toString();
        obj["updater_package_url"] = updateConfig.packageUrl.toString();
        obj["updater_expected_sha256"] = updateConfig.expectedSha256;

        QJsonArray updateHosts;
        for (const QString& host : updateConfig.allowedHosts)
            updateHosts.append(host);
        obj["updater_allowed_hosts"] = updateHosts;

        QFileInfo configInfo(configPath);
        QDir().mkpath(configInfo.absolutePath());
        if (file.open(QIODevice::WriteOnly)) {
            file.write(QJsonDocument(obj).toJson());
            file.close();
        }
    }
}

void ACS_Wynn_Builder::populateTree(QTreeWidget* tree, int siteIndex) {
    tree->clear();
    if (siteIndex == 0) {
        addTreeCategory(tree, "--- WYNN LEGACY ---", apData.wynnLegacy, "#0078D4");
        addTreeCategory(tree, "--- ENCORE ---", apData.encoreMain, "#0078D4");
        addTreeCategory(tree, "--- EXPANSION ---", apData.wynnExpansion, "#60A5FA");
        addTreeCategory(tree, "--- MISC ---", apData.wynnMisc, "#60A5FA");
    }
    else {
        addTreeCategory(tree, "--- RED ROCK ---", apData.redRock, "#EF4444");
        addTreeCategory(tree, "--- GVR ---", apData.gvr, "#EF4444");
        addTreeCategory(tree, "--- DURANGO ---", apData.durango, "#EF4444");
        addTreeCategory(tree, "--- OTHER SITES ---", apData.stationsMisc, "#F87171");
    }
}

QString ACS_Wynn_Builder::apGroupsConfigPath() const {
    const QString appDirPath = QDir(QCoreApplication::applicationDirPath()).filePath("ap_groups.json");
    if (QFileInfo::exists(appDirPath))
        return appDirPath;

    const QString appConfigDir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    if (!appConfigDir.isEmpty()) {
        const QString userConfigPath = QDir(appConfigDir).filePath("ap_groups.json");
        if (QFileInfo::exists(userConfigPath))
            return userConfigPath;
        return userConfigPath;
    }

    return appDirPath;
}

bool ACS_Wynn_Builder::isTrustedUpdateUrl(const QUrl& url, const QStringList& extraAllowedHosts) const {
    if (!updateConfig.enabled || !url.isValid())
        return false;

    if (url.scheme().compare("https", Qt::CaseInsensitive) != 0)
        return false;

    const QString host = url.host().trimmed().toLower();
    if (host.isEmpty())
        return false;

    QStringList allowedHosts = updateConfig.allowedHosts;
    allowedHosts << extraAllowedHosts;
    if (updateConfig.metadataUrl.isValid())
        allowedHosts << updateConfig.metadataUrl.host().trimmed().toLower();
    if (updateConfig.packageUrl.isValid())
        allowedHosts << updateConfig.packageUrl.host().trimmed().toLower();

    allowedHosts.removeAll(QString());
    allowedHosts.removeDuplicates();

    for (const QString& allowedHost : allowedHosts) {
        if (allowedHost.isEmpty())
            continue;

        if (host == allowedHost || host.endsWith("." + allowedHost))
            return true;
    }

    return false;
}

bool ACS_Wynn_Builder::resolveUpdateMetadata(const QByteArray& metadataBytes,
    QString* latestVersion,
    QUrl* packageUrl,
    QString* expectedSha256,
    QStringList* allowedHosts) const {
    if (!latestVersion || !packageUrl || !expectedSha256 || !allowedHosts)
        return false;

    *latestVersion = QString::fromUtf8(metadataBytes).trimmed();
    *packageUrl = updateConfig.packageUrl;
    *expectedSha256 = updateConfig.expectedSha256.trimmed().toLower();
    expectedSha256->remove(QRegularExpression("\\s+"));
    *allowedHosts = updateConfig.allowedHosts;

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(metadataBytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (latestVersion->startsWith('v', Qt::CaseInsensitive) && latestVersion->size() > 1 && latestVersion->at(1).isDigit())
            latestVersion->remove(0, 1);

        if (!latestVersion->isEmpty()) {
            static const QRegularExpression githubDownloadPattern(
                "^/([^/]+)/([^/]+)/releases/download/([^/]+)/([^/]+)$");
            const QRegularExpressionMatch match = githubDownloadPattern.match(packageUrl->path());
            if (match.hasMatch()) {
                const QString configuredTag = match.captured(3).trimmed();
                if (!configuredTag.isEmpty() && configuredTag != *latestVersion) {
                    if (!fetchGithubReleaseMetadataForVersion(*latestVersion, packageUrl, expectedSha256, allowedHosts)) {
                        *packageUrl = QUrl();
                        expectedSha256->clear();
                    }
                }
            }
        }

        return !latestVersion->isEmpty();
    }

    const QJsonObject obj = document.object();
    auto pullString = [&](const char* key) {
        return obj.value(QLatin1String(key)).toString().trimmed();
        };

    QString version = pullString("version");
    if (version.isEmpty())
        version = pullString("latest_version");
    if (version.isEmpty())
        version = pullString("tag_name");
    if (version.startsWith('v', Qt::CaseInsensitive) && version.size() > 1 && version.at(1).isDigit())
        version.remove(0, 1);
    if (!version.isEmpty())
        *latestVersion = version;

    QString checksum = pullString("sha256");
    if (checksum.isEmpty())
        checksum = pullString("package_sha256");
    if (checksum.isEmpty())
        checksum = pullString("updater_expected_sha256");
    checksum.remove(QRegularExpression("\\s+"));

    QString packageUrlString = pullString("package_url");
    if (packageUrlString.isEmpty())
        packageUrlString = pullString("download_url");
    if (packageUrlString.isEmpty())
        packageUrlString = pullString("browser_download_url");

    if (packageUrlString.isEmpty()) {
        QString configuredAssetName;
        if (updateConfig.packageUrl.isValid())
            configuredAssetName = QFileInfo(updateConfig.packageUrl.path()).fileName().trimmed();

        const QJsonArray assets = obj.value("assets").toArray();
        for (const QJsonValue& assetValue : assets) {
            const QJsonObject asset = assetValue.toObject();
            const QString assetName = asset.value("name").toString().trimmed();
            const QString assetUrl = asset.value("browser_download_url").toString().trimmed();
            QString assetDigest = asset.value("digest").toString().trimmed();
            if (assetUrl.isEmpty())
                continue;

            if (assetDigest.startsWith("sha256:", Qt::CaseInsensitive))
                assetDigest = assetDigest.mid(QString("sha256:").size());
            assetDigest.remove(QRegularExpression("\\s+"));

            const bool exactAssetMatch = !configuredAssetName.isEmpty()
                && QString::compare(assetName, configuredAssetName, Qt::CaseInsensitive) == 0;
            const bool usableFallbackAsset = assetName.endsWith(".zip", Qt::CaseInsensitive)
                || assetName.endsWith(".exe", Qt::CaseInsensitive)
                || assets.size() == 1;

            if (!exactAssetMatch && !usableFallbackAsset)
                continue;

            packageUrlString = assetUrl;
            if (checksum.isEmpty() && assetDigest.size() == 64)
                checksum = assetDigest.toLower();
            if (exactAssetMatch)
                break;
        }
    }

    if (!packageUrlString.isEmpty())
        *packageUrl = QUrl(packageUrlString);

    if (checksum.isEmpty()) {
        QString digest = pullString("digest");
        if (digest.startsWith("sha256:", Qt::CaseInsensitive))
            digest = digest.mid(QString("sha256:").size());
        digest.remove(QRegularExpression("\\s+"));
        if (digest.size() == 64)
            checksum = digest.toLower();
    }

    if (!checksum.isEmpty())
        *expectedSha256 = checksum.toLower();

    const QJsonArray hosts = obj.value("allowed_hosts").toArray();
    for (const QJsonValue& hostValue : hosts) {
        const QString host = hostValue.toString().trimmed().toLower();
        if (!host.isEmpty())
            allowedHosts->append(host);
    }
    if (obj.contains("assets")) {
        allowedHosts->append("api.github.com");
        allowedHosts->append("github.com");
        allowedHosts->append("githubusercontent.com");
        allowedHosts->append("objects.githubusercontent.com");
        allowedHosts->append("release-assets.githubusercontent.com");
    }
    allowedHosts->removeDuplicates();

    return !latestVersion->isEmpty();
}

bool ACS_Wynn_Builder::fetchGithubReleaseMetadataForVersion(const QString& version,
    QUrl* packageUrl,
    QString* expectedSha256,
    QStringList* allowedHosts) const {
    if (!packageUrl || !expectedSha256 || !allowedHosts || version.trimmed().isEmpty())
        return false;

    static const QRegularExpression githubDownloadPattern(
        "^/([^/]+)/([^/]+)/releases/download/([^/]+)/([^/]+)$");
    const QRegularExpressionMatch match = githubDownloadPattern.match(updateConfig.packageUrl.path());
    if (!match.hasMatch())
        return false;

    const QString owner = match.captured(1).trimmed();
    const QString repo = match.captured(2).trimmed();
    const QString assetName = match.captured(4).trimmed();
    if (owner.isEmpty() || repo.isEmpty() || assetName.isEmpty())
        return false;

    auto fetchReleaseByTag = [&](const QString& tag) -> bool {
        const QUrl apiUrl(QString("https://api.github.com/repos/%1/%2/releases/tags/%3")
            .arg(owner, repo, tag));

        QNetworkAccessManager manager;
        QNetworkRequest request(apiUrl);
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        request.setHeader(QNetworkRequest::UserAgentHeader, "ACS Tool Updater");

        QEventLoop loop;
        QTimer timeoutTimer;
        timeoutTimer.setSingleShot(true);

        QNetworkReply* reply = manager.get(request);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        QObject::connect(&timeoutTimer, &QTimer::timeout, &loop, &QEventLoop::quit);
        timeoutTimer.start(10000);
        loop.exec();

        if (timeoutTimer.isActive())
            timeoutTimer.stop();
        else
            reply->abort();

        if (reply->error() != QNetworkReply::NoError) {
            reply->deleteLater();
            return false;
        }

        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(reply->readAll(), &parseError);
        reply->deleteLater();
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
            return false;

        const QJsonObject obj = document.object();
        const QJsonArray assets = obj.value("assets").toArray();
        for (const QJsonValue& assetValue : assets) {
            const QJsonObject asset = assetValue.toObject();
            const QString candidateName = asset.value("name").toString().trimmed();
            const QString downloadUrl = asset.value("browser_download_url").toString().trimmed();
            QString digest = asset.value("digest").toString().trimmed();
            if (candidateName != assetName || downloadUrl.isEmpty())
                continue;

            if (digest.startsWith("sha256:", Qt::CaseInsensitive))
                digest = digest.mid(QString("sha256:").size());
            digest.remove(QRegularExpression("\\s+"));

            *packageUrl = QUrl(downloadUrl);
            // Never carry forward an older release checksum onto a newer asset.
            if (digest.size() == 64)
                *expectedSha256 = digest.toLower();
            else
                expectedSha256->clear();

            allowedHosts->append("api.github.com");
            allowedHosts->append("github.com");
            allowedHosts->append("githubusercontent.com");
            allowedHosts->append("objects.githubusercontent.com");
            allowedHosts->append("release-assets.githubusercontent.com");
            allowedHosts->removeDuplicates();
            return true;
        }

        return false;
        };

    if (fetchReleaseByTag(version))
        return true;

    if (!version.startsWith('v', Qt::CaseInsensitive) && fetchReleaseByTag("v" + version))
        return true;

    return false;
}

int ACS_Wynn_Builder::compareVersionStrings(const QString& left, const QString& right) const {
    auto normalize = [](QString version) {
        version = version.trimmed();
        if (version.startsWith('v', Qt::CaseInsensitive))
            version.remove(0, 1);
        return version;
        };

    const QStringList leftParts = normalize(left).split('.', Qt::SkipEmptyParts);
    const QStringList rightParts = normalize(right).split('.', Qt::SkipEmptyParts);
    const int count = qMax(leftParts.size(), rightParts.size());

    for (int i = 0; i < count; ++i) {
        bool leftOk = false;
        bool rightOk = false;
        const int leftValue = i < leftParts.size() ? leftParts[i].toInt(&leftOk) : 0;
        const int rightValue = i < rightParts.size() ? rightParts[i].toInt(&rightOk) : 0;

        if (leftOk && rightOk) {
            if (leftValue < rightValue)
                return -1;
            if (leftValue > rightValue)
                return 1;
            continue;
        }

        const QString leftPart = i < leftParts.size() ? leftParts[i] : QString();
        const QString rightPart = i < rightParts.size() ? rightParts[i] : QString();
        const int textCompare = QString::compare(leftPart, rightPart, Qt::CaseInsensitive);
        if (textCompare < 0)
            return -1;
        if (textCompare > 0)
            return 1;
    }

    return 0;
}

void ACS_Wynn_Builder::cleanupUpdateArtifacts() {
    if (downloadReply) {
        downloadReply->deleteLater();
        downloadReply = nullptr;
    }

    if (downloadFile) {
        if (downloadFile->isOpen())
            downloadFile->close();
        delete downloadFile;
        downloadFile = nullptr;
    }

}

// ====================================================
// AUTO UPDATER
// ====================================================

void ACS_Wynn_Builder::checkForUpdates(bool interactive) {
    updateCheckInteractive = interactive;
    if (btnUpdateApp)
        btnUpdateApp->setEnabled(false);

    if (!updateConfig.enabled) {
        if (btnUpdateApp)
            btnUpdateApp->setEnabled(true);
        if (interactive) {
            QMessageBox::information(this,
                "Updater Disabled",
                "The GitHub updater is currently disabled in configuration.");
        }
        return;
    }

    if (!isTrustedUpdateUrl(updateConfig.metadataUrl)) {
        if (btnUpdateApp)
            btnUpdateApp->setEnabled(true);
        if (interactive) {
            QMessageBox::warning(this,
                "Updater Configuration Error",
                "The release metadata URL is missing, not HTTPS, or not on the trusted host list.");
        } else {
            qWarning() << "Updater disabled: metadata URL is missing, non-HTTPS, or not allow-listed.";
        }
        return;
    }

    if (interactive)
        this->statusBar()->showMessage("Checking GitHub for the latest release...", 4000);

    QNetworkRequest request(updateConfig.metadataUrl);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setHeader(QNetworkRequest::UserAgentHeader, "ACS Tool Updater");
    versionCheckManager->get(request);
}

void ACS_Wynn_Builder::onVersionCheckComplete(QNetworkReply* reply) {
    const bool interactive = updateCheckInteractive;
    updateCheckInteractive = false;
    if (btnUpdateApp)
        btnUpdateApp->setEnabled(true);

    if (reply->error() != QNetworkReply::NoError || !isTrustedUpdateUrl(reply->url())) {
        if (interactive) {
            QMessageBox::warning(this,
                "Update Check Failed",
                reply->error() == QNetworkReply::NoError
                ? "The release metadata was returned from an untrusted URL."
                : "GitHub release metadata could not be fetched.\n\n" + reply->errorString());
        }
        reply->deleteLater();
        return;
    }

    QString latestVersion;
    QUrl packageUrl;
    QString expectedSha256;
    QStringList allowedHosts;
    const QByteArray metadataBytes = reply->readAll();
    if (!resolveUpdateMetadata(metadataBytes, &latestVersion, &packageUrl, &expectedSha256, &allowedHosts)) {
        if (interactive) {
            QMessageBox::warning(this,
                "Update Check Failed",
                "The latest release metadata could not be parsed into a version and downloadable asset.");
        }
        reply->deleteLater();
        return;
    }

    if (!latestVersion.isEmpty() && compareVersionStrings(latestVersion, CURRENT_VERSION) > 0) {
        if (!isTrustedUpdateUrl(packageUrl, allowedHosts) || expectedSha256.size() != 64) {
            if (interactive) {
                QMessageBox::warning(this,
                    "Update Check Blocked",
                    "An update was found, but the release asset is missing a trusted HTTPS download URL or SHA-256 digest.\n\n"
                    "Publish a release asset with a SHA-256 digest, or provide the checksum in ap_groups.json metadata.");
            } else {
                this->statusBar()->showMessage("A newer release is available, but the updater could not validate it.", 5000);
            }
            reply->deleteLater();
            return;
        }

        resolvedUpdateVersion = latestVersion;
        resolvedUpdatePackageUrl = packageUrl;
        resolvedUpdateSha256 = expectedSha256;
        resolvedUpdateAllowedHosts = allowedHosts;

        if (btnUpdateApp)
            btnUpdateApp->setText("UPDATE " + latestVersion);

        if (interactive) {
            const QMessageBox::StandardButton response = QMessageBox::question(
                this,
                "Install Update",
                QString("Current version: %1\nLatest GitHub release: %2\n\nDownload and install this update now?")
                .arg(CURRENT_VERSION, latestVersion),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::Yes);
            if (response == QMessageBox::Yes)
                startUpdateDownload(resolvedUpdatePackageUrl);
            else
                this->statusBar()->showMessage("Update is available whenever you're ready.", 4000);
        } else {
            this->statusBar()->showMessage("A newer release is available. Click the update button to install it.", 5000);
        }

        reply->deleteLater();
        return;
    }

    if (btnUpdateApp)
        btnUpdateApp->setText("CHECK UPDATES");
    if (interactive) {
        QMessageBox::information(this,
            "Up To Date",
            QString("This build is already current.\n\nInstalled version: %1").arg(CURRENT_VERSION));
    }

    reply->deleteLater();
}

void ACS_Wynn_Builder::startUpdateDownload(const QUrl& url) {
    if (!isTrustedUpdateUrl(url, resolvedUpdateAllowedHosts)) {
        QMessageBox::warning(this, "Update Blocked",
            "The update package URL is not trusted. Only allow-listed HTTPS endpoints are permitted.");
        return;
    }

    const QString packageName = QFileInfo(url.path()).fileName().trimmed();
    const bool packageIsExecutable = packageName.endsWith(".exe", Qt::CaseInsensitive);

    this->statusBar()->showMessage("Downloading update package. Please wait...", 0);
    QMessageBox::information(this,
        "Updating Application",
        QString("Version %1 is ready to install.\n\nThe application will download the release asset, close, replace the installed files, and relaunch automatically.")
            .arg(resolvedUpdateVersion.isEmpty() ? QString("update") : resolvedUpdateVersion));
    QApplication::processEvents();

    cleanupUpdateArtifacts();

    QString stagingBase = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (stagingBase.isEmpty())
        stagingBase = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    if (stagingBase.isEmpty())
        stagingBase = QCoreApplication::applicationDirPath();

    const QString stagingRoot = QDir(stagingBase).filePath("Updater");
    const QString payloadRoot = QDir(stagingRoot).filePath("payload");
    QDir().mkpath(stagingRoot);
    QDir(payloadRoot).removeRecursively();

    updateZipPath = QDir(stagingRoot).filePath(packageIsExecutable ? "update.exe" : "update.zip");
    updateBatchPath = QDir(stagingRoot).filePath("update.ps1");
    updateExtractPath = payloadRoot;

    QFile::remove(updateZipPath);
    QFile::remove(updateBatchPath);
    if (QFileInfo(updateZipPath).isDir())
        QDir(updateZipPath).removeRecursively();
    downloadFile = new QFile(updateZipPath);
    if (!downloadFile->open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "Update Failed",
            "The updater could not create the temporary package file.\n\nPath: " + updateZipPath +
            "\nError: " + downloadFile->errorString());
        cleanupUpdateArtifacts();
        return;
    }

    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setHeader(QNetworkRequest::UserAgentHeader, "ACS Tool Updater");
    downloadReply = downloadManager->get(request);
    connect(downloadReply, &QNetworkReply::readyRead, this, &ACS_Wynn_Builder::onDownloadReadyRead);
    connect(downloadReply, &QNetworkReply::finished, this, &ACS_Wynn_Builder::onDownloadFinished);
}

void ACS_Wynn_Builder::onDownloadReadyRead() {
    if (downloadFile && downloadReply)
        downloadFile->write(downloadReply->readAll());
}

void ACS_Wynn_Builder::onDownloadFinished() {
    if (!downloadReply || !downloadFile) {
        cleanupUpdateArtifacts();
        return;
    }

    downloadFile->write(downloadReply->readAll());
    downloadFile->close();

    if (downloadReply->error() != QNetworkReply::NoError || !isTrustedUpdateUrl(downloadReply->url(), resolvedUpdateAllowedHosts)) {
        QMessageBox::critical(this, "Update Failed",
            "The update download did not complete from a trusted HTTPS source.");
        QFile::remove(updateZipPath);
        cleanupUpdateArtifacts();
        return;
    }

    QString expectedSha256 = resolvedUpdateSha256.trimmed().toLower();
    expectedSha256.remove(QRegularExpression("\\s+"));
    if (expectedSha256.size() != 64) {
        QMessageBox::critical(this, "Update Failed",
            "The secure updater is missing a valid SHA-256 checksum.");
        QFile::remove(updateZipPath);
        cleanupUpdateArtifacts();
        return;
    }

    QFile packageCheck(updateZipPath);
    if (packageCheck.open(QIODevice::ReadOnly)) {
        QCryptographicHash hash(QCryptographicHash::Sha256);
        hash.addData(&packageCheck);
        packageCheck.close();

        const QString actualHash = QString::fromLatin1(hash.result().toHex());
        if (actualHash != expectedSha256) {
            QMessageBox::critical(this, "Update Failed",
                "Integrity check failed. The downloaded update file does not match "
                "the expected checksum and will not be applied.\n\n"
                "Please download the update manually from GitHub.");
            QFile::remove(updateZipPath);
            cleanupUpdateArtifacts();
            return;
        }
    }
    else {
        QMessageBox::critical(this, "Update Failed",
            "The updater could not reopen the downloaded package for checksum validation.");
        QFile::remove(updateZipPath);
        cleanupUpdateArtifacts();
        return;
    }

    QFile updateScript(updateBatchPath);
    if (!updateScript.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Update Failed",
            "The updater could not create the installer script.");
        QFile::remove(updateZipPath);
        cleanupUpdateArtifacts();
        return;
    }

    const QString nativePackagePath = QDir::toNativeSeparators(updateZipPath);
    const QString nativeExtractPath = QDir::toNativeSeparators(updateExtractPath);
    const QString nativeAppDir = QDir::toNativeSeparators(QCoreApplication::applicationDirPath());
    const QString nativeTargetExePath = QDir::toNativeSeparators(
        QDir(QCoreApplication::applicationDirPath()).filePath(QFileInfo(QCoreApplication::applicationFilePath()).fileName()));
    const bool packageIsExecutable = nativePackagePath.endsWith(".exe", Qt::CaseInsensitive);

    QTextStream out(&updateScript);
    out << "Start-Sleep -Seconds 6\n";
    if (packageIsExecutable) {
        out << "$package = \"" << nativePackagePath << "\"\n"
            << "$targetExe = \"" << nativeTargetExePath << "\"\n"
            << "$targetDir = Split-Path -Parent $targetExe\n"
            << "Copy-Item -LiteralPath $package -Destination $targetExe -Force\n"
            << "Start-Process -FilePath $targetExe -WorkingDirectory $targetDir\n";
    } else {
        out << "$zip = \"" << nativePackagePath << "\"\n"
            << "$extract = \"" << nativeExtractPath << "\"\n"
            << "$target = \"" << nativeAppDir << "\"\n"
            << "$targetExe = \"" << nativeTargetExePath << "\"\n"
            << "Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue\n"
            << "Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force\n"
            << "$items = Get-ChildItem -LiteralPath $extract\n"
            << "$source = if ($items.Count -eq 1 -and $items[0].PSIsContainer) { $items[0].FullName } else { $extract }\n"
            << "Copy-Item -LiteralPath (Join-Path $source '*') -Destination $target -Recurse -Force\n"
            << "Start-Process -FilePath $targetExe -WorkingDirectory $target\n";
    }
    out << "Remove-Item -LiteralPath \"" << nativePackagePath << "\" -Force -ErrorAction SilentlyContinue\n"
        << "Remove-Item -LiteralPath \"" << nativeExtractPath << "\" -Recurse -Force -ErrorAction SilentlyContinue\n"
        << "$scriptPath = $MyInvocation.MyCommand.Path\n"
        << "Start-Sleep -Milliseconds 500\n"
        << "Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue\n";
    updateScript.close();

    if (!QProcess::startDetached("powershell.exe", QStringList()
        << "-NoProfile"
        << "-ExecutionPolicy" << "Bypass"
        << "-WindowStyle" << "Hidden"
        << "-File" << updateBatchPath)) {
        QMessageBox::critical(this, "Update Failed",
            "The updater could not launch the installer script.");
        QFile::remove(updateZipPath);
        QFile::remove(updateBatchPath);
        return;
    }

    cleanupUpdateArtifacts();
    this->statusBar()->showMessage("Update downloaded. Restarting to apply update...", 0);
    QApplication::processEvents();
    QApplication::quit();
}

// ====================================================
// FRAMELESS WINDOW DRAG
// ====================================================

void ACS_Wynn_Builder::mousePressEvent(QMouseEvent* event) {
    // FIX (UI/UX): Expanded drag zone from 40px to 50px for easier grabbing.
    if (event->button() == Qt::LeftButton && event->pos().y() < 50) {
        dragPosition = event->globalPosition().toPoint() - frameGeometry().topLeft();
        event->accept();
    }
}

void ACS_Wynn_Builder::mouseMoveEvent(QMouseEvent* event) {
    if (event->buttons() & Qt::LeftButton && event->pos().y() < 50) {
        move(event->globalPosition().toPoint() - dragPosition);
        event->accept();
    }
}



