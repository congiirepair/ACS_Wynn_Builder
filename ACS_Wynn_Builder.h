#pragma once

#include <QtWidgets/QMainWindow>
#include <QWizard>
#include <QWizardPage>
#include <QLineEdit>
#include <QLabel>
#include <QVBoxLayout>
#include <QComboBox>
#include <QTreeWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QIntValidator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFrame>
#include <QDialog>
#include <QFile>
#include <QFileDialog>
#include <QDir>
#include <QThread>
#include <QStatusBar>
#include <QSyntaxHighlighter>
#include <QPalette>
#include <QTabBar>
#include <QRegularExpression>
#include <QSet>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QUrl>
#include <QDesktopServices>
#include <QProcess>
#include <QSettings>
#include <QMouseEvent>
#include <QCryptographicHash>
#include <QTextStream>
#include <QStandardPaths>
#include <QTimer>
#include <QScrollArea>

#include "ui_ACS_Wynn_Builder.h"
#include <libssh/libssh.h>

// ====================================================
// SHARED DATA STRUCTURES
// ====================================================

// FIX (Architecture): AP group data is now encapsulated in a plain struct
// instead of being exposed as raw public members on the main window.
// Wizard pages receive a const reference — no more qobject_cast coupling.
struct ApGroupData {
    QStringList wynnLegacy;
    QStringList encoreMain;
    QStringList wynnExpansion;
    QStringList wynnMisc;
    QStringList redRock;
    QStringList gvr;
    QStringList durango;
    QStringList stationsMisc;
    QStringList ciscoInterfaces;

    // FIX (Architecture): Controller IPs and paths loaded from ap_groups.json
    // instead of being hardcoded in two separate places in the source.
    QString wynnControllerIp = "172.25.78.148";
    QString stationsControllerIp = "24.120.186.116";
    QString ciscoControllerIp = "98.173.86.102";
    QString wynnConfigPath = "/md/WYNN-ENCORE-CONV";
    QString stationsConfigPath = "/mm";
};

struct UpdateSecurityConfig {
    bool enabled = false;
    QUrl metadataUrl;
    QUrl packageUrl;
    QString expectedSha256;
    QStringList allowedHosts;
    bool preferPrerelease = false;
};

struct UpdateReleaseOption {
    QString version;
    QUrl packageUrl;
    QString expectedSha256;
    QStringList allowedHosts;
    QString channelLabel;
    QString publishedLabel;
    bool isTesting = false;
    bool isLatestStable = false;
};

struct DeploymentOptions {
    bool sendInitialEnter = false;
    bool useCiscoShellLogin = false;
    bool testOnly = false;
};

// ====================================================
// SHARED CONFIG BUILDER (FIX: eliminates duplication)
// ====================================================

// FIX (C++ Code): The Aruba CLI generation logic was duplicated verbatim
// between ACS_Wynn_Builder::buildConfigScript() and WizardPage5::initializePage().
// It now lives here as a free function consumed by both.
QString buildArubaConfig(const QString& ssid,
    const QString& vlan,
    const QString& auth,
    const QString& psk,
    const QString& role,
    bool           hideSsid,
    bool           splashPage,
    int            siteIdx,
    const QStringList& groups,
    const ApGroupData& apData);

QString buildCiscoWlanConfig(const QString& ssid,
    const QString& vlan,
    const QString& psk,
    const QString& wlanId,
    const QString& companyName,
    const QString& removalDate,
    const QString& maxClients,
    bool           splashPage,
    const QStringList& groups);

// ====================================================
// SYNTAX HIGHLIGHTER
// ====================================================
class ArubaHighlighter : public QSyntaxHighlighter {
    Q_OBJECT
public:
    ArubaHighlighter(QTextDocument* parent = nullptr);
protected:
    void highlightBlock(const QString& text) override;
private:
    QTextCharFormat keywordFormat;
    QTextCharFormat stringFormat;
    QTextCharFormat commentFormat;
};

// ====================================================
// SSH WORKER THREAD
// ====================================================
class SshWorker : public QThread {
    Q_OBJECT
public:
    SshWorker(QString ip, QString user, QString pass, QString script,
        DeploymentOptions options = {}, QObject* parent = nullptr);
    void run() override;
signals:
    void updateLog(QString message);
    void deployFinished();
private:
    QString targetIp, username, password, configScript;
    DeploymentOptions deployOptions;
};

class ControllerSessionManager : public QObject {
    Q_OBJECT
public:
    explicit ControllerSessionManager(QObject* parent = nullptr);
    ~ControllerSessionManager();
public slots:
    void connectPersistent(QString ip, QString user, QString pass, bool isCiscoMode);
    void disconnectPersistent();
    void deployPersistent(QString script);
    void checkWlanIdsPersistent();
signals:
    void logMessage(QString message);
    void connectionStateChanged(bool connected, bool isCiscoMode, QString ip, QString user);
    void connectFinished(bool success, QString message);
    void deployFinished(bool success, QString message);
    void wlanIdCheckFinished(bool success, QString message, QString output);
private:
    ssh_session session = nullptr;
    ssh_channel channel = nullptr;
    bool connected = false;
    bool currentCiscoMode = false;
    QString currentIp;
    QString currentUser;
    QString currentPassword;
    void closeSession();
    void deployPersistentInternal(QString script, bool allowReconnect);
    void checkWlanIdsPersistentInternal(bool allowReconnect);
};

// ====================================================
// WIZARD PAGES
// ====================================================
class WizardPage1 : public QWizardPage { Q_OBJECT public: WizardPage1(QWidget* parent = nullptr); };
class WizardPage2 : public QWizardPage { Q_OBJECT public: WizardPage2(QWidget* parent = nullptr); };
class WizardPageSite : public QWizardPage { Q_OBJECT public: WizardPageSite(QWidget* parent = nullptr); };
class CiscoConnectWizardPage : public QWizardPage {
    Q_OBJECT
public:
    CiscoConnectWizardPage(class ACS_Wynn_Builder* owner,
        QString title = QString("Step 1: Cisco Controller Connection"),
        QWidget* parent = nullptr);
    void initializePage() override;
    bool isComplete() const override;
private:
    class ACS_Wynn_Builder* wizardOwner = nullptr;
    QLineEdit* ipField = nullptr;
    QLineEdit* userField = nullptr;
    QLineEdit* passField = nullptr;
    QLabel* statusLabel = nullptr;
    QPushButton* connectButton = nullptr;
    QString pageTitle;
    void refreshState();
};
class CiscoWizardPage1 : public QWizardPage {
    Q_OBJECT
public:
    CiscoWizardPage1(const QStringList& interfaces,
        QString title = QString("Step 1: Cisco WLAN Details"),
        QWidget* parent = nullptr);
};
class CiscoWizardPage2 : public QWizardPage {
    Q_OBJECT
public:
    CiscoWizardPage2(ApGroupData data,
        QString title = QString("Step 2: Cisco AP Group Selection"),
        QWidget* parent = nullptr);
    void initializePage() override;
    QTreeWidget* apTreeWidget;
    QLineEdit* searchBox;
    QCheckBox* chkLegacy;
    QCheckBox* chkEncore;
    QCheckBox* chkExpansion;
    QStringList initialCheckedGroups;
private:
    void applyBulkSelections();
    ApGroupData apData;
};

class WizardPage4 : public QWizardPage {
    Q_OBJECT
public:
    // FIX (Architecture): Receives ApGroupData by value — no qobject_cast to main window needed.
    WizardPage4(ApGroupData data, QWidget* parent = nullptr);
    void initializePage() override;
    QTreeWidget* apTreeWidget;
    QLineEdit* searchBox;
private:
    ApGroupData apData;
};

class WizardPageTarget : public QWizardPage {
    Q_OBJECT
public:
    // FIX (Architecture): Receives ApGroupData so it can read IPs without coupling to main window.
    WizardPageTarget(ApGroupData data,
        QString explicitIp = QString(),
        QString explicitUser = QString(),
        QString title = QString("Step 5: Controller Target"),
        QWidget* parent = nullptr);
    void initializePage() override;
    QLineEdit* leIP;
    QLineEdit* leUser;
    QLineEdit* lePass;
    QPushButton* btnCheckWlanIds = nullptr;
    QPlainTextEdit* wlanSummaryOutput = nullptr;
private:
    ApGroupData apData;
    QString configuredIp;
    QString configuredUser;
    QString pageTitle;
    bool enableCiscoTools = false;
};

class WizardPage5 : public QWizardPage {
    Q_OBJECT
public:
    WizardPage5(WizardPage4* apPage, ApGroupData data, QWidget* parent = nullptr);
    void initializePage() override;
    QPlainTextEdit* configPreview;
private:
    WizardPage4* p4;
    ApGroupData  apData;
};

class CiscoWizardPage3 : public QWizardPage {
    Q_OBJECT
public:
    CiscoWizardPage3(CiscoWizardPage2* apPage,
        QString title = QString("Step 3: Cisco Configuration Preview"),
        QWidget* parent = nullptr);
    void initializePage() override;
    QPlainTextEdit* configPreview;
private:
    CiscoWizardPage2* p2;
};

class WizardPage6 : public QWizardPage {
    Q_OBJECT
public:
    WizardPage6(QPlainTextEdit* preview,
        class ACS_Wynn_Builder* owner = nullptr,
        DeploymentOptions options = {},
        QString title = QString("Step 7: Deployment"),
        QWidget* parent = nullptr);
    bool validatePage() override;
    void initializePage() override;
    bool isComplete() const override;
    QPlainTextEdit* sshLogOutput;
private:
    class ACS_Wynn_Builder* wizardOwner = nullptr;
    QPlainTextEdit* previewOutput;
    bool deployComplete;
    DeploymentOptions deployOptions;
    QString pageTitle;
    bool waitingForPersistentConnect = false;
    bool persistentDeployStarted = false;
    QString pendingScript;
    QMetaObject::Connection logConnection;
    QMetaObject::Connection connectFinishedConnection;
    QMetaObject::Connection deployFinishedConnection;
};

// ====================================================
// MAIN WINDOW
// ====================================================
class ACS_Wynn_Builder : public QMainWindow {
    Q_OBJECT

public:
    ACS_Wynn_Builder(QWidget* parent = nullptr);
    ~ACS_Wynn_Builder();
    bool hasActiveCiscoSession() const;
    bool hasActiveControllerSession(bool isCiscoMode) const;
    QString activeCiscoSessionIp() const;
    QString activeCiscoSessionUser() const;
    QString defaultCiscoControllerIp() const;
    void setCiscoSessionCredentials(const QString& ip, const QString& user, const QString& pass);
    ControllerSessionManager* controllerSessionManager() const;

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;

signals:
    void ciscoSessionStateChanged();
    void ciscoSuggestedWlanIdChanged(const QString& wlanId);

private slots:
    void on_siteTabs_currentChanged(int index);
    void on_btn_generate_clicked();
    void on_btn_generate_cisco_clicked();
    void on_btn_remove_clicked();
    void on_btn_deploy_clicked();
    void on_btn_test_ssh_clicked();
    void on_btn_open_mremote_clicked();
    void on_btn_reset_clicked();
    void on_btn_copy_clicked();
    void on_btn_wizard_clicked();
    void on_modeTabs_currentChanged(int index);
    void on_profilePreset_currentIndexChanged(int index);
    void on_btn_select_ap_groups_clicked();
    void on_btn_check_wlan_ids_clicked();
    void handleSshLog(QString message);
    void on_btn_update_app_clicked();

    void updateLivePreview();
    void onSearchWynn(const QString& text);
    void onSearchStations(const QString& text);
    void onSearchCiscoWynn(const QString& text);

    // Auto-updater slots
    void onVersionCheckComplete(QNetworkReply* reply);
    void startUpdateDownload(const QUrl& url);
    void onDownloadReadyRead();
    void onDownloadFinished();

private:
    Ui::ACS_Wynn_BuilderClass* ui;
    QPoint dragPosition;
    bool ciscoSessionConnected = false;
    QString ciscoSessionIp;
    QString ciscoSessionUser;
    bool ciscoSessionIsCiscoMode = false;
    bool pendingAutoCiscoWlanIdSelection = false;
    bool pendingPostDeployCiscoWlanRefresh = false;
    bool pendingPersistentDeploy = false;
    bool pendingPersistentDeployIsCiscoMode = false;
    QString pendingPersistentDeployScript;
    QThread* controllerTrustThread = nullptr;
    QThread* persistentSessionThread = nullptr;
    ControllerSessionManager* persistentSessionManager = nullptr;
    QDialog* sshSessionDialog = nullptr;
    QPlainTextEdit* sshSessionLog = nullptr;
    QLabel* sshSessionStatus = nullptr;
    QDialog* outputDialog = nullptr;
    QPlainTextEdit* outputDialogText = nullptr;
    QFrame* heroFrame = nullptr;
    QLabel* heroTitleLabel = nullptr;
    QLabel* heroSubtitleLabel = nullptr;
    QLabel* modeBadgeLabel = nullptr;
    QLabel* siteBadgeLabel = nullptr;
    QLabel* sessionBadgeLabel = nullptr;
    QLabel* outputTitleLabel = nullptr;
    QLabel* outputSubtitleLabel = nullptr;

    QTreeWidget* tree_wynn;
    QTreeWidget* tree_stations;
    QLineEdit* search_wynn;
    QLineEdit* search_stations;
    ArubaHighlighter* highlighter;
    QTabBar* modeTabs = nullptr;
    QFrame* profilePresetFrame = nullptr;
    QComboBox* profilePresetCombo = nullptr;
    QFrame* apGroupSelectorFrame = nullptr;
    QPushButton* btnSelectApGroups = nullptr;
    QLabel* apGroupSummaryLabel = nullptr;
    QFrame* actionPanelFrame = nullptr;
    QFrame* buyoutOptionsFrame = nullptr;
    QWidget* wynnBuyoutOptionsRow = nullptr;
    QWidget* stationsBuyoutOptionsRow = nullptr;
    QWidget* ciscoBuyoutOptionsRow = nullptr;
    QPushButton* btnCheckWlanIds = nullptr;
    QFrame* ciscoFrame = nullptr;
    QFrame* ciscoLoginFrame = nullptr;
    QLineEdit* ciscoControllerIpField = nullptr;
    QLineEdit* ciscoControllerUserField = nullptr;
    QLineEdit* ciscoControllerPassField = nullptr;
    QLineEdit* ciscoCompanyName = nullptr;
    QLineEdit* ciscoRemovalDate = nullptr;
    QLineEdit* ciscoSsid = nullptr;
    QLineEdit* ciscoPassword = nullptr;
    QLineEdit* ciscoWlanId = nullptr;
    QLineEdit* ciscoMaxClients = nullptr;
    QComboBox* ciscoVlan = nullptr;
    QLabel* ciscoConnectionStatusLabel = nullptr;
    QFrame* ciscoDetailsFrame = nullptr;
    QTreeWidget* tree_cisco_wynn = nullptr;
    QLineEdit* search_cisco_wynn = nullptr;
    QCheckBox* chk_cisco_legacy = nullptr;
    QCheckBox* chk_cisco_encore = nullptr;
    QCheckBox* chk_cisco_expansion = nullptr;
    QCheckBox* chkHideSsid = nullptr;
    QCheckBox* chkArubaSplashPage = nullptr;
    QCheckBox* chkCiscoSplashPage = nullptr;

    // FIX (Architecture): All AP group data lives in one struct, kept private.
    ApGroupData apData;
    UpdateSecurityConfig updateConfig;
    UpdateSecurityConfig testingUpdateConfig;

    // FIX (Architecture): Two separate network managers — one for version check,
    // one for file download — so onVersionCheckComplete never fires for download replies.
    QNetworkAccessManager* versionCheckManager;
    QNetworkAccessManager* downloadManager;

    QPushButton* btnUpdateApp = nullptr;
    const QString CURRENT_VERSION = "2.3.17";
    void checkForUpdates(bool interactive = false, bool testingChannel = false);
    QString installedVersionLabel() const;

    QNetworkReply* downloadReply = nullptr;
    QFile* downloadFile = nullptr;
    QString updateZipPath;
    QString updateBatchPath;
    QString updateExtractPath;
    QString resolvedUpdateVersion;
    QUrl resolvedUpdatePackageUrl;
    QString resolvedUpdateSha256;
    QStringList resolvedUpdateAllowedHosts;
    QString resolvedUpdateChannelLabel;
    bool resolvedUpdateIsTesting = false;

    QString    buildConfigScript();
    QString    buildCiscoConfigScript();
    QString    buildPreviewList();
    QString    buildCiscoPreview() const;
    QStringList getSelectedGroups();
    QStringList getCiscoWynnApGroups() const;
    QStringList getCiscoWynnMiscGroups() const;

    bool isTrustedUpdateUrl(const UpdateSecurityConfig& config, const QUrl& url, const QStringList& extraAllowedHosts = {}) const;
    void cleanupUpdateArtifacts();
    QString apGroupsConfigPath() const;
    bool resolveUpdateMetadataFromObject(const UpdateSecurityConfig& config,
        const QJsonObject& releaseObject,
        QString* latestVersion,
        QUrl* packageUrl,
        QString* expectedSha256,
        QStringList* allowedHosts) const;
    bool resolveUpdateMetadata(const UpdateSecurityConfig& config,
        const QByteArray& metadataBytes,
        QString* latestVersion,
        QUrl* packageUrl,
        QString* expectedSha256,
        QStringList* allowedHosts) const;
    QUrl githubReleasesMetadataUrl() const;
    QList<UpdateReleaseOption> buildReleaseOptions(const QByteArray& metadataBytes) const;
    bool promptForReleaseSelection(const QList<UpdateReleaseOption>& releases, const QString& installedVersion, bool preferTestingChannel);
    int compareVersionStrings(const QString& left, const QString& right) const;
    void refreshWorkspaceSummary();
    void syncModeUi();
    void loadApGroupsFromJson();
    void populateTree(QTreeWidget* tree, int siteIndex);
    void executeSearch(QTreeWidget* tree, const QString& text);
    void applyAdaptiveTheme();
    void updateCiscoConnectionUi();
    void ensureSshSessionDialog(const QString& title, const QString& statusText, bool clearLog = true);
    void ensureOutputDialog(const QString& title, bool clearOutput = false);
    void setOutputText(const QString& text, const QString& title = "Generated Output");
    void appendOutputText(const QString& text, const QString& title = "Generated Output");
    void applyProfilePreset(const QString& presetName, bool persistSelection = true);
    void updateApGroupSelectionSummary();
    void updateBuyoutOptionsUi();
    void showApGroupSelectorDialog(const QString& title, QTreeWidget* sourceTree);
    QString resolveMRemotePath();
    QString mRemoteExecutablePath;
};
