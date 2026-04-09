#include "ACS_Wynn_Builder.h"
#include <QGuiApplication>
#include <QCoreApplication> // Required for UI unfreezing during SSH
#include <QClipboard>
#include <QMessageBox>
#include <QTimer>
#include <QComboBox>
#include <QIcon>
#include <QThread>
#include <libssh/libssh.h>

// --- Wynn AP Group Lists ---
const QStringList wynn_legacy_list = { "Alsace", "Chambertin", "Delilah", "Lafleur", "Latache", "Lafite_1|2|3", "Lafite_4|7|9", "Lafite_5|Stage", "Lafite_6|8", "Lafite_GreenRoom", "Lafite_Latour|Hallways", "Latour_1|4", "Latour_2|Stage", "Latour_3", "Latour_5|6|7", "Latour_GreenRoom", "Margaux", "Montrachet", "Mouton", "Palmer", "Petrus", "Registration_1", "Registration_2", "Registration_3", "Registration_4", "St_Julian", "St_Pierre", "Sunset_Terrace" };
const QStringList encore_conv_list = { "Bach", "Brahms", "Beethoven", "Chopin", "Debussy", "Encore_B_1|2|3", "Encore_B_4|5|6", "Encore_B_7|5|8", "Handel", "Mozart", "Puccini", "Ravel", "Registration_5", "Registration_6", "Schubert", "Strauss", "Vivaldi", "WYNN|ENCORE-THEATRE", "WYNN|ENCORE-THEATRE|LOBBY" };
const QStringList wynn_exp_list = { "Avignon", "Avize", "Bandol", "Bollinger", "Castillon", "Convention_Lounge", "Cristal_1|3", "Cristal_2|4", "Cristal_5|7", "Cristal_6|8", "Cristal_GreenRoom", "Cristal_Hallway", "Cristal_Terrace", "Epernay", "Fleurie", "Hermitage", "Krug", "Meursault", "Moet", "Mumm", "Musigny", "Pomerol", "Registration_Desk_A", "Registration_Desk_B", "Reims", "Roederer", "Rotunda_Down", "Rotunda_Up", "Ruinart", "New_Wynn_BOH", "Pavillion/Garden" };

const QStringList wynn_ap_groups = { "", "ACS-Office-TestAPs", "Alsace", "Avignon", "Avize", "B10AP", "Bach", "Bandol", "Beethoven", "Bollinger", "Brahms", "C4", "Castillon", "Catering_Office", "Chambertin", "Chopin", "Convention_Lounge", "Cristal_1|3", "Cristal_2|4", "Cristal_5|7", "Cristal_6|8", "Cristal_GreenRoom", "Cristal_Hallway", "Cristal_Terrace", "Debussy", "default", "Delilah", "Encore_B_1|2|3", "Encore_B_4|5|6", "Encore_B_7|5|8", "Encore_Ballroom_Hallway", "EncoreBusinessCenter", "Epernay", "Fleurie", "Graton-Convention", "Handel", "Hermitage", "Krug", "Lafite_1|2|3", "Lafite_4|7|9", "Lafite_5|Stage", "Lafite_6|8", "Lafite_GreenRoom", "Lafite_Latour|Hallways", "Lafleur", "Latache", "Latour_1|4", "Latour_2|Stage", "Latour_3", "Latour_5|6|7", "Latour_GreenRoom", "Margaux", "Meursault", "Moet", "Montrachet", "Mouton", "Mozart", "Mumm", "Musigny", "New_Wynn_BOH", "NoAuthApGroup", "Palmer", "Pavillion/Garden", "Petrus", "Pomerol", "Puccini", "Ravel", "Registration_1", "Registration_2", "Registration_3", "Registration_4", "Registration_5", "Registration_6", "Registration_Desk_A", "Registration_Desk_B", "Reims", "Roederer", "Rotunda_Down", "Rotunda_Up", "Ruinart", "Schubert", "St_Julian", "St_Pierre", "Strauss", "Sunset_Terrace", "Vivaldi", "Wing-Lei", "WYNN|ENCORE-THEATRE", "WYNN|ENCORE-THEATRE|LOBBY", "WynnBusinessCenter", "XS_Nightclub" };

// --- Stations Casinos AP Group Lists ---
const QStringList stations_redrock_list = { "RR-Charleston_Ballroom", "RR-Pavilion_Ballroom", "RR-RedRock_Ballroom", "RR-Registration Area", "RR-Strip_Canyon_View", "RR-Strip&Canyon_View", "RR-Summerlin_Ballroom", "RR-Tbones_Crimson", "RR-Veranda-Rooms", "RR-Veranda_Rooms", "ACS-RR-Office" };
const QStringList stations_gvr_list = { "GVR-8200Suite", "GVR-Boardroom", "GVR-Cielos", "GVR-Conv-Libraryrooms", "GVR-Convention", "GVR-DelRoomsandLuna", "GVR-ElViento", "GVR-EstanciaBallroom", "GVR-GrandBallroom", "GVR-GVR PRECON", "GVR-LaCascada", "GVR-LaSirena", "GVR-Tech-Office", "ACS_GVR_Office" };
const QStringList stations_durango_list = { "DUR-Agave-BR-A", "DUR-Agave-BR-B", "DUR-Agave-BR-C", "DUR-Agave-BR-D", "DUR-Agave-BR-E", "DUR-Agave-BR-F", "DUR-Lantana-A", "DUR-Lantana-B", "DUR-Pre-Function", "DUR-Sauguaro", "DUR-Cactus", "DUR-Boardroom", "DURANGO|ACS" };

const QStringList stations_ap_groups = {
    "", "default", ".Boulder-Convention", ".FiestaHenderson-Convention", ".Palace-Convention", ".SantaFe-Convention",
    ".Sunset-Convention", ".Texas-Convention", "ACS-RR-Office", "ACS_GVR_Office", "Boulder-Convention", "DUR-Agave-BR-A",
    "DUR-Agave-BR-B", "DUR-Agave-BR-C", "DUR-Agave-BR-D", "DUR-Agave-BR-E", "DUR-Agave-BR-F", "DUR-Boardroom", "DUR-Cactus",
    "DUR-Lantana-A", "DUR-Lantana-B", "DUR-Pre-Function", "DUR-Sauguaro", "DURANGO|ACS", "GVR-8200Suite", "GVR-Boardroom",
    "GVR-Cielos", "GVR-Conv-Libraryrooms", "GVR-Convention", "GVR-DelRoomsandLuna", "GVR-ElViento", "GVR-EstanciaBallroom",
    "GVR-GrandBallroom", "GVR-GVR PRECON", "GVR-LaCascada", "GVR-LaSirena", "GVR-Tech-Office", "Palace-Convention",
    "RR-Charleston_Ballroom", "RR-Pavilion_Ballroom", "RR-RedRock_Ballroom", "RR-Registration Area", "RR-Strip&Canyon_View",
    "RR-Strip_Canyon_View", "RR-Summerlin_Ballroom", "RR-Tbones_Crimson", "RR-Veranda-Rooms", "RR-Veranda_Rooms",
    "SantaFe-Convention", "Sunset-Convention"
};

ACS_Wynn_Builder::ACS_Wynn_Builder(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::ACS_Wynn_BuilderClass) {
    ui->setupUi(this);
    setWindowIcon(QIcon(":/logo.png"));

    // Laptop-friendly dynamic sizing
    this->setMinimumSize(550, 600);
    this->resize(650, 650);

    applyTheme(0);

    ui->combo_auth->addItems({ "WPA2-PSK", "Open" });

    // --- Dynamic Combo Box Setup ---
    QList<QComboBox*> w_combos = { ui->combo_1, ui->combo_2, ui->combo_3, ui->combo_4, ui->combo_5, ui->combo_6, ui->combo_7, ui->combo_8, ui->combo_9, ui->combo_10 };
    QList<QComboBox*> s_combos = { ui->s_combo_1, ui->s_combo_2, ui->s_combo_3, ui->s_combo_4, ui->s_combo_5, ui->s_combo_6, ui->s_combo_7, ui->s_combo_8, ui->s_combo_9, ui->s_combo_10 };

    for (int i = 0; i < 10; ++i) {
        w_combos[i]->addItems(wynn_ap_groups);
        s_combos[i]->addItems(stations_ap_groups);

        if (i > 0) {
            w_combos[i]->setVisible(false);
            s_combos[i]->setVisible(false);
        }

        if (i < 9) {
            connect(w_combos[i], &QComboBox::currentTextChanged, this, [=](const QString& text) {
                if (!text.isEmpty()) w_combos[i + 1]->setVisible(true);
                });
            connect(s_combos[i], &QComboBox::currentTextChanged, this, [=](const QString& text) {
                if (!text.isEmpty()) s_combos[i + 1]->setVisible(true);
                });
        }
    }

    connect(ui->siteTabs, SIGNAL(currentChanged(int)), this, SLOT(on_siteTabs_currentChanged(int)));
    on_btn_reset_clicked();
}

ACS_Wynn_Builder::~ACS_Wynn_Builder() { delete ui; }

// --- DYNAMIC FULL-APP THEME SWITCHER ---
void ACS_Wynn_Builder::applyTheme(int tabIndex) {
    QString theme;

    if (tabIndex == 0) {
        // WYNN THEME: Classic Dark Brown & Gold
        theme = R"(
            QMainWindow { background-color: #1C1918; border-image: url(:/wynn_bg.png) 0 0 0 0 stretch stretch; }
            QWidget#centralWidget { background: transparent; }
            QLabel { color: #D1B377; font-family: 'Segoe UI'; font-size: 14px; font-weight: bold; background: transparent; }
            QFrame { background-color: rgba(28, 25, 24, 190); border: 1px solid #4A3E36; border-radius: 10px; }
            QLineEdit, QComboBox { background-color: #141211; border: 1px solid #6B5535; border-radius: 4px; color: #FDFBF7; padding: 6px; font-family: 'Segoe UI'; font-size: 13px;}
            QLineEdit:focus, QComboBox:focus { border: 1px solid #D1B377; background-color: #0F0D0C; }
            QComboBox QAbstractItemView { background-color: #141211; color: #FDFBF7; selection-background-color: #8C734B; selection-color: #1C1918; border: 1px solid #4A3E36; }
            QPushButton { font-family: 'Segoe UI'; font-size: 14px; font-weight: bold; border-radius: 6px; padding: 8px; border: 1px solid #8C734B; }
            QPushButton#btn_generate, QPushButton#btn_deploy { background-color: #8C734B; color: #1C1918; }
            QPushButton#btn_deploy:disabled { background-color: #4A3E36; color: #6B5535; border: 1px solid #2A2523; }
            QPushButton#btn_generate:hover, QPushButton#btn_deploy:hover { background-color: #A68B5B; }
            QPushButton#btn_remove { background-color: #5C2C2C; color: #FDFBF7; border-color: #5C2C2C; }
            QPushButton#btn_remove:hover { background-color: #7A3A3A; }
            QPushButton#btn_copy { background-color: #2A4C3B; color: #FDFBF7; border-color: #2A4C3B; }
            QPushButton#btn_copy:hover { background-color: #38664F; }
            QPushButton#btn_reset { background-color: rgba(42, 37, 35, 180); color: #D1B377; border-color: #4A3E36; }
            QPushButton#btn_reset:hover { background-color: #4A3E36; color: #FDFBF7; }
            QPlainTextEdit { background-color: rgba(15, 14, 13, 180); color: #D1B377; font-family: 'Consolas'; font-size: 13px; border: 1px solid #4A3E36; border-radius: 8px; padding: 10px; }
            QCheckBox { color: #FFFFFF; font-family: 'Segoe UI'; font-weight: bold; font-size: 13px; background: transparent; }
            QCheckBox::indicator { background-color: #FFFFFF; border: 1px solid #8C734B; width: 14px; height: 14px; border-radius: 2px; }
            QCheckBox::indicator:checked { background-color: #8C734B; }
            QTabWidget::pane { border: 1px solid #4A3E36; border-radius: 8px; background: rgba(28, 25, 24, 190); }
            QTabBar::tab { background-color: #141211; color: #D1B377; padding: 8px 20px; border-top-left-radius: 8px; border-top-right-radius: 8px; border: 1px solid #4A3E36; margin-right: 2px; font-weight: bold; font-family: 'Segoe UI'; }
            QTabBar::tab:selected { background-color: #8C734B; color: #1C1918; }
        )";
    }
    else {
        // STATIONS THEME: Luxury High-Limit Lounge (Enhanced Transparency & Pills)
        theme = R"(
            QMainWindow { background-color: #000000; border-image: url(:/stations_bg.png) 0 0 0 0 stretch stretch; }
            QWidget#centralWidget, QWidget#tabWynn, QWidget#tabStations { background: transparent; }
            
            QLabel { color: #FDFBF7; font-family: 'Georgia', 'serif'; font-size: 14px; font-weight: bold; background: transparent; letter-spacing: 1px; }
            
            QFrame { background-color: rgba(15, 15, 18, 160); border: 1px solid rgba(224, 224, 224, 0.2); border-radius: 15px; }
            
            QLineEdit, QComboBox { background-color: rgba(0, 0, 0, 180); border: 1px solid #4A1515; border-radius: 8px; color: #FFFFFF; padding: 8px; }
            QLineEdit:focus, QComboBox:focus { border: 1px solid #E2231A; background-color: rgba(25, 5, 5, 230); }
            
            QPushButton { font-family: 'Georgia'; font-weight: bold; font-size: 13px; border-radius: 20px; border: 1px solid rgba(255, 255, 255, 0.2); padding: 10px; color: #FFFFFF; }

            QPushButton#btn_generate, QPushButton#btn_deploy { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1A237E, stop:1 #0D47A1); }
            QPushButton#btn_generate:hover, QPushButton#btn_deploy:hover { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #283593, stop:1 #1565C0); }
            
            QPushButton#btn_remove { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #B71C1C, stop:1 #7F0000); }
            QPushButton#btn_remove:hover { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #D32F2F, stop:1 #B71C1C); }
            
            QPushButton#btn_copy { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1B5E20, stop:1 #004D40); }
            QPushButton#btn_copy:hover { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2E7D32, stop:1 #1B5E20); }
            
            QPushButton#btn_reset { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #424242, stop:1 #212121); }
            QPushButton#btn_reset:hover { background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #616161, stop:1 #424242); }

            QPushButton:disabled { background-color: #222222; color: #555555; border: 1px solid #333333; }

            QPlainTextEdit { background-color: rgba(0, 0, 0, 190); color: #E2231A; font-family: 'Consolas'; font-size: 13px; border: 1px solid rgba(224, 224, 224, 0.1); border-radius: 12px; padding: 12px; }
            
            QTabWidget::pane { border: 1px solid rgba(224, 224, 224, 0.2); border-radius: 15px; background: rgba(15, 15, 18, 160); }
            QTabBar::tab { background-color: rgba(0, 0, 0, 200); color: rgba(224, 224, 224, 0.6); padding: 12px 30px; border-top-left-radius: 12px; border-top-right-radius: 12px; margin-right: 4px; font-family: 'Georgia'; }
            QTabBar::tab:selected { background-color: #E2231A; color: #FFFFFF; }
            
            QCheckBox { color: #E0E0E0; font-weight: bold; }
        )";
    }
    this->setStyleSheet(theme);
}

void ACS_Wynn_Builder::on_siteTabs_currentChanged(int index) {
    if (index == 0) {
        ui->entry_ip->setText("172.25.78.148");
        ui->entry_path->setText("/md/WYNN-ENCORE-CONV");
    }
    else if (index == 1) {
        ui->entry_ip->setText("24.120.186.116");
        ui->entry_path->setText("/mm");
    }
    applyTheme(index);
}

void ACS_Wynn_Builder::on_btn_generate_clicked() {
    QString name = ui->entry_profile_name->text().trimmed();
    QString ssid = ui->entry_essid->text().trimmed();
    QString path = ui->entry_path->text().trimmed();
    QString role = ui->entry_role->text().trimmed();
    QString vlan = ui->entry_vlan->text().trimmed();
    QString auth = ui->combo_auth->currentText();
    QString psk = ui->entry_psk->text().trimmed();

    ui->text_output->clear();
    if (name.isEmpty()) {
        ui->text_output->setPlainText("> ERROR: Profile Name required.");
        return;
    }

    QStringList config;
    if (ui->siteTabs->currentIndex() == 1) {
        if (!path.isEmpty()) config << "change-config-node " + path << "configure terminal";
    }
    else {
        if (!path.isEmpty()) config << "cd " + path << "configure terminal";
    }

    config << "aaa authentication dot1x \"" + name + "\"" << "!";
    config << "aaa profile \"" + name + "\"" << "  authentication-dot1x \"" + name + "\"";
    if (!role.isEmpty()) config << "  initial-role \"" + role + "\"";
    config << "  enforce-dhcp" << "!";
    config << "wlan ht-ssid-profile \"" + name + "\"" << "  no 80mhz-enable" << "  no 40mhz-enable" << "!";
    config << "wlan ssid-profile \"" + name + "\"" << "  essid \"" + ssid + "\"";
    if (ui->chk_hide_ssid->isChecked()) config << "  hide-ssid";

    if (auth == "WPA2-PSK") config << "  wpa-passphrase \"" + (psk.isEmpty() ? "CHANGEME" : psk) + "\"" << "  opmode wpa2-psk-aes";
    else config << "  opmode opensystem";

    config << "  opmode-transition" << "  dot11r-profile \"default\"" << "  dtim-period 1" << "  Max-clients 250" << "  ht-ssid-profile \"" + name + "\"" << "!";
    config << "wlan virtual-ap \"" + name + "\"" << "  aaa-profile \"" + name + "\"" << "  ssid-profile \"" + name + "\"";
    if (!vlan.isEmpty()) config << "  vlan " + vlan;
    if (ui->siteTabs->currentIndex() == 1) config << "  forward-mode decrypt-tunnel";
    config << "  band-steering" << "  broadcast-filter all" << "!";

    QStringList groups = { "default" };
    if (ui->siteTabs->currentIndex() == 0) {
        QList<QComboBox*> combos = { ui->combo_1, ui->combo_2, ui->combo_3, ui->combo_4, ui->combo_5, ui->combo_6, ui->combo_7, ui->combo_8, ui->combo_9, ui->combo_10 };
        for (auto c : combos) if (c->isVisible() && !c->currentText().isEmpty()) groups << c->currentText();
        if (ui->chk_wynn_legacy->isChecked()) groups << wynn_legacy_list;
        if (ui->chk_encore_conv->isChecked()) groups << encore_conv_list;
        if (ui->chk_wynn_exp->isChecked()) groups << wynn_exp_list;
    }
    else {
        QList<QComboBox*> combos = { ui->s_combo_1, ui->s_combo_2, ui->s_combo_3, ui->s_combo_4, ui->s_combo_5, ui->s_combo_6, ui->s_combo_7, ui->s_combo_8, ui->s_combo_9, ui->s_combo_10 };
        for (auto c : combos) if (c->isVisible() && !c->currentText().isEmpty()) groups << c->currentText();
        if (ui->chk_s_redrock->isChecked()) groups << stations_redrock_list;
        if (ui->chk_s_gvr->isChecked()) groups << stations_gvr_list;
        if (ui->chk_s_durango->isChecked()) groups << stations_durango_list;
    }

    groups.removeDuplicates();
    for (const QString& g : groups) config << "ap-group \"" + g + "\"" << "  virtual-ap \"" + name + "\"" << "!";
    config << "configuration commit" << "write memory\n";

    ui->text_output->setPlainText(config.join("\n"));
    ui->btn_deploy->setEnabled(true);
}

void ACS_Wynn_Builder::on_btn_remove_clicked() {
    QString name = ui->entry_profile_name->text().trimmed();
    QString path = ui->entry_path->text().trimmed();
    ui->text_output->clear();

    if (name.isEmpty()) {
        ui->text_output->setPlainText("> ERROR: Profile Name required.");
        return;
    }

    QStringList config;
    if (ui->siteTabs->currentIndex() == 1) {
        if (!path.isEmpty()) config << "change-config-node " + path << "configure terminal";
    }
    else {
        if (!path.isEmpty()) config << "cd " + path << "configure terminal";
    }

    QStringList groups = { "default" };
    if (ui->siteTabs->currentIndex() == 0) {
        QList<QComboBox*> combos = { ui->combo_1, ui->combo_2, ui->combo_3, ui->combo_4, ui->combo_5, ui->combo_6, ui->combo_7, ui->combo_8, ui->combo_9, ui->combo_10 };
        for (auto c : combos) if (c->isVisible() && !c->currentText().isEmpty()) groups << c->currentText();
        if (ui->chk_wynn_legacy->isChecked()) groups << wynn_legacy_list;
        if (ui->chk_encore_conv->isChecked()) groups << encore_conv_list;
        if (ui->chk_wynn_exp->isChecked()) groups << wynn_exp_list;
    }
    else {
        QList<QComboBox*> combos = { ui->s_combo_1, ui->s_combo_2, ui->s_combo_3, ui->s_combo_4, ui->s_combo_5, ui->s_combo_6, ui->s_combo_7, ui->s_combo_8, ui->s_combo_9, ui->s_combo_10 };
        for (auto c : combos) if (c->isVisible() && !c->currentText().isEmpty()) groups << c->currentText();
        if (ui->chk_s_redrock->isChecked()) groups << stations_redrock_list;
        if (ui->chk_s_gvr->isChecked()) groups << stations_gvr_list;
        if (ui->chk_s_durango->isChecked()) groups << stations_durango_list;
    }

    groups.removeDuplicates();
    for (const QString& g : groups) config << "ap-group \"" + g + "\"" << "  no virtual-ap \"" + name + "\"" << "!";
    config << "no wlan virtual-ap \"" + name + "\"" << "no wlan ssid-profile \"" + name + "\"" << "no aaa profile \"" + name + "\"" << "!";
    config << "configuration commit" << "write memory\n";

    ui->text_output->setPlainText(config.join("\n"));
    ui->btn_deploy->setEnabled(true);
}

void ACS_Wynn_Builder::on_btn_deploy_clicked() {
    QString ip = ui->entry_ip->text().trimmed();
    QString user = ui->entry_user->text().trimmed();
    QString pass = ui->entry_ssh_pass->text().trimmed();
    QString cmd = ui->text_output->toPlainText();

    if (ip.isEmpty() || user.isEmpty() || pass.isEmpty() || cmd.isEmpty()) {
        QMessageBox::warning(this, "Safety Check", "Missing credentials or code.");
        return;
    }

    // --- ANTI-SPAM LOCKOUT ---
    ui->btn_deploy->setEnabled(false);
    ui->btn_deploy->setText("DEPLOYING...");

    ui->text_output->appendPlainText("\n> Initializing connection to " + ip + "...");
    QCoreApplication::processEvents();

    ssh_session session = ssh_new();
    if (session == NULL) {
        ui->btn_deploy->setEnabled(true);
        ui->btn_deploy->setText("DEPLOY");
        return;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, ip.toStdString().c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, user.toStdString().c_str());

    long timeout = 5;
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

    // --- STEP 1: TEST CONNECTION ---
    if (ssh_connect(session) != SSH_OK) {
        ui->text_output->appendPlainText(QString("> CONNECTION FAILED: ") + ssh_get_error(session));
        ssh_free(session);
        ui->btn_deploy->setEnabled(true);
        ui->btn_deploy->setText("DEPLOY");
        return;
    }

    ui->text_output->appendPlainText("> Connected. Negotiating authentication...");
    QCoreApplication::processEvents();

    // --- STEP 2: TEST AUTHENTICATION ---
    int auth_rc = ssh_userauth_password(session, NULL, pass.toStdString().c_str());

    // --- FALLBACK: Keyboard-Interactive ---
    if (auth_rc != SSH_AUTH_SUCCESS) {
        ui->text_output->appendPlainText("> Standard password rejected. Attempting Keyboard-Interactive fallback...");
        QCoreApplication::processEvents();

        auth_rc = ssh_userauth_kbdint(session, NULL, NULL);
        while (auth_rc == SSH_AUTH_INFO) {
            ssh_userauth_kbdint_setanswer(session, 0, pass.toStdString().c_str());
            auth_rc = ssh_userauth_kbdint(session, NULL, NULL);
        }
    }

    if (auth_rc != SSH_AUTH_SUCCESS) {
        ui->text_output->appendPlainText(QString("> AUTHENTICATION FAILED: ") + ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        ui->btn_deploy->setEnabled(true);
        ui->btn_deploy->setText("DEPLOY");
        return;
    }

    // --- STEP 3: DEPLOYMENT ---
    ui->text_output->appendPlainText("> Authentication Success. Pushing config...");
    QCoreApplication::processEvents();

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        ui->text_output->appendPlainText("> Error creating SSH channel.");
        ssh_disconnect(session);
        ssh_free(session);
        ui->btn_deploy->setEnabled(true);
        ui->btn_deploy->setText("DEPLOY");
        return;
    }

    ssh_channel_open_session(channel);
    ssh_channel_request_shell(channel);

    cmd += "\n";
    ssh_channel_write(channel, cmd.toStdString().c_str(), cmd.length());

    QThread::msleep(3000);

    char buf[1024];
    int n;
    QString resp = "\n--- CONTROLLER RESPONSE ---\n";

    while ((n = ssh_channel_read_nonblocking(channel, buf, sizeof(buf), 0)) > 0) {
        resp += QString::fromLocal8Bit(buf, n);
    }

    ui->text_output->appendPlainText(resp + "\n--- DEPLOYMENT COMPLETE ---");
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    // Re-enable button when completely finished
    ui->btn_deploy->setEnabled(true);
    ui->btn_deploy->setText("DEPLOY");
}

void ACS_Wynn_Builder::on_btn_reset_clicked() {
    ui->entry_profile_name->clear(); ui->entry_essid->clear(); ui->entry_vlan->clear(); ui->entry_psk->clear();
    ui->entry_user->clear(); ui->entry_ssh_pass->clear();
    ui->entry_role->setText("50Mbps-Per-User");
    ui->combo_auth->setCurrentText("WPA2-PSK");
    ui->text_output->clear();

    on_siteTabs_currentChanged(ui->siteTabs->currentIndex());

    QList<QComboBox*> w = { ui->combo_1, ui->combo_2, ui->combo_3, ui->combo_4, ui->combo_5, ui->combo_6, ui->combo_7, ui->combo_8, ui->combo_9, ui->combo_10 };
    QList<QComboBox*> s = { ui->s_combo_1, ui->s_combo_2, ui->s_combo_3, ui->s_combo_4, ui->s_combo_5, ui->s_combo_6, ui->s_combo_7, ui->s_combo_8, ui->s_combo_9, ui->s_combo_10 };
    for (int i = 0; i < 10; ++i) {
        w[i]->setCurrentIndex(0); s[i]->setCurrentIndex(0);
        if (i > 0) { w[i]->setVisible(false); s[i]->setVisible(false); }
    }

    ui->chk_hide_ssid->setChecked(false); ui->chk_wynn_legacy->setChecked(false); ui->chk_encore_conv->setChecked(false); ui->chk_wynn_exp->setChecked(false);
    ui->chk_s_redrock->setChecked(false); ui->chk_s_gvr->setChecked(false); ui->chk_s_durango->setChecked(false);

    ui->btn_deploy->setEnabled(false);
}

void ACS_Wynn_Builder::on_btn_copy_clicked() {
    QString generated_text = ui->text_output->toPlainText();
    if (!generated_text.isEmpty() && !generated_text.startsWith("> ERROR")) {
        QGuiApplication::clipboard()->setText(generated_text);
        ui->btn_copy->setText("Copied!");
        QTimer::singleShot(2000, this, [=]() { ui->btn_copy->setText("COPY"); });
        QMessageBox::information(this, "Success", "CLI code copied to clipboard.");
    }
}