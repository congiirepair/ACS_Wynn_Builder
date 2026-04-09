#pragma once
#include <QtWidgets/QMainWindow>
#include "ui_ACS_Wynn_Builder.h"

QT_BEGIN_NAMESPACE
namespace Ui { class ACS_Wynn_BuilderClass; }
QT_END_NAMESPACE

class ACS_Wynn_Builder : public QMainWindow {
    Q_OBJECT

public:
    ACS_Wynn_Builder(QWidget* parent = nullptr);
    ~ACS_Wynn_Builder();

private slots:
    void on_btn_generate_clicked();
    void on_btn_remove_clicked();
    void on_btn_copy_clicked();
    void on_btn_reset_clicked();
    void on_btn_deploy_clicked();
    void on_siteTabs_currentChanged(int index);

private:
    Ui::ACS_Wynn_BuilderClass* ui;
    void applyTheme(int tabIndex);
};