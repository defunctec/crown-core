#include "createnodedialog.h"
#include "ui_createnodedialog.h"
#include "ui_interface.h"
#include "masternodeman.h"
#include "systemnodeman.h"
#include "net.h"
#include "netbase.h"
#include <QMessageBox>
#include <QPushButton>

CreateNodeDialog::CreateNodeDialog(QWidget *parent) :
    QDialog(parent),
    editMode(false),
    startAlias(""),
    ui(new Ui::CreateNodeDialog)
{
    ui->setupUi(this);
}

CreateNodeDialog::~CreateNodeDialog()
{
    delete ui;
}

QString CreateNodeDialog::getAlias()
{
    return ui->aliasEdit->text();
}

void CreateNodeDialog::setAlias(QString alias)
{
    ui->aliasEdit->setText(alias);
    startAlias = alias;
}

QString CreateNodeDialog::getIP()
{
    return ui->ipEdit->text();
}

void CreateNodeDialog::setIP(QString ip)
{
    ui->ipEdit->setText(ip);
}

QString CreateNodeDialog::getLabel()
{
    return ui->labelEdit->text();
}

void CreateNodeDialog::setNoteLabel(QString text)
{
    ui->noteLabel->setText(text);
}

void CreateNodeDialog::setEditMode()
{
    ui->labelEdit->setVisible(false);
    ui->label->setVisible(false);
    ui->buttonBox->move(ui->buttonBox->pos().x(), 
                        ui->buttonBox->pos().y() - 50);
    resize(size().width(), size().height() - 50);
    editMode = true;
}

bool CreateNodeDialog::CheckAlias()
{
    // Check alias
    if (ui->aliasEdit->text().isEmpty())
    {
        ui->aliasEdit->setValid(false);
        QMessageBox::warning(this, windowTitle(), tr("Alias is Required"), QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }
    // Check white-space characters
    if (ui->aliasEdit->text().contains(QRegExp("\\s")))
    {
        ui->aliasEdit->setValid(false);
        QMessageBox::warning(this, windowTitle(), tr("Alias cannot contain white-space characters"), QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }
    // Check if alias exists
    if (aliasExists(ui->aliasEdit->text()))
    {
        QString aliasEditText = ui->aliasEdit->text();
        if (!(startAlias != "" && aliasEditText == startAlias))
        {
            ui->aliasEdit->setValid(false);
            QMessageBox::warning(this, windowTitle(), tr("Alias %1 Already Exists").arg(ui->aliasEdit->text()), 
                    QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
    }
    return true;
}

bool CreateNodeDialog::CheckIP()
{
    QString ip = ui->ipEdit->text();

    // Check if IP address field is empty
    if (ip.isEmpty())
    {
        ui->ipEdit->setValid(false);
        QMessageBox::warning(this, windowTitle(), tr("IP is Required"), QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }

    // Check if port is entered along with the IP address
    if (ip.contains(QRegExp(":+[0-9]")))
    {
        ui->ipEdit->setValid(false);
        QMessageBox::warning(this, windowTitle(), tr("Enter IP Without Port"), QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }

    // Validate IP address format
    // Note: This is only for validation so port doesn't matter for this check
    CService addr(ip.toStdString(), 9340); // Default port set to 9340
    if (!(addr.IsIPv4() && addr.IsRoutable())) {
        ui->ipEdit->setValid(false);
        QMessageBox::warning(this, windowTitle(), tr("Invalid IP Address. IPV4 ONLY"), QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }

    // Check if the IP address is already in use by another Masternode or Systemnode
    try {
        if (mnodeman.IsAddressInUse(addr)) {
            ui->ipEdit->setValid(false);
            QMessageBox::warning(this, windowTitle(), tr("IP address is already in use by another Masternode."), QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }

        if (snodeman.IsAddressInUse(addr)) {
            ui->ipEdit->setValid(false);
            QMessageBox::warning(this, windowTitle(), tr("IP address is already in use by another Systemnode."), QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
    } catch (const std::exception &e) {
        ui->ipEdit->setValid(false);
        QMessageBox::critical(this, windowTitle(), tr("An error occurred while checking the IP address: %1").arg(e.what()), QMessageBox::Ok, QMessageBox::Ok);
        return false;
    } catch (...) {
        ui->ipEdit->setValid(false);
        QMessageBox::critical(this, windowTitle(), tr("An unknown error occurred while checking the IP address."), QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }

    // IP address is valid and not in use
    return true;
}


void CreateNodeDialog::accept()
{
    ui->buttonBox->button(QDialogButtonBox::Ok)->setFocus();
    if (!CheckAlias())
    {
        return;
    }
    if (!CheckIP())
    {
        return;
    }
    QDialog::accept();
}
