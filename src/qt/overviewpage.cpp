#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "clientmodel.h"
#include "walletmodel.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "transactiontablemodel.h"
#include "transactionfilterproxy.h"
#include "guiutil.h"
#include "guiconstants.h"
//#include "main.h"                    ////////// новое //////////
#include "miner.h"                   ////////// новое //////////
#include "init.h"                    ////////// новое //////////

#include <QAbstractItemDelegate>
#include <QPainter>

#define DECORATION_SIZE 64
#define NUM_ITEMS 3

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate(): QAbstractItemDelegate(), unit(BitcoinUnits::BTC)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address);

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;

};


#include "overviewpage.moc"

OverviewPage::OverviewPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    clientModel(0),
    walletModel(0),
    currentBalance(-1),
    currentUnconfirmedBalance(-1),
    currentImmatureBalance(-1),
    txdelegate(new TxViewDelegate()),
    filter(0)
{
    ui->setupUi(this);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText("(" + tr("out of sync") + ")");
    ui->labelTransactionsStatus->setText("(" + tr("out of sync") + ")");

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        emit transactionClicked(filter->mapToSource(index));
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(qint64 balance, qint64 unconfirmedBalance, qint64 immatureBalance)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance));
    ui->labelTotal->setText(BitcoinUnits::formatWithUnit(unit, balance + unconfirmedBalance + immatureBalance));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    ui->labelImmature->setVisible(showImmature);
    ui->labelImmatureText->setVisible(showImmature);
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter = new TransactionFilterProxy();
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->sort(TransactionTableModel::Status, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter);
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance());
        connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64)), this, SLOT(setBalance(qint64, qint64, qint64)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if(currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}

/*************************** новое ******************************/

//void OverviewPage::on_ButtonSendTrans_clicked()          ////////// новое //////////
//{

////    ui->label_SendTrans->setText("STr");        ////////// новое //////////



//    double inAmount = ui->doubleSpinBoxAmount->value();
//    int inQuantity = ui->spinBoxQuantity->value();

//    std::map<CTxDestination, std::string>::iterator mi = pwalletMain->mapAddressBook.begin();
//    const CBitcoinAddress& address = (*mi).first;       // берём первый адрес из mapAddressBook

//    SendCoinsRecipient recipient;
//    recipient.address = QString::fromStdString(address.ToString());
//    recipient.amount = inAmount * COIN;

//    QList<SendCoinsRecipient> recipients;
//    recipients.append(recipient);




//    for (int i = 0; i < inQuantity; i++)
//    {
//        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
//        if(!ctx.isValid())
//        {
//            // Unlock wallet was cancelled
//            return;
//        }

//        WalletModel::SendCoinsReturn sendstatus = walletModel->sendCoins(recipients);      // отправка монет (SendCoinsDialog)
//        switch(sendstatus.status)                                 // здесь много лишнего
//        {
//        case WalletModel::InvalidAddress:
//            QMessageBox::warning(this, tr("Exchenge Coins"),
//                tr("The recipient address is not valid, please recheck."),
//                QMessageBox::Ok, QMessageBox::Ok);
//            break;
//        case WalletModel::InvalidAmount:
//            QMessageBox::warning(this, tr("Exchenge Coins"),
//                tr("The amount to pay must be larger than 0."),
//                QMessageBox::Ok, QMessageBox::Ok);
//            break;
//        case WalletModel::AmountExceedsBalance:
//            QMessageBox::warning(this, tr("Exchenge Coins"),
//                tr("The amount exceeds your balance."),
//                QMessageBox::Ok, QMessageBox::Ok);
//            break;
//        case WalletModel::AmountWithFeeExceedsBalance:
//            QMessageBox::warning(this, tr("Exchenge Coins"),
//                tr("The total exceeds your balance when the %1 transaction fee is included.").
//                arg(BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, sendstatus.fee)),
//                QMessageBox::Ok, QMessageBox::Ok);
//            break;
//        case WalletModel::DuplicateAddress:
//            QMessageBox::warning(this, tr("Exchenge Coins"),
//                tr("Duplicate address found, can only send to each address once per send operation."),
//                QMessageBox::Ok, QMessageBox::Ok);
//            break;
//        case WalletModel::TransactionCreationFailed:
//            QMessageBox::warning(this, tr("Exchenge Coins"),
//                tr("Error: Transaction creation failed!"),
//                QMessageBox::Ok, QMessageBox::Ok);
//            break;
//        case WalletModel::TransactionCommitFailed:
//            QMessageBox::warning(this, tr("Exchenge Coins"),
//                tr("sendcoinsdialog.cpp Error: The transaction was rejected. This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here."),
//                QMessageBox::Ok, QMessageBox::Ok);
//    //printf("\n     >>==> OverviewPage.cpp TransactionCommitFailed <==<<\n");
//            break;
//        case WalletModel::Aborted: // User aborted, nothing to do
//            break;
//        case WalletModel::OK:
//    // от SendCoinsDialog        accept();
//            break;
//        }


//        ui->label_SendTrans->setText("STr " + QString::number(i + 1, 10));        ////////// новое //////////
//    }






//}

//void OverviewPage::on_ButtonGenerate_clicked()          ////////// новое //////////
//{
//    if (Params().NetworkID() == CChainParams::REGTEST)
//    {
//        GenerateBitcoins(true, pwalletMain);            ////////// новое //////////
//    }
//    else if (miner)
//    {
//        ui->startGen->setText("");                      ////////// новое //////////
//        ui->ButtonGenerate->setText("Generate");        ////////// новое //////////
//        GenerateBitcoins(false, pwalletMain);           ////////// новое //////////
//        miner = false;
//    }
//    else
//    {
//        ui->startGen->setText("work");                  ////////// новое //////////
//        ui->ButtonGenerate->setText("Stop");            ////////// новое //////////
//        GenerateBitcoins(true, pwalletMain);            ////////// новое //////////
//        miner = true;
//    }
//}
