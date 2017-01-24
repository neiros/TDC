#ifndef CLIENTMODEL_H
#define CLIENTMODEL_H

#include <QObject>

class OptionsModel;
class AddressTableModel;
class TransactionTableModel;
class CWallet;

QT_BEGIN_NAMESPACE
class QDateTime;
class QTimer;
QT_END_NAMESPACE

enum BlockSource {
    BLOCK_SOURCE_NONE,
    BLOCK_SOURCE_REINDEX,
    BLOCK_SOURCE_DISK,
    BLOCK_SOURCE_NETWORK
};

/** Model for Bitcoin network client.                                                       Модель для Bitcoin сетевого клиента */
class ClientModel : public QObject
{
    Q_OBJECT

public:
    explicit ClientModel(OptionsModel *optionsModel, QObject *parent = 0);
    ~ClientModel();

    OptionsModel *getOptionsModel();

    int getNumConnections() const;
    int getNumBlocks() const;
    int getNumBlocksAtStartup();

    double getVerificationProgress() const;
    QDateTime getLastBlockDate() const;

    //! Return true if client connected to testnet                                          Возвращает true, если клиент подключен к testnet
    bool isTestNet() const;
    //! Return true if core is doing initial block download                                 Возвращает true, если ядро делает начальную загрузку блока
    bool inInitialBlockDownload() const;
    //! Return true if core is importing blocks                                             Возвращает true, если ядро импортирует блоки
    enum BlockSource getBlockSource() const;
    //! Return conservative estimate of total number of blocks, or 0 if unknown             Вернуться консервативную оценку общего числа блоков, или 0 если неизвестно
    int getNumBlocksOfPeers() const;
    //! Return warnings to be displayed in status bar                                       Вернуться предупреждения, которые будут отображаться в строке состояния
    QString getStatusBarWarnings() const;

    QString formatFullVersion() const;
    QString formatBuildDate() const;
    bool isReleaseVersion() const;
    QString clientName() const;
    QString formatClientStartupTime() const;

private:
    OptionsModel *optionsModel;

    int cachedNumBlocks;
    int cachedNumBlocksOfPeers;
	bool cachedReindexing;
	bool cachedImporting;

    int numBlocksAtStartup;

    QTimer *pollTimer;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

signals:
    void numConnectionsChanged(int count);
    void numBlocksChanged(int count, int countOfPeers);
    void alertsChanged(const QString &warnings);

    //! Asynchronous message notification
    void message(const QString &title, const QString &message, unsigned int style);

public slots:
    void updateTimer();
    void updateNumConnections(int numConnections);
    void updateAlert(const QString &hash, int status);
};

#endif // CLIENTMODEL_H
