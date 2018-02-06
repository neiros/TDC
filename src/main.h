// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "core.h"
#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "script.h"

#include <list>

class CWallet;
class CBlock;
class CBlockIndex;
class CKeyItem;
class CReserveKey;

class CAddress;
class CInv;
class CNode;

struct CBlockIndexWorkComparator;

/**
 *                  Часть цепи, рабочая длина блокчейна*/
static const int PART_CHAIN = 105000;                       ////////// новое //////////   12 * 24 * 365 = 105120 блоков в год
/**
 *                  Процент за перенос непотраченного выхода транзакции*/
static const double RATE_PART_CHAIN = 0.01;                 ////////// новое //////////
/**
 *                  Минимальная плата за перенос непотраченного выхода транзакции*/
static const int MIN_FEE_PART_CHAIN = 10000;                ////////// новое //////////
/**
*                   Какому блоку транзакций возвращать комиссии*/
static const unsigned int BLOCK_TX_FEE = 5;                 ////////// новое //////////
/**
 *                  Максимальное количество блоков транзакций используемых при возврате комиссий*/
static const unsigned int NUMBER_BLOCK_TX = 5;              ////////// новое //////////
/**
 *                  Менее такого количества транзакций добавляется очередной блок транзакций*/
static const unsigned int QUANTITY_TX = 105;                ////////// новое //////////
/**
 *                  Смещение по высоте блока в влокчейне для переменной tBlock транзакции */
static const unsigned int TX_TBLOCK = 1;                    ////////// новое //////////


/** The maximum allowed size for a serialized block, in bytes (network rule)
 *                  Максимально допустимый размер сериализованную блока в байтах (сетевое правило)*/
static const unsigned int MAX_BLOCK_SIZE = 5000000;         ////////// новое ////////// было 1000000
/** The maximum size for mined blocks
 *                  Максимальный размер добываемых блоков*/
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
/** The maximum size for transactions we're willing to relay/mine
 *                  Максимальный размер транзакций которые мы готовы транслировать/добывать*/
static const unsigned int MAX_STANDARD_TX_SIZE = MAX_BLOCK_SIZE_GEN/5;
/** The maximum allowed number of signature check operations in a block (network rule)
 *                  Максимально допустимое количество операций проверки подписи в блоке (сетевое правило)*/
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
/** The maximum number of orphan transactions kept in memory
 *                  Максимальное количество сиротских транзакций сохраняемых в памяти*/
static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/200;     // было 100
/** The maximum size of a blk?????.dat file (since 0.8)
 *                  Максимальный размер BLK???. DAT файлов (с 0,8)*/
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8)
 *                  Предварительное выделенный размер секций blk???. DAT файлов (с 0,8)*/
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8)
 *                  Предварительное выделенный размер секций rev???. DAT файлов (с 0,8)*/
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
/** Fake height value used in CCoins to signify they are only in the memory pool (since 0.8)
 *                  Поддельные высшие значение используемые в CCoins для обозначения что они находятся только в пуле памяти   (с 0,8)*/
static const unsigned int MEMPOOL_HEIGHT = 0x7FFFFFFF;
/** No amount larger than this (in satoshi) is valid
 *                  не больше этого количеств (в Satoshi) действительно*/
//static const int64 MAX_MONEY = 21000000 * COIN;
static const int64 MAX_MONEY = 53760000 * COIN;
inline bool MoneyRange(int64 nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule)
 *                  Транзакционные выходы Coinbase могут расходоваться только после этого количество новых блоков (сетевое правило)*/
static const int COINBASE_MATURITY = 80;                     ////////// новое ////////// было 100
/** Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp.
 *                  Порог для nLockTime: ниже этого значения интерпретируется как номер блока, в противном случае, как временная метка UNIX.*/
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC
/** Maximum number of script-checking threads allowed
 *                  Максимальное количество потоков скрипт-проверок разрешено*/
static const int MAX_SCRIPTCHECK_THREADS = 16;
/** Default amount of block size reserved for high-priority transactions (in bytes)
 *                  по умолчанию количество от размера блока зарезервировано для приоритетных транзакций (в байтах)*/
static const int DEFAULT_BLOCK_PRIORITY_SIZE = 105000;   // было 27000
#ifdef USE_UPNP
static const int fHaveUPnP = true;
#else
static const int fHaveUPnP = false;
#endif


extern CScript COINBASE_FLAGS;





extern CCriticalSection cs_main;
extern std::map<uint256, CBlockIndex*> mapBlockIndex;
extern std::vector<CBlockIndex*> vBlockIndexByHeight;
extern std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexValid;
extern CBlockIndex* pindexGenesisBlock;
extern int nBestHeight;
extern uint256 nBestChainWork;
extern uint256 nBestInvalidWork;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
extern unsigned int nTransactionsUpdated;
extern uint64 nLastBlockTx;
extern uint64 nLastBlockSize;
extern const std::string strMessageMagic;
extern double dHashesPerSec;
extern int64 nHPSTimerStart;
extern int64 nTimeBestReceived;
extern CCriticalSection cs_setpwalletRegistered;
extern std::set<CWallet*> setpwalletRegistered;
extern bool fImporting;
extern bool fReindex;
extern bool fBenchmark;
extern int nScriptCheckThreads;
extern bool fTxIndex;
extern unsigned int nCoinCacheSize;
extern bool fHaveGUI;

// Settings
extern int64 nTransactionFee;
extern int64 nMinerTransFee;                            ////////// новое //////////

// Minimum disk space required - used in CheckDiskSpace()               Минимальный размер требуемого дискового пространства - используется в CheckDiskSpace ()
static const uint64 nMinDiskSpace = 52428800;


class CReserveKey;
class CCoinsDB;
class CBlockTreeDB;
struct CDiskBlockPos;
class CCoins;
class CTxUndo;
class CCoinsView;
class CCoinsViewCache;
class CScriptCheck;
class CValidationState;

struct CBlockTemplate;

/** Register a wallet to receive updates from core
 *                  Регистрация бумажника, чтобы получать обновления от ядра*/
void RegisterWallet(CWallet* pwalletIn);
/** Unregister a wallet from core
 *                  Отменить регистрацию бумажника от ядра*/
void UnregisterWallet(CWallet* pwalletIn);
/** Unregister all wallets from core
 *                  Отменить регистрацию всех кошельков от ядра*/
void UnregisterAllWallets();
/** Push an updated transaction to all registered wallets
 *                  Проталкиваем обновленный транзакции для всех зарегистрированных кошельков*/
void SyncWithWallets(const uint256 &hash, const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false);

/** Register with a network node to receive its signals
 *                  Зарегистрироваться с узлом сети для приёма его сигналов */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node
 *                  Отмена регистрации сетевого узла*/
void UnregisterNodeSignals(CNodeSignals& nodeSignals);

void PushGetBlocks(CNode* pnode, CBlockIndex* pindexBegin, uint256 hashEnd);

/** Process an incoming block
 *                  Обработка входящего блока */
bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock, CDiskBlockPos *dbp = NULL);
/** Check whether enough disk space is available for an incoming block
 *                  Проверьте, достаточно ли места на диске доступно для входящего блока*/
bool CheckDiskSpace(uint64 nAdditionalBytes = 0);
/** Open a block file (blk?????.dat)
 *                  Открытие файла блока (BLK???. DAT)*/
FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat)
 *                  Открытие файла отката (Rev???. DAT)*/
FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Import blocks from an external file
 *                  Импорт блоков из внешнего файла*/
bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp = NULL);
/** Initialize a new block tree database + block data on disk
 *                  Инициализация нового блока базы данных дерева + блок данных на диске*/
bool InitBlockIndex();
/** Load the block tree and coins database from disk
 *                  Загрузите блок-дерева и монет базы данных с диска*/
bool LoadBlockIndex();
/** Unload database information
 *                  Выгрузка информации базы данных*/
void UnloadBlockIndex();
/** Verify consistency of the block and coin databases
 *                  Проверка соответствия блока и монет базы данных*/
bool VerifyDB(int nCheckLevel, int nCheckDepth);
/** Print the loaded block tree
 *                  Распечатать загруженное блок-дерево*/
void PrintBlockTree();
/** Find a block by height in the currently-connected chain
 *                  Найти блок по высоте в данный-момент-подключенной цепи*/
CBlockIndex* FindBlockByHeight(int nHeight);
/** Process protocol messages received from a given node
 *                  Сообщения протокола процесса, полученные от данного узла*/
bool ProcessMessages(CNode* pfrom);
/** Send queued protocol messages to be sent to a give node
 *                  Отправка очереди сообщений протокола, который будет отправлены данному узлу*/
bool SendMessages(CNode* pto, bool fSendTrickle);
/** Run an instance of the script checking thread
 *                  Запустить экземпляр проверки сценария в потоке*/
void ThreadScriptCheck();
/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits
 *                  Проверить, удовлетворяет ли хэш блока требованию доказательства-работы указанное в nBits */
//bool CheckProofOfWork(uint256 hash, unsigned int nBits);
bool CheckProofOfWorkNEW(std::vector<CTransaction> vtx, uint256 hash, unsigned int nBits);
/** Calculate the minimum amount of work a received block needs, without knowing its direct parent
 *                  Рассчитайте минимальное количество работы необходимое для получения блока, не зная его прямого родителя*/
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime);
/** Get the number of active peers
 *                  Получить количество активных пиров*/
int GetNumBlocksOfPeers();
/** Check whether we are doing an initial block download (synchronizing from disk or network)
 *                  Проверьте, правильно ли мы делаем начальную загрузку блока (синхронизация с диском или сетью)*/
bool IsInitialBlockDownload();
/** Format a string that describes several potential problems detected by the core
 *                  Формат строки, описывающей несколько потенциальных проблем, обнаруженных ядром*/
std::string GetWarnings(std::string strFor);
/** Retrieve a transaction (from memory pool, or from disk, if possible)
 *                  Получение транзакций (от памяти пула, или с диска, если это возможно)*/
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock, bool fAllowSlow = false);
/** Connect/disconnect blocks until pindexNew is the new tip of the active block chain
 *                  Подключение/отключение блоков до тех пор пока pindexNew станет новым активным окончанием цепи блоков*/
bool SetBestChain(CValidationState &state, CBlockIndex* pindexNew);
/** Find the best known block, and make it the tip of the block chain
 *                  Найти наилучший известный блок, и сделать его окончанием цепи блоков*/
bool ConnectBestBlock(CValidationState &state);
int GetHeightPartChain(int nHeight);                              ////////// новое //////////
int64 GetBlockValue(int nHeight, int64 nFees);
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock);

void UpdateTime(CBlockHeader& block, const CBlockIndex* pindexPrev);

/** Create a new block index entry for a given block hash
 *                  Создайте новую запись индекса блока для данного хэша блока*/
CBlockIndex * InsertBlockIndex(uint256 hash);
/** Verify a signature
 *                  Проверить подпись*/
bool VerifySignature(const CCoins& txFrom, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType);
/** Abort with a message
 *                  Прервать с сообщением*/
bool AbortNode(const std::string &msg);




/*************************** новое ******************************/
struct TransM
{
    std::vector<CTxIn> vinM;
    std::vector<CTxOut> voutM;
    uint256 hashBlock;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vinM);
        READWRITE(voutM);
        READWRITE(hashBlock);
    )

    TransM() {
        SetNull();
    }

    void SetNull() {
        vinM.clear();
        voutM.clear();
        hashBlock = 0;
    }
};


typedef boost::tuple<uint256, CTxOut> TxHashPriority;
class TxHashPriorityCompare
{
    bool byHash;
public:
    TxHashPriorityCompare(bool _byHash) : byHash(_byHash) { }
    bool operator()(const TxHashPriority& a, const TxHashPriority& b)
    {
        return a.get<0>() < b.get<0>();
    }
};
/*************************** новое ******************************/






bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(nFile));
        READWRITE(VARINT(nPos));
    )

    CDiskBlockPos() {
        SetNull();
    }

    CDiskBlockPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return !(a == b);
    }

    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }
};

struct CDiskTxPos : public CDiskBlockPos
{
    unsigned int nTxOffset; // after header                             после заголовка

    IMPLEMENT_SERIALIZE(
        READWRITE(*(CDiskBlockPos*)this);
        READWRITE(VARINT(nTxOffset));
    )

    CDiskTxPos(const CDiskBlockPos &blockIn, unsigned int nTxOffsetIn) : CDiskBlockPos(blockIn.nFile, blockIn.nPos), nTxOffset(nTxOffsetIn) {
    }

    CDiskTxPos() {
        SetNull();
    }

    void SetNull() {
        CDiskBlockPos::SetNull();
        nTxOffset = 0;
    }
};



enum GetMinFee_mode
{
    GMF_RELAY,
    GMF_SEND,
};

int64 GetMinFee(const CTransaction& tx, bool fAllowFree, enum GetMinFee_mode mode);

//
// Check transaction inputs, and make sure any                          Проверить транзакции входов, и убедиться, что любые
// pay-to-script-hash transactions are evaluating IsStandard scripts    платы-за-сценарий-хэша транзакции оцениваются IsStandard скриптами
//
// Why bother? To avoid denial-of-service attacks; an attacker          Зачем беспокоиться? Чтобы избежать отказа в обслуживании; злоумышленник
// can submit a standard HASH... OP_EQUAL transaction,                  можете представить стандартный HASH... OP_EQUAL транзакции,
// which will get accepted into blocks. The redemption                  который и будет принят в блоках. Сценарием погашения(выкупа)
// script can be anything; an attacker could use a very                 может быть что угодно, злоумышленник может использовать очень
// expensive-to-check-upon-redemption script like:                      дорогие-для-проверки-на-выкуп сценарии, как:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1                     DUP CHECKSIG DROP ... повторяется 100 раз ... op_1
//

    /** Check for standard transaction types
        @param[in] mapInputs    Map of previous transactions that have outputs we're spending
        @return True if all inputs (scriptSigs) use only standard transaction forms
                    Проверка для стандартных типов транзакций
                    @param[in] mapInputs Карта предыдущих сделок, которые имеют выходы что мы тратим
                    @return истина, если все входы (scriptSigs) используют только стандартную форму транзакции
    */
bool AreInputsStandard(const CTransaction& tx, CCoinsViewCache& mapInputs);

/** Count ECDSA signature operations the old-fashioned (pre-0.6) way
    @return number of sigops this transaction's outputs will produce when spent
    @see CTransaction::FetchInputs
                    Количество ECDSA операций подписи старомодным (до 0,6) способом
                    @return количество SIGOPS выходов этой транзакции будет пролучено, при трате(проведении)
                    @see CTransaction :: FetchInputs
*/
unsigned int GetLegacySigOpCount(const CTransaction& tx);

/** Count ECDSA signature operations in pay-to-script-hash inputs.      Количество ECDSA операций подписи в оплате-за-сценарий-хэша входов.

    @param[in] mapInputs	Map of previous transactions that have outputs we're spending
    @return maximum number of sigops required to validate this transaction's inputs
    @see CTransaction::FetchInputs
                    @param[in] mapInputs Карта предыдущих сделок, которые имеют выходы что мы тратим
                    @return максимального количества SIGOPS необходимых для проверки входов этой транзакции
                    @see  CTransaction :: FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, CCoinsViewCache& mapInputs);


inline bool AllowFree(double dPriority)
{
    // Large (in bytes) low-priority (new, small-coin) transactions     Большие (в байтах) низкоприоритетные (новые, малые монеты) операции
    // need a fee.                                                      требуют платы.
    return dPriority > COIN * 144 / 250;
}

// Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
// This does not modify the UTXO set. If pvChecks is not NULL, script checks are pushed onto it
// instead of being performed inline.

//                  Убедитесь в том, что все входа этой сделки действительны (нет двойной траты, скрипты и SIGs, суммы)
//                  Это не изменяе UTXO набор. Если pvChecks не NULL, скрипт проверки замещаются вместо тех,
//                  что выполняться встроенными.
bool CheckInputs(const CTransaction& tx, CValidationState &state, CCoinsViewCache &view, bool fScriptChecks = true,
                 unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
                 std::vector<CScriptCheck> *pvChecks = NULL);

// Apply the effects of this transaction on the UTXO set represented by view    Применить последствия этой сделки на UTXO наборе, представленного для рассмотрения
void UpdateCoins(const CTransaction& tx, CValidationState &state, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight, const uint256 &txhash);

// Context-independent validity checks                                  Контекстно-независимые проверки достоверности
bool CheckTransaction(const CTransaction& tx, CValidationState& state);

/** Check for standard transaction types                                Проверка для стандартных типов транзакций
    @return True if all outputs (scriptPubKeys) use only standard transaction forms
                    @return Истина, если все выходы (scriptPubKeys) используют только стандартные формы транзакции
*/
bool IsStandardTx(const CTransaction& tx, std::string& reason);

bool IsFinalTx(const CTransaction &tx, int nBlockHeight = 0, int64 nBlockTime = 0);

/** Amount of bitcoins spent by the transaction.                        Количество проведенных Bitcoins транзакций.
    @return sum of all outputs (note: does not include fees)            сумма всех выходов (Примечание: не включает сборы)
 */
int64 GetValueOut(const CTransaction& tx);

/** Undo information for a CBlock                                       Информация отмены для CBlock*/
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase           для всех кроме coinbase

    IMPLEMENT_SERIALIZE(
        READWRITE(vtxundo);
    )

    bool WriteToDisk(CDiskBlockPos &pos, const uint256 &hashBlock)
    {
        // Open history file to append                                  открытыть файлов для добавления
        CAutoFile fileout = CAutoFile(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
        if (!fileout)
            return error("CBlockUndo::WriteToDisk() : OpenUndoFile failed");

        // Write index header                                           запись индекса заголовка
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(Params().MessageStart()) << nSize;

        // Write undo data                                              запись отмены данных
        long fileOutPos = ftell(fileout);
        if (fileOutPos < 0)
            return error("CBlockUndo::WriteToDisk() : ftell failed");
        pos.nPos = (unsigned int)fileOutPos;
        fileout << *this;

        // calculate & write checksum                                   рассчитать и записать контрольную сумму
        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        hasher << hashBlock;
        hasher << *this;
        fileout << hasher.GetHash();

        // Flush stdio buffers and commit to disk before returning      сбросить stdio буферы и передать на диск, прежде чем вернуться
        fflush(fileout);
        if (!IsInitialBlockDownload())
            FileCommit(fileout);

        return true;
    }

    bool ReadFromDisk(const CDiskBlockPos &pos, const uint256 &hashBlock)
    {
        // Open history file to read                                    открытыть файл для читения
        CAutoFile filein = CAutoFile(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error("CBlockUndo::ReadFromDisk() : OpenBlockFile failed");

        // Read block                                                   прочитать блок
        uint256 hashChecksum;
        try {
            filein >> *this;
            filein >> hashChecksum;
        }
        catch (std::exception &e) {
            return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
        }

        // Verify checksum                                              проверить контрольную сумму
        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        hasher << hashBlock;
        hasher << *this;
        if (hashChecksum != hasher.GetHash())
            return error("CBlockUndo::ReadFromDisk() : checksum mismatch");

        return true;
    }
};


/** Closure representing one script verification                        Закрытое исполнение одной проверки скрипта
 *  Note that this stores references to the spending transaction        Заметим, что это хранит ссылки на расходные транзакции */
class CScriptCheck
{
private:
    CScript scriptPubKey;
    const CTransaction *ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    int nHashType;

public:
    CScriptCheck() {}
    CScriptCheck(const CCoins& txFromIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, int nHashTypeIn) :
        scriptPubKey(txFromIn.vout[txToIn.vin[nInIn].prevout.n].scriptPubKey),
        ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), nHashType(nHashTypeIn) { }

    bool operator()() const;

    void swap(CScriptCheck &check) {
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(nHashType, check.nHashType);
    }
};

/** A transaction with a merkle branch linking it to the block chain.   Сделки с ветвью Меркля связывающие их с цепью блоков*/
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }


    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    int SetMerkleBranch(const CBlock* pblock=NULL);
    int GetDepthInMainChain(CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(bool fLimitFree=true);
};





/** Data structure that represents a partial merkle tree.                       Структура данных, которая представляет собой частичное дерево Меркле.
 *
 * It respresents a subset of the txid's of a known block, in a way that        Он представляет собой подмножество txid's в известном блок, таким образом,
 * allows recovery of the list of txid's and the merkle root, in an             что обеспечивает восстановление списка txid's и корневой Меркле,
 * authenticated way.                                                           проверенным способом
 *
 * The encoding works as follows: we traverse the tree in depth-first order,    Кодирование работает следующим образом: мы обходим дерево на глубину первых ордеров,
 * storing a bit for each traversed node, signifying whether the node is the    сохраняем бит для каждого пройденного узла, означающий ли узел является родительским
 * parent of at least one matched leaf txid (or a matched txid itself). In      по крайней мере один лист соответствует txid (или соответствует txid непосредственно).
 * case we are at the leaf level, or this bit is 0, its merkle node hash is     В случае, если мы находимся на уровне листьев или этот бит равен 0, его узловой Меркле
 * stored, and its children are not explorer further. Otherwise, no hash is     Хэш сохраняется, и его дети не исследуются далее. В противном случае хэш не сохраняется
 * stored, but we recurse into both (or the only) child branch. During          но мы recurse в две (или одной) дочерней ветви.
 * decoding, the same depth-first traversal is performed, consuming bits and    Во время декодирования, выполняется тойже глубины обход потребления битов и
 * hashes as they written during encoding.                                      хэшей как они записаны в процессе кодирования.
 *
 * The serialization is fixed and provides a hard guarantee about the           Сериализация фиксируется и обеспечивает, что дает твердой гарантии о
 * encoded size:                                                                размер закодированного
 *
 *   SIZE <= 10 + ceil(32.25*N)
 *
 * Where N represents the number of leaf nodes of the partial tree. N itself    Где N представляет собой количество конечных узлов частичного дерева.
 * is bounded by:                                                               N непосредственно ограничен.
 *
 *   N <= total_transactions
 *   N <= 1 + matched_transactions*tree_height                                  matched - соответствие
 *
 * The serialization format:                                                    Формат сериализации:
 *  - uint32     total_transactions (4 bytes)
 *  - varint     number of hashes   (1-3 bytes)
 *  - uint256[]  hashes in depth-first order (<= 32*N bytes)                    depth - глубина
 *  - varint     number of bytes of flag bits (1-3 bytes)
 *  - byte[]     flag bits, packed per 8 in a byte, least significant bit first (<= 2*N-1 bits)     биты флагов, упакованный в 8 байт, младший бит первый
 * The size constraints follow from this.                                       Размер ограничения вытекают из этого
 */
class CPartialMerkleTree                    //  ЧастичноеДеревоМеркля
{
protected:
    // the total number of transactions in the block                            общее количество сделок в блоке
    unsigned int nTransactions;

    // node-is-parent-of-matched-txid bits                                      узел-из-родителей-соответствии-txid биты
    std::vector<bool> vBits;

    // txids and internal hashes                                                txids и внутренние хэши
    std::vector<uint256> vHash;

    // flag set when encountering invalid data                                  установление флага при встрече неверных данные
    bool fBad;

    // helper function to efficiently calculate the number of nodes at given height in the merkle tree
    //                  вспомогательная функция для эффективного вычисления количества узлов на заданной высоте в дереве Меркля
    unsigned int CalcTreeWidth(int height) {
        return (nTransactions+(1 << height)-1) >> height;
    }

    // calculate the hash of a node in the merkle tree (at leaf level: the txid's themself)
    //                  вычисление хэш узла в дереве Меркля (на уровне листьев: txid's сам собой)
    uint256 CalcHash(int height, unsigned int pos, const std::vector<uint256> &vTxid);

    // recursive function that traverses tree nodes, storing the data as bits and hashes
    //                  рекурсивная функция, которая проходит узлы дерева, хранящие данные в виде битов и хэшей
    void TraverseAndBuild(int height, unsigned int pos, const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch);

    // recursive function that traverses tree nodes, consuming the bits and hashes produced by TraverseAndBuild. It returns the hash of the respective node.
    //                  рекурсивная функция, которая проходит узлы дерева, использующая биты и хэши полученные от TraverseAndBuild. Она возвращает хэш соответствующего узла.
    uint256 TraverseAndExtract(int height, unsigned int pos, unsigned int &nBitsUsed, unsigned int &nHashUsed, std::vector<uint256> &vMatch);

public:

    // serialization implementation                                             реализация сериализации
    IMPLEMENT_SERIALIZE(
        READWRITE(nTransactions);
        READWRITE(vHash);
        std::vector<unsigned char> vBytes;
        if (fRead) {
            READWRITE(vBytes);
            CPartialMerkleTree &us = *(const_cast<CPartialMerkleTree*>(this));
            us.vBits.resize(vBytes.size() * 8);
            for (unsigned int p = 0; p < us.vBits.size(); p++)
                us.vBits[p] = (vBytes[p / 8] & (1 << (p % 8))) != 0;
            us.fBad = false;
        } else {
            vBytes.resize((vBits.size()+7)/8);
            for (unsigned int p = 0; p < vBits.size(); p++)
                vBytes[p / 8] |= vBits[p] << (p % 8);
            READWRITE(vBytes);
        }
    )

    // Construct a partial merkle tree from a list of transaction id's, and a mask that selects a subset of them
    //                  Построить частичное дерева Меркля из списка идентификатор транзакции, и маску, которая выбирает их подмножество
    CPartialMerkleTree(const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch);

    CPartialMerkleTree();

    // extract the matching txid's represented by this partial merkle tree.     извлечь соответствующие txid's, представленные этой частью дерева Меркля.
    // returns the merkle root, or 0 in case of failure                         возвращает корень Меркля, или 0 в случае неудачи
    uint256 ExtractMatches(std::vector<uint256> &vMatch);       // ИзвлечениеСоответствия
};



/** Functions for disk access for blocks                                        Функции доступа к диску для блоков*/
bool WriteBlockToDisk(CBlock& block, CDiskBlockPos& pos);
bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex);


/** Functions for validating blocks and updating the block tree                 Функции для проверки блоков и обновление блока дерева */

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  In case pfClean is provided, operation will try to be tolerant about errors, and *pfClean
 *  will be true if no problems were found. Otherwise, the return value will be false in case
 *  of problems. Note that in any case, coins may be modified.
 *                      Устранить последствия этого блока (с заданным индексом) на множестве UTXO представленое ​​монетами.
 *                      В случае pfClean обеспечении, производится попытка что бы быть терпимым к ошибкам, и *pfClean
 *                      будет верно, если никаких проблем обнаружено не было. В противном случае, возвращаемым значением будет false
 *                      в случае возникновения проблем. Следует отметить, что в любом случае, монеты могут быть изменены.
*/
bool DisconnectBlock(CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins, bool* pfClean = NULL);

// Apply the effects of this block (with given index) on the UTXO set represented by coins
//                      Применить последствия этого блока (с заданным индексом) на множестве UTXO представленное монетами
bool ConnectBlock(CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins, bool fJustCheck = false);

// Add this block to the block index, and if necessary, switch the active block chain to this
//                      Добавить блока к индексируванным блокам, и при необходимости переключить активную цепь блоков к него
bool AddToBlockIndex(CBlock& block, CValidationState& state, const CDiskBlockPos& pos);

// Context-independent validity checks                                          Контекстно-независимые проверки достоверности
bool CheckBlock(const CBlock& block, CValidationState& state, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

// Store block on disk                                                          Сохранить блок на диске
// if dbp is provided, the file is known to already reside on disk              если DBP в том случае, то файл, как известно, уже находятся на диске
bool AcceptBlock(CBlock& block, CValidationState& state, CDiskBlockPos* dbp = NULL);



class CBlockFileInfo
{
public:
    unsigned int nBlocks;      // number of blocks stored in file               количество блоков хранящихся в файле
    unsigned int nSize;        // number of used bytes of block file            количество используемых байтов в блок файле
    unsigned int nUndoSize;    // number of used bytes in the undo file         количество использованных байтов в файле отката
    unsigned int nHeightFirst; // lowest height of block in file                низкая высота блока в файл
    unsigned int nHeightLast;  // highest height of block in file               наибольшая высота блок в файле
    uint64 nTimeFirst;         // earliest time of block in file                раннее время блок в файле
    uint64 nTimeLast;          // latest time of block in file                  последнее время блок в файле

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(nBlocks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
     )

     void SetNull() {
         nBlocks = 0;
         nSize = 0;
         nUndoSize = 0;
         nHeightFirst = 0;
         nHeightLast = 0;
         nTimeFirst = 0;
         nTimeLast = 0;
     }

     CBlockFileInfo() {
         SetNull();
     }

     std::string ToString() const {
         return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst).c_str(), DateTimeStrFormat("%Y-%m-%d", nTimeLast).c_str());
     }

     // update statistics (does not update nSize)                               Обновление статистики (не обновляется nSize)
     void AddBlock(unsigned int nHeightIn, uint64 nTimeIn) {
         if (nBlocks==0 || nHeightFirst > nHeightIn)
             nHeightFirst = nHeightIn;
         if (nBlocks==0 || nTimeFirst > nTimeIn)
             nTimeFirst = nTimeIn;
         nBlocks++;
         if (nHeightIn > nHeightFirst)
             nHeightLast = nHeightIn;
         if (nTimeIn > nTimeLast)
             nTimeLast = nTimeIn;
     }
};

extern CCriticalSection cs_LastBlockFile;
extern CBlockFileInfo infoLastBlockFile;
extern int nLastBlockFile;

enum BlockStatus {
    BLOCK_VALID_UNKNOWN      =    0,
    BLOCK_VALID_HEADER       =    1, // parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
                                        // разбирать, версия ok, хэш удовлетворяет утверждению PoW 1 <= vtx count <= Max, временная метка не в будущем
    BLOCK_VALID_TREE         =    2, // parent found, difficulty matches, timestamp >= median previous, checkpoint
                                        // родитель найден, соответствие трудности, временная метка >= средне-предыдущего, checkpoint
    BLOCK_VALID_TRANSACTIONS =    3, // only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids, sigops, size, merkle root
                                        // только первая tx is coinbase, 2 <= coinbase входа сценарий длиной <= 100, действительными сделок, нет повторяющихся txids, sigops, size, merkle root
    BLOCK_VALID_CHAIN        =    4, // outputs do not overspend inputs, no double spends, coinbase output ok, immature coinbase spends, BIP30
                                        // Выходы не сорят деньгами входов, никаких двойных тратит, coinbase OUTPUT OK, незрелые coinbase тратятся, BIP30
    BLOCK_VALID_SCRIPTS      =    5, // scripts/signatures ok                       скрипты/подписи ok
    BLOCK_VALID_MASK         =    7,

    BLOCK_HAVE_DATA          =    8, // full block available in blk*.dat            полный блок доступен в blk*.dat)
    BLOCK_HAVE_UNDO          =   16, // undo data available in rev*.dat             отмена данных имеется в rev*.dat)
    BLOCK_HAVE_MASK          =   24,

    BLOCK_FAILED_VALID       =   32, // stage after last reached validness failed   после последнего этапа достигнуть (достоверности?) не удалось
    BLOCK_FAILED_CHILD       =   64, // descends from failed block                  спускаемся от неудачного блока
    BLOCK_FAILED_MASK        =   96
};

/** The block chain is a tree shaped structure starting with the                    Цепь блоков дерево-образной структуры, начиная с
 * genesis block at the root, with each block potentially having multiple           блока генезиса в корне, причем каждый блок потенциально имеет несколько
 * candidates to be the next block. A blockindex may have multiple pprev pointing   кандидатов в следующий блок. Blockindex может иметь несколько pprev, указывающие
 * to it, but at most one of them can be part of the currently active branch.       на него, но не более одного из них может быть частью активной в данный момент ветви.
 */
class CBlockIndex
{
public:
    // pointer to the hash of the block, if any. memory is owned by this CBlockIndex (указатель на хэш-блока, если такой имеется в памяти, принадлежащей этому CBlockIndex)
    const uint256* phashBlock;

    // pointer to the index of the predecessor of this block                        указатель на индекс предшественника этого блока
    CBlockIndex* pprev;

    // height of the entry in the chain. The genesis block has height 0             высота входа в цепь. Блок генезиса имеет высоту 0
    int nHeight;

    // Which # file this block is stored in (blk?????.dat)                          В каком # файла этот блок хранится (blk?????.dat)
    int nFile;

    // Byte offset within blk?????.dat where this block's data is stored            Смещение в байтах в blk?????.dat, где данные этого блока хранятся
    unsigned int nDataPos;

    // Byte offset within rev?????.dat where this block's undo data is stored       Смещение в байтах в rev?????.dat, где отмена этого блока хранятся
    unsigned int nUndoPos;

    // (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    //                  (память) общим объем работ (ожидаемое количество хэшей) в цепи до и в том числе этот блок
    uint256 nChainWork;

    // Number of transactions in this block.                                        Количество сделок в этом блоке.
    // Note: in a potential headers-first mode, this number cannot be relied upon   Примечание: в потенциальном заголовке первого режима, на это число можно не полагаться
    unsigned int nTx;

    // (memory only) Number of transactions in the chain up to and including this block        (память) Количество сделок в цепочке вплоть до этого блока
    unsigned int nChainTx; // change to 64-bit type when necessary; won't happen before 2030   изменить на 64-битный тип в случае необходимости; произойдет не ранее 2030

    // Verification status of this block. See enum BlockStatus                      Проверка статуса этого блока. См. перечисление BlockStatus
    unsigned int nStatus;

    // block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;


    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainWork = 0;
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBlockIndex(CBlockHeader& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainWork = 0;
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
    }

    CDiskBlockPos GetBlockPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_DATA) {
            ret.nFile = nFile;
            ret.nPos  = nDataPos;
        }
        return ret;
    }

    CDiskBlockPos GetUndoPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_UNDO) {
            ret.nFile = nFile;
            ret.nPos  = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }

    CBigNum GetBlockWork() const
    {
        CBigNum bnTarget;
        bnTarget.SetCompact(nBits);
        if (bnTarget <= 0)
            return 0;
        return (CBigNum(1)<<256) / (bnTarget+1);
    }

    bool IsInMainChain() const
    {
        return nHeight < (int)vBlockIndexByHeight.size() && vBlockIndexByHeight[nHeight] == this;
    }

    CBlockIndex *GetNextInMainChain() const {
        return nHeight+1 >= (int)vBlockIndexByHeight.size() ? NULL : vBlockIndexByHeight[nHeight+1];
    }

//    bool CheckIndex() const
//    {
//        return CheckProofOfWork(GetBlockHash(), nBits);  здесь нет массива с транзакциями для проверки nBits
//    }

    enum { nMedianTimeSpan=11 };

    int64 GetMedianTimePast() const
    {
        int64 pmedian[nMedianTimeSpan];
        int64* pbegin = &pmedian[nMedianTimeSpan];
        int64* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    int64 GetMedianTime() const
    {
        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan/2; i++)
        {
            if (!pindex->GetNextInMainChain())
                return GetBlockTime();
            pindex = pindex->GetNextInMainChain();
        }
        return pindex->GetMedianTimePast();
    }

    /**
     * Returns true if there are nRequired or more blocks of minVersion or above    Возвращает истину, если есть nRequired или более блоков MinVersion или выше
     * in the last nToCheck blocks, starting at pstart and going backwards.         в последних nToCheck блоках, начиная с PSTART и  и двигаться назад.
     */
    static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart,
                                unsigned int nRequired, unsigned int nToCheck);

    std::string ToString() const
    {
        return strprintf("CBlockIndex(pprev=%p, pnext=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
            pprev, GetNextInMainChain(), nHeight,
            hashMerkleRoot.ToString().c_str(),
            GetBlockHash().ToString().c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

struct CBlockIndexWorkComparator
{
    bool operator()(CBlockIndex *pa, CBlockIndex *pb) {
        if (pa->nChainWork > pb->nChainWork) return false;
        if (pa->nChainWork < pb->nChainWork) return true;

        if (pa->GetBlockHash() < pb->GetBlockHash()) return false;
        if (pa->GetBlockHash() > pb->GetBlockHash()) return true;

        return false; // identical blocks                                           идентичные блоки
    }
};



/** Used to marshal pointers into hashes for db storage.                            Используется для выстраивания указателей на хэши для db хранения*/
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;

    CDiskBlockIndex() {
        hashPrev = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(VARINT(nVersion));

        READWRITE(VARINT(nHeight));
        READWRITE(VARINT(nStatus));
        READWRITE(VARINT(nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
            READWRITE(VARINT(nFile));
        if (nStatus & BLOCK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    )

    uint256 GetBlockHash() const
    {
        CBlockHeader block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        return block.GetHash();
    }


    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

/** Capture information about block/transaction validation    Захват информации о блоке/транзакционные проверки*/
class CValidationState {
private:
    enum mode_state {
        MODE_VALID,   // everything ok                                              все в порядке
        MODE_INVALID, // network rule violation (DoS value may be set)              сетевое нарушение правил (DoS может быть установлено)
        MODE_ERROR,   // run-time error                                             ошибки во время выполнения
    } mode;
    int nDoS;
public:
    CValidationState() : mode(MODE_VALID), nDoS(0) {}
    bool DoS(int level, bool ret = false) {
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false) {
        return DoS(0, ret);
    }
    bool Error() {
        mode = MODE_ERROR;
        return false;
    }
    bool Abort(const std::string &msg) {
        AbortNode(msg);
        return Error();
    }
    bool IsValid() {
        return mode == MODE_VALID;
    }
    bool IsInvalid() {
        return mode == MODE_INVALID;
    }
    bool IsError() {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int &nDoSOut) {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
};







/** Describes a place in the block chain to another node such that if the           Обозначает место в цепи блоков на другом узле так, что если другой узел
 * other node doesn't have the same branch, it can find a recent common trunk.      не имеет ту же ветку, он может найти последнее общее продолжение цепи(ствола).
 * The further back it is, the further before the fork it may be.                   В дальнейшем, далее до вилки может быть.
 */
class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:
    CBlockLocator() {}

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock);

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }

    /** Given a block initialises the locator to that point in the chain.           Данный блок инициализирует локатор на этой точке в цепи.*/
    void Set(const CBlockIndex* pindex);
    /** Returns the distance in blocks this locator is from our chain head.         Возвращает расстояние в блоках этого локатора от головы нашей цепи.*/
    int GetDistanceBack();
    /** Returns the first best-chain block the locator contains.                    Возвращает первый блок лучшие цепь который локатор содержит. */
    CBlockIndex* GetBlockIndex();
    /** Returns the hash of the first best chain block the locator contains.        Возвращает хэш первого лучшего блока цепи содержащихся в локаторе. */
    uint256 GetBlockHash();
    /** Returns the height of the first best chain block the locator has.           Возвращает высоту первого лучшего блока цепи который локатор имеет. */
    int GetHeight();
};








class CTxMemPool
{
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;

    bool accept(CValidationState &state, CTransaction &tx, bool fLimitFree, bool* pfMissingInputs);
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    bool remove(const CTransaction &tx, bool fRecursive = false);
    bool removeConflicts(const CTransaction &tx);
    void clear();
    void queryHashes(std::vector<uint256>& vtxid);
    void pruneSpent(const uint256& hash, CCoins &coins);

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    bool exists(uint256 hash)
    {
        return (mapTx.count(hash) != 0);
    }

    CTransaction& lookup(uint256 hash)
    {
        return mapTx[hash];
    }
};

extern CTxMemPool mempool;

struct CCoinsStats
{
    int nHeight;
    uint256 hashBlock;
    uint64 nTransactions;
    uint64 nTransactionOutputs;
    uint64 nSerializedSize;
    uint256 hashSerialized;
    int64 nTotalAmount;

    CCoinsStats() : nHeight(0), hashBlock(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), hashSerialized(0), nTotalAmount(0) {}
};

/** Abstract view on the open txout dataset.                                        Абстрактное представление об открытом txout наборе данных */
class CCoinsView
{
public:
    // Retrieve the CCoins (unspent transaction outputs) for a given txid           Получить CCoins (неизрасходованные выходы сделки) для данного TXID
    virtual bool GetCoins(const uint256 &txid, CCoins &coins);

    // Modify the CCoins for a given txid                                           Изменить CCoins для данной TXID
    virtual bool SetCoins(const uint256 &txid, const CCoins &coins);

    // Just check whether we have data for a given txid.                            Просто проверить, есть ли у нас данные для данной TXID.
    // This may (but cannot always) return true for fully spent transactions        Это может (но не всегда) возвращать true для полностью потраченных транзакциях
    virtual bool HaveCoins(const uint256 &txid);

    // Retrieve the block index whose state this CCoinsView currently represents    Получить индекс блока, состояние этого CCoinsView в настоящее время представляет
    virtual CBlockIndex *GetBestBlock();

    // Modify the currently active block index                                      Изменение текущего активного блока индексов
    virtual bool SetBestBlock(CBlockIndex *pindex);

    // Do a bulk modification (multiple SetCoins + one SetBestBlock)                При массовой модификации (несколько SetCoins + один SetBestBlock)
    virtual bool BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex);

    // Calculate statistics about the unspent transaction output set                Вычислить статистику относительно неизрасходованного набора выходной транзакции
    virtual bool GetStats(CCoinsStats &stats);

    // As we use CCoinsViews polymorphically, have a virtual destructor             Так как мы используем CCoinsViews полиморфно, иметь виртуальный деструктор
    virtual ~CCoinsView() {}
};

/** CCoinsView backed by another CCoinsView                                         CCoinsView опирается на другой CCoinsView  */
class CCoinsViewBacked : public CCoinsView
{
protected:
    CCoinsView *base;

public:
    CCoinsViewBacked(CCoinsView &viewIn);
    bool GetCoins(const uint256 &txid, CCoins &coins);
    bool SetCoins(const uint256 &txid, const CCoins &coins);
    bool HaveCoins(const uint256 &txid);
    CBlockIndex *GetBestBlock();
    bool SetBestBlock(CBlockIndex *pindex);
    void SetBackend(CCoinsView &viewIn);
    bool BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex);
    bool GetStats(CCoinsStats &stats);
};

/** CCoinsView that adds a memory cache for transactions to another CCoinsView      CCoinsView, добавляет в кэш-память для транзакций на другой CCoinsView)*/
class CCoinsViewCache : public CCoinsViewBacked
{
protected:
    CBlockIndex *pindexTip;
    std::map<uint256,CCoins> cacheCoins;

public:
    CCoinsViewCache(CCoinsView &baseIn, bool fDummy = false);

    // Standard CCoinsView methods                                                  Стандартные CCoinsView методы
    bool GetCoins(const uint256 &txid, CCoins &coins);
    bool SetCoins(const uint256 &txid, const CCoins &coins);
    bool HaveCoins(const uint256 &txid);
    CBlockIndex *GetBestBlock();
    bool SetBestBlock(CBlockIndex *pindex);
    bool BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex);

    // Return a modifiable reference to a CCoins. Check HaveCoins first.            Возвращает ссылку на модифицированные CCoins. Проверьте HaveCoins первым.
    // Many methods explicitly require a CCoinsViewCache because of this method,    Многие методы явно требуют CCoinsViewCache из-за этого способа,
    // to reduce copying.                                                           для сокращения копирования.
    CCoins &GetCoins(const uint256 &txid);

    // Push the modifications applied to this cache to its base. Failure to call    Протолкните приложенные модификации в кэш на его базу. Если не вызывать
    // this method before destruction will cause the changes to be forgotten.       этот метод до деструктора, сделанные изменения будут забыты.
    bool Flush();

    // Calculate the size of the cache (in number of transactions)                  Вычислить размер кэша (в количестве сделок)
    unsigned int GetCacheSize();

    /** Amount of bitcoins coming in to a transaction
        Note that lightweight clients may not know anything besides the hash of previous transactions,
        so may not be able to calculate this.
                        Количество Bitcoins вхождений в транзакции
                        Обратите внимание, что легкие клиенты могут не знать ничего, кроме хэша предыдущих сделок,
                        таким образом, не могут быть в состоянии что бы вычислить это.

        @param[in] tx	transaction for which we are checking input total           сделки для которых мы проверяем input total
        @return	Sum of value of all inputs (scriptSigs)
        @see CTransaction::FetchInputs
     */
    int64 GetValueIn(const CTransaction& tx);
    
    // Check whether all prevouts of the transaction are present in the UTXO set set represented by this view
    //                  Проверьте, все ли prevouts сделки присутствуют в наборе UTXO представленном для рассмотрения
    bool HaveInputs(const CTransaction& tx);

    const CTxOut &GetOutputFor(const CTxIn& input);

private:
    std::map<uint256,CCoins>::iterator FetchCoins(const uint256 &txid);
};

/** CCoinsView that brings transactions from a memorypool into view.                CCoinsView который переносит транзакции из MemoryPool в поле зрения.
    It does not check for spendings by memory pool transactions.                    Он не проверяет траты для транзакций пула памяти.
 */
class CCoinsViewMemPool : public CCoinsViewBacked
{
protected:
    CTxMemPool &mempool;

public:
    CCoinsViewMemPool(CCoinsView &baseIn, CTxMemPool &mempoolIn);
    bool GetCoins(const uint256 &txid, CCoins &coins);
    bool HaveCoins(const uint256 &txid);
};

/** Global variable that points to the active CCoinsView (protected by cs_main)    Глобальная переменная, которая указывает на активную CCoinsView*/
extern CCoinsViewCache *pcoinsTip;

/** Global variable that points to the active block tree (protected by cs_main)    Глобальная переменная, которая указывает на активное дерево блок*/
extern CBlockTreeDB *pblocktree;

struct CBlockTemplate
{
    CBlock block;
    std::vector<int64_t> vTxFees;
    std::vector<int64_t> vTxSigOps;
    CBigNum sumTrDif;
};




/** Used to relay blocks as header + vector<merkle branch>                          Используется для передачи блоков, как заголовок + vector<merkle branch>
 * to filtered nodes.                                                               в отфильтрованных узлах.
 */
class CMerkleBlock
{
public:
    // Public only for unit testing                                                 Паблик только для модульного тестирования
    CBlockHeader header;
    CPartialMerkleTree txn;

public:
    // Public only for unit testing and relay testing                               Паблик только для модульного тестирования и испытания трансляции
    // (not relayed)                                                                (не передается)
    std::vector<std::pair<unsigned int, uint256> > vMatchedTxn;

    // Create from a CBlock, filtering transactions according to filter             Создаётя из CBLOCK, фильтрует транзакции в соответствии с фильтром
    // Note that this will call IsRelevantAndUpdate on the filter for each          Заметим, что это вызовет IsRelevantAndUpdate на фильтре для каждой
    // transaction, thus the filter will likely be modified.                        сделки, при этом фильтр, вероятно, будет изменен.
    CMerkleBlock(const CBlock& block, CBloomFilter& filter);

    IMPLEMENT_SERIALIZE
    (
        READWRITE(header);
        READWRITE(txn);
    )
};

#endif
