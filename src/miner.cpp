// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core.h"
#include "wallet.h"
#include "miner.h"
#include "main.h"


//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

//
// ScanHash scans nonces looking for a hash with at least some zero bits.       ScanHash сканирует nonce, ища для хэш с по крайней мере несколькими нулевыми битами
// It operates on big endian data.  Caller does the byte reversing.             Это работает на big endian данных. Вызывающий делает изменение байта
// All input buffers are 16-byte aligned.  nNonce is usually preserved          Все входные буферы 16-байтово выровнены. nNonce обычно сохраняются между вызовами,
// between calls, but periodically or if nNonce is 0xffff0000 or above,         но периодически или если nNonce становится 0xffff0000 или выше, блок перестраивается
// the block is rebuilt and nNonce starts over at zero.                         и nNonce начинается заново с нуля.
//
unsigned int static ScanHash_CryptoPP(char* pmidstate, char* pdata, char* phash1, char* phash, unsigned int& nHashesDone)
{
    unsigned int& nNonce = *(unsigned int*)(pdata + 12);
    for (;;)
    {
        // Crypto++ SHA256
        // Hash pdata using pmidstate as the starting state into                Hash pdata использоует pmidstate как начальное состояние в предварительно
        // pre-formatted buffer phash1, then hash phash1 into phash             отформатированном буфере phash1, затем хэш phash1 в phash
        nNonce++;
        SHA256Transform(phash1, pdata, pmidstate);
        SHA256Transform(phash, phash1, pSHA256InitState);

        // Return the nonce if the hash has at least some zero bits,            Возвращает nonce, если хэш имеет по крайней мере некоторые нулевых бит
        // caller will check if it has enough to reach the target               вызывающий объект будет проверить если это достаточно для достижения цели
        if (((unsigned short*)phash)[14] == 0)
            return nNonce;

        // If nothing found after trying for a while, return -1                 Если ничего не найдено после этого, возвращение -1
        if ((nNonce & 0xffff) == 0)
        {
            nHashesDone = 0xffff+1;
            return (unsigned int) -1;
        }
        if ((nNonce & 0xfff) == 0)
            boost::this_thread::interruption_point();
    }
}

// Some explaining would be appreciated                                         Некоторые толкования(объяснения) будут оценены
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().c_str(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().c_str());
    }
};


uint64 nLastBlockTx = 0;
uint64 nLastBlockSize = 0;

// We want to sort transactions by priority and fee, so:                            Мы хотим, отсортировать транзакции по приоритету и комиссии, так:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

/*************************** новое ******************************/

//typedef boost::tuple<uint256, CTransaction&, CScript> TxHashPriority;
//class TxHashPriorityCompare
//{
//    bool byHash;
//public:
//    TxHashPriorityCompare(bool _byHash) : byHash(_byHash) { }
//    bool operator()(const TxHashPriority& a, const TxHashPriority& b)
//    {
//        return a.get<0>() < b.get<0>();
//    }
//};

/*************************** новое ******************************/


CBlockTemplate* CreateNewBlock(CReserveKey& reservekey)
{
    // Create new block                                                             Создание нового блока
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience             точка для удобства

    // Create coinbase tx                                                           Создание монетнойбазы транзакций
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey))
        return NULL;
    txNew.vout[0].scriptPubKey << pubkey << OP_CHECKSIG;

    // Add our coinbase tx as first transaction                                     Добавьте нашу coinbase tx как первую транзакцию
    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1); // updated at end                        обновить в конце
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end                      обновить в конце

    // Largest block you're willing to create:                                      Крупнейший блок вы готовы создавать:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:                       Ограничения в диапазоне от 1K и MAX_BLOCK_SIZE-1K для здравого смысла.
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,     Сколько в блоке должно быть выделенно первоочередным транзакциям,
    // included regardless of the fees they pay                                     включая независимо от сборов, которые они платят
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions       Минимальный размер блока который вы хотите создать; блок будет заполняться
    // until there are no more or the block reaches this size:                      бесплатными транзакциями до тех пор, пока будет не более или блок достигает этого размера:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block                              Собрать memory pool транзакций в блоке
    int quantityGoodHashTr = 0;                                                                             ////////// новое //////////
    int quantityGoodFeesTr = 0;                                                                             ////////// новое //////////
    uint256 targetGoodTr = uint256("0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");   ////////// новое //////////
    int64 nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = pindexBest;
        CCoinsViewCache view(*pcoinsTip, true);

        // Priority order to process transactions                                   Порядок приоритета для обработки транзакций
        list<COrphan> vOrphan; // list memory doesn't move                          Список памяти не перемещается
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:                        Этот вектор будет отсортирован в приоритетной очереди:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());

        vector<TxHashPriority> vecTxHashPriority;                               ////////// новое //////////
        vecTxHashPriority.reserve(mempool.mapTx.size());                        ////////// новое //////////

        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;
            if (tx.IsCoinBase() || !IsFinalTx(tx))
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64 nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction                                            Чтение предыдущей транзакции
                if (!view.HaveCoins(txin.prevout.hash))
                {
                    // This should never happen; all transactions in the memory     Это должно никогда не случаться; все транзакции в пуле памяти
                    // pool should connect to either transactions in the chain      должны подключаться к любой транзакции в цепочке
                    // or other transactions in the memory pool.                    или другим транзакциям в пуле памяти.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies                                 Должен ждать зависимостей
                    if (!porphan)
                    {
                        // Use list for automatic deletion                          Использует список для автоматического удаления
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;       // а не лишнее ли это(одно из двух)
                    continue;                                                                   // <-- не лишнее, всё в порядке !!!
                }
                const CCoins &coins = view.GetCoins(txin.prevout.hash);

                int64 nValueIn = coins.vout[txin.prevout.n].nValue;                                 // а не лишнее ли это(одно из двух)
                nTotalIn += nValueIn;

                int nConf = pindexPrev->nHeight - coins.nHeight + 1;

                dPriority += (double)nValueIn * nConf;
            }

            if (fMissingInputs) continue;

            // Priority(приоритет) is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            //                  Это более точное плата-за-килобайт, чем используемая клиентским кодом, так как
            //                  код клиента округляет размер до ближайшего 1K. Это хорошо, потому что это дает
            //                  стимул для создания меньших транзакций.
            double dFeePerKb =  double(nTotalIn-GetValueOut(tx)) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
        }

        // Collect transactions into block                                          Собрать транзакции в блок
        uint64 nBlockSize = 1000;
        uint64 nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:            Брать наивысший приоритет транзакции вне очереди приоритета:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);    //     одно           удаление элемента из кучи
            vecPriority.pop_back();                                             //   удаление         удаление последнего элемента вектора

            // Size limits                                                          Ограничения размера
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:                                             Старые ограничения на sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Skip free transactions if we're past the minimum block size:         Пропустить бесплатные транзакции если мы за пределами минимального размера блока:
            if (fSortedByFee && (dFeePerKb < CTransaction::nMinTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority     Приоритет по комиссии после приоритета по размеру
            // transactions:                                                                    или мы исчерпали приоритетные транзакции
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!view.HaveInputs(tx))
                continue;

            int64 nTxFees = view.GetValueIn(tx)-GetValueOut(tx);

            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            CValidationState state;
            if (!CheckInputs(tx, state, view, true, SCRIPT_VERIFY_P2SH))
                continue;

/*************************** новое ******************************/

            TransM trM;

            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                trM.vinM.push_back(CTxIn(txin.prevout.hash, txin.prevout.n));       ////////// новое //////////

            trM.voutM = tx.vout;                                                    ////////// новое //////////
            BOOST_FOREACH (CTxOut& out, trM.voutM)                                  ////////// новое //////////
                out.scriptPubKey = CScript();                                       ////////// новое //////////

            trM.hashBlock = vBlockIndexByHeight[tx.tBlock]->GetBlockHash();         ////////// новое //////////
            //trM.hashBlock = pindexBest->pprev->GetBlockHash();                      ////////// новое //////////

            uint256 HashTrM = SerializeHash(trM);                                   ////////// новое //////////

            const CCoins &coins = view.GetCoins(tx.vin[0].prevout.hash);
            vecTxHashPriority.push_back(TxHashPriority(HashTrM, CTxOut(nTxFees, coins.vout[tx.vin[0].prevout.n].scriptPubKey)));

            if (nTxFees > 0)                                                        ////////// новое //////////
                quantityGoodFeesTr++;                                               ////////// новое //////////
            if (HashTrM < targetGoodTr)                                             ////////// новое //////////
                quantityGoodHashTr++;                                               ////////// новое //////////

/*************************** новое ******************************/

            CTxUndo txundo;
            uint256 hash = tx.GetHash();
            UpdateCoins(tx, state, view, txundo, pindexPrev->nHeight+1, hash);      // очень много я об это спотыкался

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;


            if (fPrintPriority)
            {
                printf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
            }

            // Add transactions that depend on this one to the priority queue       Добавление транзакции, которые зависят от этого в приоритетной очереди
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        TxHashPriorityCompare comparerHash(true);                                                   ////////// новое //////////
        std::sort(vecTxHashPriority.begin(), vecTxHashPriority.end(), comparerHash);                ////////// новое //////////


        int retFeesTr = 0;                                                      // определяем количество
        while (quantityGoodFeesTr > 1 + (8 + 2 * (retFeesTr + 1)) * retFeesTr)  // транзакций с возвратом
            retFeesTr++;                                                        // увеличенной комиссии
//        {
//            printf("***while*** %i - %i \n", retFeesTr, 1 + (8 + 2 * (retFeesTr + 1)) * retFeesTr);
//        }
//printf("===>> retFeesTr = %i\n", retFeesTr);

        if (retFeesTr > 0)
            retFeesTr = (quantityGoodFeesTr / 2) / retFeesTr;   // во сколько раз нужно будет умножить комиссию
                       //quantityGoodFeesTr /= 2 транзакциям достаётся ~50% комиссий

printf("\n===>> quantityGoodFeesTr = %i   quantityGoodHashTr = %i   retFeesTr = %i\n", quantityGoodFeesTr, quantityGoodHashTr, retFeesTr);

        int64 threshold = nFees * 0.51;                         // порог возврата транзакциям - суммарная величина будет меньше или много меньше 51%
        unsigned int step = 0;
        unsigned int ii = 0;
printf("===>> vecTxHashPriority.size() = %i\n", vecTxHashPriority.size());
        BOOST_FOREACH (const TxHashPriority& THP, vecTxHashPriority)  // сделать костантным
        {
            int64 ret = THP.get<1>().nValue * retFeesTr;

            if (ii == 1 + (8 + 2 * (step + 1)) * step)
            {
                if (THP.get<0>() > targetGoodTr)                // только тр. с хорошим хешем
                    break;

                if (ret < threshold)
                {
                    pblock->vtx[0].vout.push_back(CTxOut(ret, THP.get<1>().scriptPubKey));
printf("=!!!==>> vecTxHashPriority   hashTr: %s  %"PRI64d"  step = %i\n", THP.get<0>().GetHex().c_str(), ret, step);
                    nFees -= ret;
                    threshold -= ret;
                }
                else if (THP.get<1>().nValue < threshold)       // здесь что либо подобное этому CTransaction::nMinTxFee вроде бы ненужно
                {
                    pblock->vtx[0].vout.push_back(CTxOut(threshold, THP.get<1>().scriptPubKey));
printf("=!!!==>> vecTxHashPriority   hashTr: %s  %"PRI64d"  step = %i  threshold\n", THP.get<0>().GetHex().c_str(), threshold, step);
                    nFees -= threshold;
                    threshold = 0;
                }
                step++;
            }
            ii++;

printf("===>> vecTxHashPriority   hashTr: %s  %"PRI64d"  step = %i  ii = %i\n", THP.get<0>().GetHex().c_str(), THP.get<1>().nValue, step, ii);
        }


        int64 NewCoin = GetBlockValue(pindexPrev->nHeight+1, nFees);

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        printf("CreateNewBlock(): total size %"PRI64u"\n", nBlockSize);

        pblock->vtx[0].vout[0].nValue = NewCoin;
        pblock->vtx[0].tBlock = pindexPrev->nHeight - 1;              ////////// новое ////////// можно здесь и 0 оставить

        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header                                                           Заполнение заголовка
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        UpdateTime(*pblock, pindexPrev);
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock);
        pblock->nNonce         = 0;
        pblock->vtx[0].vin[0].scriptSig = CScript() << OP_0 << OP_0;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        CBlockIndex indexDummy(*pblock);
        indexDummy.pprev = pindexPrev;
        indexDummy.nHeight = pindexPrev->nHeight + 1;
        CCoinsViewCache viewNew(*pcoinsTip, true);
        CValidationState state;
        if (!ConnectBlock(*pblock, state, &indexDummy, viewNew, true))
            throw std::runtime_error("CreateNewBlock() : ConnectBlock failed");
    }

    return pblocktemplate.release();
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first(высота первого) in coinbase required(требуется) for block.version=2
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers                                                       Пред-постройка хэш буферов
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer                                               Байт подкачки всего входного буфера
    for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant               Предварительный расчет первой половины первого хэша, который остается постоянным
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hash = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if (hash > hashTarget)
        return false;

    //// debug print
    printf("BitcoinMiner:\n");
    printf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution                                                             Найденное решение
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("BitcoinMiner : generated block is stale");

        // Remove key from key pool                                                 Удаление ключа из пула ключей
        reservekey.KeepKey();

        // Track how many getdata requests this block gets                          Отследить сколько getdata запрасов этот блок получает
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }

        // Process this block the same as if we had received it from another node   Обработать этот блок такой же, как если бы мы получили ее от другого узла
        CValidationState state;
        if (!ProcessBlock(state, NULL, pblock))
            return error("BitcoinMiner : ProcessBlock, block not accepted");
    }

    return true;
}

void static BitcoinMiner(CWallet *pwallet)
{
    printf("BitcoinMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("---TTC---miner");

    // Each thread has its own key and counter                                      Каждый поток имеет свой собственный ключ и счетчик
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    try { while (true) {
        if (Params().NetworkID() != CChainParams::REGTEST) {
            // Busy-wait for the network to come online so we don't waste time      Занят-ожидание для сети, чтобы перейти в оперативный режим, так что бы мы не
            // mining on an obsolete chain. In regtest mode we expect to fly solo.  тратили время добычи на устаревшей цепи. В режиме regtest мы ожидаем прилёта самостоятельно.
            while (vNodes.empty())
                MilliSleep(1000);
        }

        //
        // Create new block                                                         создание нового блока
        //
        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;

        auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(reservekey));
        if (!pblocktemplate.get())
            return;
        CBlock *pblock = &pblocktemplate->block;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        printf("Running BitcoinMiner with %"PRIszu" transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Pre-build hash buffers                                                   Предварительная постройка хэш буферов
        //
        char pmidstatebuf[32+16]; char* pmidstate = alignup<16>(pmidstatebuf);
        char pdatabuf[128+16];    char* pdata     = alignup<16>(pdatabuf);
        char phash1buf[64+16];    char* phash1    = alignup<16>(phash1buf);

        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        unsigned int& nBlockTime = *(unsigned int*)(pdata + 64 + 4);
        unsigned int& nBlockBits = *(unsigned int*)(pdata + 64 + 8);
        unsigned int& nBlockNonce = *(unsigned int*)(pdata + 64 + 12);


        //
        // Search
        //
        int64 nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        uint256 hashbuf[2];
        uint256& hash = *alignup<16>(hashbuf);
        while (true)
        {
            unsigned int nHashesDone = 0;
            unsigned int nNonceFound;

            // Crypto++ SHA256
            nNonceFound = ScanHash_CryptoPP(pmidstate, pdata + 64, phash1,
                                            (char*)&hash, nHashesDone);

            // Check if something found                                             Проверка, если что-то нашли
            if (nNonceFound != (unsigned int) -1)
            {
                for (unsigned int i = 0; i < sizeof(hash)/4; i++)
                    ((unsigned int*)&hash)[i] = ByteReverse(((unsigned int*)&hash)[i]);

                if (hash <= hashTarget)
                {
                    // Found a solution                                             Найденное решение
                    pblock->nNonce = ByteReverse(nNonceFound);
                    assert(hash == pblock->GetHash());

                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock, *pwallet, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);

                    // In regression test mode, stop mining after a block is found. This        В регрессивном тестовом режиме, остановить добычу после найденного блока.
                    // allows developers to controllably generate a block on demand.            Это позволяет разработчикам контролируемо генерировать блок по требованию.
                    if (Params().NetworkID() == CChainParams::REGTEST)
                        throw boost::thread_interrupted();

                    break;
                }
            }

            // Meter hashes/sec                                                     Измеритель хешей в секунду
            static int64 nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;
            if (GetTimeMillis() - nHPSTimerStart > 4000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                        static int64 nLogTime;
                        if (GetTime() - nLogTime > 30 * 60)
                        {
                            nLogTime = GetTime();
                            printf("hashmeter %6.0f khash/s\n", dHashesPerSec/1000.0);
                        }
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt                       Проверка для остановки или если блок должен быть перестроен
            boost::this_thread::interruption_point();
            if (vNodes.empty() && Params().NetworkID() != CChainParams::REGTEST)
                break;
            if (nBlockNonce >= 0xffff0000)
                break;
            if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != pindexBest)
                break;

            // Update nTime every few seconds                                       Обновление nTime каждые несколько секунд
            UpdateTime(*pblock, pindexPrev);
            nBlockTime = ByteReverse(pblock->nTime);
            if (TestNet())
            {
                // Changing pblock->nTime can change work required on testnet:      Изменение pblock->Ntime можете изменить работу, необходимую на testnet:
                nBlockBits = ByteReverse(pblock->nBits);
                hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
            }
        }
    } }
    catch (boost::thread_interrupted)
    {
        printf("BitcoinMiner terminated\n");
        throw;
    }
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    static boost::thread_group* minerThreads = NULL;

    int nThreads = GetArg("-genproclimit", -1);
    if (nThreads < 0) {
        if (Params().NetworkID() == CChainParams::REGTEST)
            nThreads = 1;
        else
            nThreads = boost::thread::hardware_concurrency();
    }

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&BitcoinMiner, pwallet));
}
