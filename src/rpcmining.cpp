// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "db.h"
#include "init.h"
#include "miner.h"
#include "bitcoinrpc.h"

using namespace json_spirit;
using namespace std;

// Key used by getwork/getblocktemplate miners.                                 Ключь, используемый для getwork/getblocktemplate майнеров
// Allocated in InitRPCMining, free'd in ShutdownRPCMining                      Выделенный в InitRPCMining, освобожденный в ShutdownRPCMining
static CReserveKey* pMiningKey = NULL;

void InitRPCMining()
{
    // getwork/getblocktemplate mining rewards paid here:                       getwork/getblocktemplate майнинг вознаграждение выплачивается здесь:
    pMiningKey = new CReserveKey(pwalletMain);
}

void ShutdownRPCMining()
{
    delete pMiningKey; pMiningKey = NULL;
}


Value usetxinblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "usetxinblock <hash>\n"
            "Returns an object containing block and transaction hashes related information.");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    ReadBlockFromDisk(block, pblockindex);

    int64 txFees = 0;
    BOOST_FOREACH(CTransaction& tx, block.vtx)
    {
        if (!tx.IsCoinBase())
        {
            int64 nIn = 0;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                CTransaction getTx;
                const uint256 txHash = txin.prevout.hash;
                uint256 hashBlock = 0;
                if (GetTransaction(txHash, getTx, hashBlock, false))
                    nIn += getTx.vout[txin.prevout.n].nValue;
                //else проверка ошибок, если нужно
            }

            int64 nOut = 0;
            BOOST_FOREACH (CTxOut& out, tx.vout)
            {
                nOut += out.nValue;
            }

            txFees = nIn - nOut;
        }
    }

    Object obj;
    obj.push_back(Pair("block",             block.GetHash().GetHex()));
    obj.push_back(Pair("tx",                (boost::int64_t)block.vtx.size() - 1));
    obj.push_back(Pair("txFees",            ValueFromAmount(txFees)));
    obj.push_back(Pair("subsidy block",     ValueFromAmount(GetBlockValue(pblockindex->nHeight, txFees))));

    for (int i = 0; i < (int)BLOCK_TX_FEE; i++)
        obj.push_back(Pair(" - block", vBlockIndexByHeight[pblockindex->nHeight - i - 1]->GetBlockHash().GetHex()));


    vector<TxHashPriority> vecTxHashPriority;
    std::map<uint256, uint256> mapTxHashes;

    if (pblockindex->nHeight > int(BLOCK_TX_FEE + NUMBER_BLOCK_TX))
    {
        uint256 useHashBack;
        for (unsigned int i = 0; i < NUMBER_BLOCK_TX; i++)                      // получение транзакций которым возможен возврат комиссий
        {
            CBlock rBlock;
            ReadBlockFromDisk(rBlock, vBlockIndexByHeight[pblockindex->nHeight - BLOCK_TX_FEE - i - 1]);             // -5, -6, -7, -8, -9 блоки


            obj.push_back(Pair("block",     rBlock.GetHash().GetHex()));
            obj.push_back(Pair("tx",        (boost::int64_t)rBlock.vtx.size() - 1));


            if (i == 0)
                useHashBack = rBlock.GetHash();                                 // хэш(uint256) блока для определения случайных позиций

            BOOST_FOREACH(CTransaction& tx, rBlock.vtx)
            {
                if (!tx.IsCoinBase())
                {
                    TransM trM;

                    int64 nIn = 0;
                    BOOST_FOREACH(const CTxIn& txin, tx.vin)
                    {
                        trM.vinM.push_back(CTxIn(txin.prevout.hash, txin.prevout.n));

                        CTransaction getTx;
                        const uint256 txHash = txin.prevout.hash;
                        uint256 hashBlock = 0;
                        if (GetTransaction(txHash, getTx, hashBlock, false))
                            nIn += getTx.vout[txin.prevout.n].nValue;
                        //else проверка ошибок, если нужно
                    }

                    int64 nOut = 0;
                    BOOST_FOREACH (CTxOut& out, tx.vout)
                    {
                        trM.voutM.push_back(CTxOut(out.nValue, CScript()));
                        nOut += out.nValue;
                    }

                    int64 nTxFees = nIn - nOut;

                    trM.hashBlock = vBlockIndexByHeight[tx.tBlock]->GetBlockHash();

                    uint256 HashTrM = SerializeHash(trM);
                    lyra2re2_hashTX(BEGIN(HashTrM), BEGIN(HashTrM), 32);

                    CTransaction getTx;
                    const uint256 txHash = tx.vin[0].prevout.hash;
                    uint256 hashBlock = 0;
                    if (GetTransaction(txHash, getTx, hashBlock, false))
                        vecTxHashPriority.push_back(TxHashPriority(HashTrM, CTxOut(nTxFees, getTx.vout[tx.vin[0].prevout.n].scriptPubKey)));

                    mapTxHashes[HashTrM] = tx.GetHash();
                }
            }

            if (vecTxHashPriority.size() > QUANTITY_TX)
                break;
        }

        obj.push_back(Pair("total tx",     (boost::int64_t)vecTxHashPriority.size()));

        if (vecTxHashPriority.size() > 1)
        {
            TxHashPriorityCompare comparerHash(true);
            std::sort(vecTxHashPriority.begin(), vecTxHashPriority.end(), comparerHash);


            double powsqrt = (useHashBack & CBigNum(uint256(65535)).getuint256()).getdouble() * 0.00001 + 1.2;  // получаем число от 1,2 до 1,85535
            unsigned int stepTr = pow((double)vecTxHashPriority.size(), 1.0 / powsqrt);                         // величина промежутка
            unsigned int numPosition = vecTxHashPriority.size() / stepTr;                                       // количество промежутков
            unsigned int arProgression = stepTr / numPosition;          // аргумент арифметической прогрессии при котором последний промежуток почти равен первым двум

            obj.push_back(Pair("random one",         powsqrt));
            powsqrt = (useHashBack & CBigNum(uint256(262143)).getuint256()).getdouble() * 0.000001;             // число от 0 до 0,262143
            obj.push_back(Pair("random two",         0.4 + powsqrt));
            unsigned int retFeesTr = (stepTr + 1) * (0.4 + powsqrt);    // во сколько раз нужно умножить возвращаемую комиссию (+1 чтобы не было 0)


            unsigned int pos = 0;
            unsigned int nextInt = 0;
            unsigned int ntx = 0;
            unsigned int www = 0;
            unsigned int iii = 0;
            BOOST_FOREACH(const TxHashPriority& tx, vecTxHashPriority)
            {
                if (nextInt == iii)
                {
                    useHashBack = Hash(BEGIN(useHashBack),  END(useHashBack));
                    unsigned int interval = stepTr + www * arProgression;                     // разбивка vecTxHashPriority на промежутки
                    pos = nextInt + interval * (useHashBack & CBigNum(uint256(1048575)).getuint256()).getdouble() / 1048575.0;   // получаем число от 0 до 1
                    nextInt = iii + interval + 1;
                    www++;

                    obj.push_back(Pair("interval",              (boost::int64_t)interval));
                    obj.push_back(Pair("start next interval",   (boost::int64_t)nextInt));
                }

                if (iii == pos)
                {
                    ntx++;
                    obj.push_back(Pair("this",                  "tx"));
                    obj.push_back(Pair(tx.get<0>().GetHex(),    mapTxHashes[tx.get<0>()].GetHex()));
                    obj.push_back(Pair("fee",                   ValueFromAmount(tx.get<1>().nValue)));
                    obj.push_back(Pair("fee return",            ValueFromAmount(tx.get<1>().nValue * retFeesTr)));

                    CTxDestination address;
                    if (ExtractDestination(tx.get<1>().scriptPubKey, address))
                        obj.push_back(Pair("address",           CBitcoinAddress(address).ToString()));
                }
                else
                    obj.push_back(Pair(tx.get<0>().GetHex(),    mapTxHashes[tx.get<0>()].GetHex()));
                iii++;
            }
            obj.push_back(Pair("selected transactions",         (boost::int64_t)ntx));
            obj.push_back(Pair("increase fee in",               (boost::int64_t)retFeesTr));
        }
    }

    return obj;
}


// Return average network hashes per second based on the last 'lookup' blocks,
// or from the last difficulty change if 'lookup' is nonpositive.
// If 'height' is nonnegative, compute the estimate at the time when a given block was found.
Value GetNetworkHashPS(int lookup, int height) {
    CBlockIndex *pb = pindexBest;

    if (height >= 0 && height < nBestHeight)
        pb = FindBlockByHeight(height);

    if (pb == NULL || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pb->nHeight % 2016 + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64 minTime = pb0->GetBlockTime();
    int64 maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64 time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64 timeDiff = maxTime - minTime;

    return (boost::int64_t)(workDiff.getdouble() / timeDiff);
}

Value getnetworkhashps(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getnetworkhashps [blocks] [height]\n"
            "Returns the estimated network hashes per second based on the last 120 blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
            "Pass in [height] to estimate the network speed at the time when a certain block was found.");

    return GetNetworkHashPS(params.size() > 0 ? params[0].get_int() : 120, params.size() > 1 ? params[1].get_int() : -1);
}


Value getgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getgenerate\n"
            "Returns true or false.");

    return GetBoolArg("-gen", false);
}


Value setgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setgenerate <generate> [genproclimit]\n"
            "<generate> is true or false to turn generation on or off.\n"
            "Generation is limited to [genproclimit] processors, -1 is unlimited.");

    bool fGenerate = true;
    if (params.size() > 0)
        fGenerate = params[0].get_bool();

    if (params.size() > 1)
    {
        int nGenProcLimit = params[1].get_int();
        mapArgs["-genproclimit"] = itostr(nGenProcLimit);
        if (nGenProcLimit == 0)
            fGenerate = false;
    }
    mapArgs["-gen"] = (fGenerate ? "1" : "0");

    GenerateCoins(fGenerate, pwalletMain);
    return Value::null;
}


Value gethashespersec(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gethashespersec\n"
            "Returns a recent hashes per second performance measurement while generating.");

    if (GetTimeMillis() - nHPSTimerStart > 8000)
        return (boost::int64_t)0;
    return (boost::int64_t)dHashesPerSec;
}


Value getmininginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");

    Object obj;
    obj.push_back(Pair("blocks",           (int)nBestHeight));
    obj.push_back(Pair("currentblocksize", (uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",   (uint64_t)nLastBlockTx));
    obj.push_back(Pair("difficulty",       (double)GetDifficulty()));
    obj.push_back(Pair("errors",           GetWarnings("statusbar")));
    obj.push_back(Pair("generate",         GetBoolArg("-gen", false)));
    obj.push_back(Pair("genproclimit",     (int)GetArg("-genproclimit", -1)));
    obj.push_back(Pair("hashespersec",     gethashespersec(params, false)));
    obj.push_back(Pair("pooledtx",         (uint64_t)mempool.size()));
    obj.push_back(Pair("testnet",          TestNet()));
    return obj;
}


Value getwork(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "TTC is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "TTC is downloading blocks...");

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
    static vector<CBlockTemplate*> vNewBlockTemplate;

    if (params.size() == 0)
    {
        // Update block                                                         Обновление блока
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64 nStart;
        static CBlockTemplate* pblocktemplate;
        if (pindexPrev != pindexBest ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now             Освобождение старых блоков, так как они являются устаревшими теперь
                mapNewBlock.clear();
                BOOST_FOREACH(CBlockTemplate* pblocktemplate, vNewBlockTemplate)
                    delete pblocktemplate;
                vNewBlockTemplate.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            //                  Очистить pindexPrev так будущие getworks будут делать новый блок, несмотря на какие-либо ошибки
            pindexPrev = NULL;

            // Store the pindexBest used before CreateNewBlock, to avoid races  Сохранение pindexBest использующийся до CreateNewBlock, что бы избежать гонок
            nTransactionsUpdatedLast = nTransactionsUpdated;
            CBlockIndex* pindexPrevNew = pindexBest;
            nStart = GetTime();

            // Create new block                                                 Создание нового блока
            pblocktemplate = CreateNewBlock(*pMiningKey);
            if (!pblocktemplate)
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            vNewBlockTemplate.push_back(pblocktemplate);

            // Need to update only after we know CreateNewBlock succeeded       Необходимое обновление только после того, как мы узнаем, что CreateNewBlock удалось
            pindexPrev = pindexPrevNew;
        }
        CBlock* pblock = &pblocktemplate->block; // pointer for convenience

        // Update nTime                                                         обновление nTime
        UpdateTime(*pblock, pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce                                                   обновление nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Pre-build hash buffers                                               Предварительная сборка хеш буферов
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        Object result;
        result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated(возражать,устарело)
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated(возражать,устарело)
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));
        return result;
    }
    else
    {
        // Parse parameters                                                     Парсинг параметров
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        if (vchData.size() != 128)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse                                                         байт реверс
        for (int i = 0; i < 128/4; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

        // Get saved block                                                      Получить сохраненный блок
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;
        pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();


//*****************************************************************
        CBigNum maxBigNum = CBigNum(~uint256(0));
        CBigNum sumTrDif = 0;

        BOOST_FOREACH(CTransaction& tx, pblock->vtx)
        {
            TransM trM;

//            trM.vinM = tx.vin;    // почемуто в wallet.cpp подобное работает, а здесь нет
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                trM.vinM.push_back(CTxIn(txin.prevout.hash, txin.prevout.n));

            BOOST_FOREACH (const CTxOut& out, tx.vout)
                trM.voutM.push_back(CTxOut(out.nValue, CScript()));

            trM.hashBlock = vBlockIndexByHeight[tx.tBlock]->GetBlockHash();

            uint256 hashTr = SerializeHash(trM);
            lyra2re2_hashTX(BEGIN(hashTr), BEGIN(hashTr), 32);
            CBigNum bntx = CBigNum(hashTr);
            sumTrDif += maxBigNum / bntx;

//printf(">>>>> BOOST_FOREACH pblock->vtx    hashTr: %s    maxBigNum / bntx: %s   sumTrDif: %s\n", hashTr.GetHex().c_str(), (maxBigNum / bntx).ToString().c_str(), pblocktemplate->sumTrDif.ToString().c_str());
        }

        return CheckWork(pblock, *pwalletMain, *pMiningKey, sumTrDif);

//*****************************************************************
//        return CheckWork(pblock, *pwalletMain, *pMiningKey);
    }
}


Value getblocktemplate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::string strMode = "template";
    if (params.size() > 0)
    {
        const Object& oparam = params[0].get_obj();
        const Value& modeval = find_value(oparam, "mode");
        if (modeval.type() == str_type)
            strMode = modeval.get_str();
        else if (modeval.type() == null_type)
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "TTC is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "TTC is downloading blocks...");

    // Update block                                                             Обновление блока
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64 nStart;
    static CBlockTemplate* pblocktemplate;
    if (pindexPrev != pindexBest ||
        (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        //                  Очистить pindexPrev так будущие вызовы будут делать новый блок, несмотря на какие-либо ошибки
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrevNew = pindexBest;
        nStart = GetTime();

        // Create new block                                                     Создание нового блока
        if(pblocktemplate)
        {
            delete pblocktemplate;
            pblocktemplate = NULL;
        }
        pblocktemplate = CreateNewBlock(*pMiningKey);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded           Необходимое обновление только после того, как мы узнаем, что CreateNewBlock удалось
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience         Указатель для удобства

    // Update nTime                                                             Обновление nTime
    UpdateTime(*pblock, pindexPrev);
    pblock->nNonce = 0;

    Array transactions;
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    BOOST_FOREACH (CTransaction& tx, pblock->vtx)
    {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        Object entry;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));

        entry.push_back(Pair("hash", txHash.GetHex()));

        Array deps;
        BOOST_FOREACH (const CTxIn &in, tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.push_back(Pair("depends", deps));

        int index_in_template = i - 1;
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template]));
        entry.push_back(Pair("sigops", pblocktemplate->vTxSigOps[index_in_template]));

        transactions.push_back(entry);
    }

    Object aux;
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    static Array aMutable;
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    Object result;
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
    result.push_back(Pair("curtime", (int64_t)pblock->nTime));
    result.push_back(Pair("bits", HexBits(pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));

    return result;
}

Value submitblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    vector<unsigned char> blockData(ParseHex(params[0].get_str()));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    CBlock pblock;
    try {
        ssBlock >> pblock;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    CValidationState state;
    bool fAccepted = ProcessBlock(state, NULL, &pblock);
    if (!fAccepted)
        return "rejected"; // TODO: report validation state

    return Value::null;
}
