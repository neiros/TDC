// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "main.h"
#include "uint256.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    // How many times we expect transactions after the last checkpoint to           На сколько времени наше ожидание транзакции после последней контрольной точки
    // be slower. This number is a compromise, as it can't be accurate for          будет медленнее. Это число представляет собой компромисс, так как не может быть
    // every system. When reindexing from a fast disk with a slow CPU, it           точным для каждой системы. При переиндексации на быстром диски с медленным
    // can be up to 20, while when downloading from a slow network with a           процессором это может быть до 20, в то время как при загрузке из медленной сети
    // fast multicore CPU, it won't be much higher than 1.                          с быстрым многоядерным CPU, это не будет много выше, чем 1.
    static const double fSigcheckVerificationFactor = 5.0;

    struct CCheckpointData {
        const MapCheckpoints *mapCheckpoints;
        int64 nTimeLastCheckpoint;
        int64 nTransactionsLastCheckpoint;
        double fTransactionsPerDay;
    };

    bool fEnabled = true;

    // What makes a good checkpoint block?                                          Что является хорошим чекпоинтом - блоком?
    // + Is surrounded by blocks with reasonable timestamps                         + Окружен блоками с разумными временными метками
    //   (no blocks before with a timestamp after, none after with                    (нет блоков до с меткой времени после, нет после с меткой времени до)
    //    timestamp before)
    // + Contains no strange transactions                                           + Не содержит странные транзакции
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (0, uint256("0x00000009efba3f88db6f03373c7ff6f6be1b6f9ad21306b4eb26f65dfdffac8d"))
        ;
    static const CCheckpointData data = {
        &mapCheckpoints,
        1511875500, // * UNIX timestamp of last checkpoint block                            UNIX временная метка последней контрольной точки - блока
        1,          // * total number of transactions between genesis and last checkpoint   Общее количество сделок между генезисом и последней контрольной точкой
                    //   (the tx=... number in the SetBestChain debug.log lines)
        500         // * estimated number of transactions per day after checkpoint          Предполагаемое количество сделок в день после чекпоинта
    };

    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        (0, uint256("0x00000005a3478dec5f338f967df456a862e72b7fd614ff972053ce8ebd0f5329"))
        ;
    static const CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1511875961,
        1,
        1
    };

    const CCheckpointData &Checkpoints() {
        if (TestNet())
            return dataTestnet;
        else
            return data;
    }

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (!fEnabled)
            return true;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    // Guess how far we are in the verification process at the given block index        Угадать как далеко мы находимся в процессе проверки на данном блоке индекса
    double GuessVerificationProgress(CBlockIndex *pindex) {
        if (pindex==NULL)
            return 0.0;

        int64 nNow = time(NULL);

        double fWorkBefore = 0.0; // Amount of work done before pindex                  Объем работы, проделанный до pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)       Количество работы после pindex (по приблизительной оченке)
        // Work is defined as: 1.0 per transaction before the last checkoint, and       Работа определяется как: 1.0 за транзакцию до последнего checkoint и
        // fSigcheckVerificationFactor per transaction after.                           fSigcheckVerificationFactor за транзакцию после

        const CCheckpointData &data = Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->nTime)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int GetTotalBlocksEstimate()
    {
        if (!fEnabled)
            return 0;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        if (!fEnabled)
            return NULL;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }
}
