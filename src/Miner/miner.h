// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "Models/transaction.h"
#include "Wallet/wallet.h"
#include "Lyra2RE.h"

/** Run the miner threads                                                           Запуск miner потоков */
void GenerateCoins(bool fGenerate, CWallet* pwallet);
/** Generate a new block, without valid proof-of-work                               Генерация нового блока, без валидного proof-of-work */
CBlockTemplate* CreateNewBlock(CReserveKey& reservekey);
/** Modify the extranonce in a block                                                Изменение extranonce в блоке */
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
/** Do mining precalculation                                                        Сделать предварительное вычисление майнинга  */
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
/** Check mined block                                                               Проверить добытый блок*/
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey, CBigNum psumTrDif);
/** Base sha256 mining transform                                                    Базовое sha256 майнинг преобразование  */
void SHA256Transform(void* pstate, void* pinput, const void* pinit);

#endif // BITCOIN_MINER_H
