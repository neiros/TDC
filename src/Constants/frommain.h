//
// Created by Polaris on 18-May-20.
//

#ifndef TDC_CORE_FROMMAIN_H
#define TDC_CORE_FROMMAIN_H

#include "Helpers/util.h"   // for int64

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

/**
 *                  Переход на другой алгоритм будет после этой высоты блокчейна */
static const int HEIGHT_OTHER_ALGO = 75000;                        ////////// новое //////////


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

#endif //TDC_CORE_FROMMAIN_H
