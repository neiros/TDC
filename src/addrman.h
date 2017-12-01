// Copyright (c) 2012 Pieter Wuille
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef _BITCOIN_ADDRMAN
#define _BITCOIN_ADDRMAN 1

#include "netbase.h"
#include "protocol.h"
#include "util.h"
#include "sync.h"


#include <map>
#include <vector>

#include <openssl/rand.h>


/** Extended statistics about a CAddress                                Расширенная статистика о CAddress  */
class CAddrInfo : public CAddress
{
private:
    // where knowledge about this address first came from               когда знания об этом адресе впервые прибыли
    CNetAddr source;

    // last successful connection by us                                 последнее успешное соединение с нам
    int64 nLastSuccess;

    // last try whatsoever by us:                                       последняя попытка чего-либо с нами
    // int64 CAddress::nLastTry

    // connection attempts since last successful attempt                попытки соединения с момента последней успешной попытки
    int nAttempts;

    // reference count in new sets (memory only)                        счетчик ссылок в новых наборах (только память)
    int nRefCount;

    // in tried set? (memory only)                                      при верных установках? (только память)
    bool fInTried;

    // position in vRandom                                              позиция в vRandom
    int nRandomPos;

    friend class CAddrMan;

public:

    IMPLEMENT_SERIALIZE(
        CAddress* pthis = (CAddress*)(this);
        READWRITE(*pthis);
        READWRITE(source);
        READWRITE(nLastSuccess);
        READWRITE(nAttempts);
    )

    void Init()
    {
        nLastSuccess = 0;
        nLastTry = 0;
        nAttempts = 0;
        nRefCount = 0;
        fInTried = false;
        nRandomPos = -1;
    }

    CAddrInfo(const CAddress &addrIn, const CNetAddr &addrSource) : CAddress(addrIn), source(addrSource)
    {
        Init();
    }

    CAddrInfo() : CAddress(), source()
    {
        Init();
    }

    // Calculate in which "tried" bucket this entry belongs             Вычислить в которой «попытке» bucket(ведро) эта запись принадлежит
    int GetTriedBucket(const std::vector<unsigned char> &nKey) const;

    // Calculate in which "new" bucket this entry belongs, given a certain source
    //      Вычислить к которому «new» bucket(ведру) принадлежит эта запись, учитывая определенный источник
    int GetNewBucket(const std::vector<unsigned char> &nKey, const CNetAddr& src) const;

    // Calculate in which "new" bucket this entry belongs, using its default source
    //      Вычислить к которому «new» bucket(ведру) принадлежит эта запись, с использованием источника по умолчанию
    int GetNewBucket(const std::vector<unsigned char> &nKey) const
    {
        return GetNewBucket(nKey, source);
    }

    // Determine whether the statistics about this entry are bad enough so that it can just be deleted
    //      Определить, являются ли статистические данные об этой записи достаточно плохи, что бы их можно было просто удалить
    bool IsTerrible(int64 nNow = GetAdjustedTime()) const;

    // Calculate the relative chance this entry should be given when selecting nodes to connect to
    //      Вычислить относительную вероятность что эта записи должна быть предоставленна при выборе узлов подключения
    double GetChance(int64 nNow = GetAdjustedTime()) const;

};

// Stochastic address manager               Стохастические менеджер адресов
//
// Design goals:                            Дизайн задач(целей):
//  * Only keep a limited number of addresses around, so that addr.dat and memory requirements do not grow without bound.
//  * Keep the address tables in-memory, and asynchronously dump the entire to able in addr.dat.
//  * Make sure no (localized) attacker can fill the entire table with his nodes/addresses.
//
//              * Только держать ограниченное количество адресов вокруг, так что addr.dat и требуемая память не растут неограниченно.
//              * Держите адреса таблиц в памяти, и асинхронно сбрасывают все состояния в addr.dat.
//              * Убедитесь, что (локальные) злоумышленник не может заполнить таблицу его узлами/адресами.
//
// To that end:                             С этой целью:
//  * Addresses are organized into buckets.
//    * Address that have not yet been tried go into 256 "new" buckets.
//      * Based on the address range (/16 for IPv4) of source of the information, 32 buckets are selected at random
//      * The actual bucket is chosen from one of these, based on the range the address itself is located.
//      * One single address can occur in up to 4 different buckets, to increase selection chances for addresses that
//        are seen frequently. The chance for increasing this multiplicity decreases exponentially.
//      * When adding a new address to a full bucket, a randomly chosen entry (with a bias favoring less recently seen
//        ones) is removed from it first.
//
//              * Адреса организованы в buckets(ведрах).
//                * Адрес, которые еще не были опробованы идтут в 256 «новые» buckets(ведра).
//                  * Исходя из диапазона адресов (/16 для IPv4) из источника информации, 32 buckets(ведер) выбираются произвольно
//                  * Выбор одного актуального bucketа из них, на основе диапазона адресов сам по себе находится.
//                  * Один и тот же адрес может появиться в до 4 различных вакетах, чтобы увеличить шансы на выбор для этих адресов,
//                    которые часто можно увидеть. Шанс для увеличения это множество уменьшается экспоненциально.
//                  * При добавлении нового адреса в полный бакет, случайно выбранная запись (с уклоном в пользу менее видимой)
//                    удаляется из него первой.
//
//    * Addresses of nodes that are known to be accessible go into 64 "tried" buckets.
//      * Each address range selects at random 4 of these buckets.
//      * The actual bucket is chosen from one of these, based on the full address.
//      * When adding a new good address to a full bucket, a randomly chosen entry (with a bias favoring less recently
//        tried ones) is evicted from it, back to the "new" buckets.
//
//              * Адреса узлов, которые как известно доступны, идут в 64 "tried" buckets.
//                * Каждый диапазон адресов выбирает наугад 4 бакетами.
//                * Фактический бакет выбирается из одного из них, на основе полного адреса.
//                * При добавлении нового хорошего адреса в полный бакет, случайно выбранная запись (с уклоном в пользу менее опробованной)
//                  выселяется из него обратно в "new" buckets.
//
//    * Bucket selection is based on cryptographic hashing, using a randomly-generated 256-bit key, which should not
//      be observable by adversaries.
//    * Several indexes are kept for high performance. Defining DEBUG_ADDRMAN will introduce frequent (and expensive)
//      consistency checks for the entire data structure.
//
//              * Выбор бакета основана на криптографическом хешировании, используя случайно сгенерированный 256-битный ключ,
//                который не должен быть видимым противникам
//              * Несколько индексов хранятся для высокой производительности. Определение DEBUG_ADDRMAN представит частые (и дорогие)
//                проверки согласованности для сплошной структуры данных
//

// total number of buckets for tried addresses                          общее количество бакетов для пробуемых адресов
#define ADDRMAN_TRIED_BUCKET_COUNT 64

// maximum allowed number of entries in buckets for tried addresses     максимально допустимое количество записей в бакетах для проверяемых адресов
#define ADDRMAN_TRIED_BUCKET_SIZE 64

// total number of buckets for new addresses                            общее количество бакетов для новых адресов
#define ADDRMAN_NEW_BUCKET_COUNT 256

// maximum allowed number of entries in buckets for new addresses       максимально допустимое количество записей в ифлуеу для новых адресов
#define ADDRMAN_NEW_BUCKET_SIZE 64

// over how many buckets entries with tried addresses from a single group (/16 for IPv4) are spread
//                      сколько записей бакетов с пробуемыми адресами от единственной группы (/16 для IPv4) распространяются
#define ADDRMAN_TRIED_BUCKETS_PER_GROUP 4

// over how many buckets entries with new addresses originating from a single group are spread
//                      сколько записей бакетов с новыми адресами, происходящими из одной группы распространяются
#define ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP 32

// in how many buckets for entries with new addresses a single address may occur
//                      в скольких бакетах для записей с новыми адресами один адрес может произойти
#define ADDRMAN_NEW_BUCKETS_PER_ADDRESS 4

// how many entries in a bucket with tried addresses are inspected, when selecting one to replace
//                      сколько записей в бакете с проверенными адресами проверяются, когда выбираем один для замены
#define ADDRMAN_TRIED_ENTRIES_INSPECT_ON_EVICT 4

// how old addresses can maximally be                                   сколько старых адресов могут максимально быть
#define ADDRMAN_HORIZON_DAYS 30

// after how many failed attempts we give up on a new node              через сколько неудачных попыток мы отказаться от нового узла
#define ADDRMAN_RETRIES 3

// how many successive failures are allowed ...                         сколько последовательныех отказов допускается ...
#define ADDRMAN_MAX_FAILURES 10

// ... in at least this many days                                       ... по крайней мере этого множества дней
#define ADDRMAN_MIN_FAIL_DAYS 7

// the maximum percentage of nodes to return in a getaddr call          максимальный процент узлов для возвращения getaddr вызова
#define ADDRMAN_GETADDR_MAX_PCT 23

// the maximum number of nodes to return in a getaddr call              максимальное количество узлов для возвращения getaddr вызова
#define ADDRMAN_GETADDR_MAX 2500

/** Stochastical (IP) address manager */
class CAddrMan
{
private:
    // critical section to protect the inner data structures            серьезная секция, чтобы защитить внутренние структуры данных
    mutable CCriticalSection cs;

    // secret key to randomize bucket select with                       Секретный ключ для случайного выбера бакета
    std::vector<unsigned char> nKey;

    // last used nId                                                    последний используеюй nId
    int nIdCount;

    // table with information about all nIds                            таблица с информацией о всех nId
    std::map<int, CAddrInfo> mapInfo;

    // find an nId based on its network address                         поиск nId на основе его сетевого адреса
    std::map<CNetAddr, int> mapAddr;

    // randomly-ordered vector of all nIds                              случайно-упорядоченный вектор всх nIds
    std::vector<int> vRandom;

    // number of "tried" entries                                        количество "испытанных" записей
    int nTried;

    // list of "tried" buckets                                          список "испытанных" бакетов
    std::vector<std::vector<int> > vvTried;

    // number of (unique) "new" entries                                 количество (уникальных) "новых" записей
    int nNew;

    // list of "new" buckets                                            список "новых" бакетов
    std::vector<std::set<int> > vvNew;

protected:

    // Find an entry.                                                   найти запись
    CAddrInfo* Find(const CNetAddr& addr, int *pnId = NULL);

    // find an entry, creating it if necessary.                         найти запись, создавая её если это необходимо
    // nTime and nServices of found node is updated, if necessary.      ntime и nServices из найденного узла обновляется, если необходимо
    CAddrInfo* Create(const CAddress &addr, const CNetAddr &addrSource, int *pnId = NULL);

    // Swap two elements in vRandom.                                    поменять два элемента в vRandom
    void SwapRandom(unsigned int nRandomPos1, unsigned int nRandomPos2);

    // Return position in given bucket to replace.                      вернуться позицию в данном бакете для замены
    int SelectTried(int nKBucket);

    // Remove an element from a "new" bucket.                           удаление элемента из "нового" бакета
    // This is the only place where actual deletes occur.               это единственное место, где происходит фактическое удаление.
    // They are never deleted while in the "tried" table, only possibly evicted back to the "new" table.
    //                  Они никогда не удаляются в таблице "проверенных", только возможно выселение обратно в таблицу "новых".
    int ShrinkNew(int nUBucket);

    // Move an entry from the "new" table(s) to the "tried" table       переместить запись из таблицы "new" в таблицу "проверенных"
    // @pre vvUnkown[nOrigin].count(nId) != 0
    void MakeTried(CAddrInfo& info, int nId, int nOrigin);

    // Mark an entry "good", possibly moving it from "new" to "tried".  Отметить запись "хороший", возможно его перемещение из "новых" в "проверенные"
    void Good_(const CService &addr, int64 nTime);

    // Add an entry to the "new" table.                                 добпвления записи в таблицу "новых"
    bool Add_(const CAddress &addr, const CNetAddr& source, int64 nTimePenalty);

    // Mark an entry as attempted to connect.                           пометить запись как попытку подключения
    void Attempt_(const CService &addr, int64 nTime);

    // Select an address to connect to.                                 выбор адреса для подключения
    // nUnkBias determines how much to favor new addresses over tried ones (min=0, max=100)
    //                  nUnkBias определяет, на сколько предпочтительнее новые адреса над проверенными (min=0, max=100)
    CAddress Select_(int nUnkBias);

#ifdef DEBUG_ADDRMAN
    // Perform consistency check. Returns an error code or zero.        выполняет проверку согласованности. Возвращает код ошибки или ноль.
    int Check_();
#endif

    // Select several addresses at once.                                выберите несколько адресов сразу
    void GetAddr_(std::vector<CAddress> &vAddr);

    // Mark an entry as currently-connected-to.                         отметить запись как в настоящее_время_подключен
    void Connected_(const CService &addr, int64 nTime);

public:

    IMPLEMENT_SERIALIZE
    (({
        // serialized format:                                           Формат скриализации
        // * version byte (currently 0)
        // * nKey
        // * nNew
        // * nTried
        // * number of "new" buckets
        // * all nNew addrinfos in vvNew
        // * all nTried addrinfos in vvTried
        // * for each bucket:
        //   * number of elements
        //   * for each element: index
        //
        // Notice(обратите внимание ) that vvTried, mapAddr and vVector are never encoded explicitly(никогда не кодируется явно);
        // they are instead reconstructed from the other information.   они вместо этого восстанавливаются из другой информации
        //
        // vvNew is serialized, but only used if ADDRMAN_UNKOWN_BUCKET_COUNT didn't change,
        // otherwise it is reconstructed as well.
        //          vvNew скриализуется, но только в том случае, если ADDRMAN_UNKOWN_BUCKET_COUNT не изменился
        //          в противном случае он будет восстановлен также
        //
        // This format is more complex, but significantly smaller (at most 1.5 MiB), and supports
        // changes to the ADDRMAN_ parameters without breaking the on-disk structure.
        //          Этот формат является более сложным, но значительно меньшим (не более 1,5 Мб),
        //          и поддерживает изменения параметров ADDRMAN_, не нарушая структуры на диске
        {
            LOCK(cs);
            unsigned char nVersion = 0;
            READWRITE(nVersion);
            READWRITE(nKey);
            READWRITE(nNew);
            READWRITE(nTried);

            CAddrMan *am = const_cast<CAddrMan*>(this);
            if (fWrite)
            {
                int nUBuckets = ADDRMAN_NEW_BUCKET_COUNT;
                READWRITE(nUBuckets);
                std::map<int, int> mapUnkIds;
                int nIds = 0;
                for (std::map<int, CAddrInfo>::iterator it = am->mapInfo.begin(); it != am->mapInfo.end(); it++)
                {
                    if (nIds == nNew) break; // this means nNew was wrong, oh ow        Это значит, nNew был ошибочен, ой ой
                    mapUnkIds[(*it).first] = nIds;
                    CAddrInfo &info = (*it).second;
                    if (info.nRefCount)
                    {
                        READWRITE(info);
                        nIds++;
                    }
                }
                nIds = 0;
                for (std::map<int, CAddrInfo>::iterator it = am->mapInfo.begin(); it != am->mapInfo.end(); it++)
                {
                    if (nIds == nTried) break; // this means nTried was wrong, oh ow    Это значит, nTried был ошибочен, ой ой
                    CAddrInfo &info = (*it).second;
                    if (info.fInTried)
                    {
                        READWRITE(info);
                        nIds++;
                    }
                }
                for (std::vector<std::set<int> >::iterator it = am->vvNew.begin(); it != am->vvNew.end(); it++)
                {
                    const std::set<int> &vNew = (*it);
                    int nSize = vNew.size();
                    READWRITE(nSize);
                    for (std::set<int>::iterator it2 = vNew.begin(); it2 != vNew.end(); it2++)
                    {
                        int nIndex = mapUnkIds[*it2];
                        READWRITE(nIndex);
                    }
                }
            } else {
                int nUBuckets = 0;
                READWRITE(nUBuckets);
                am->nIdCount = 0;
                am->mapInfo.clear();
                am->mapAddr.clear();
                am->vRandom.clear();
                am->vvTried = std::vector<std::vector<int> >(ADDRMAN_TRIED_BUCKET_COUNT, std::vector<int>(0));
                am->vvNew = std::vector<std::set<int> >(ADDRMAN_NEW_BUCKET_COUNT, std::set<int>());
                for (int n = 0; n < am->nNew; n++)
                {
                    CAddrInfo &info = am->mapInfo[n];
                    READWRITE(info);
                    am->mapAddr[info] = n;
                    info.nRandomPos = vRandom.size();
                    am->vRandom.push_back(n);
                    if (nUBuckets != ADDRMAN_NEW_BUCKET_COUNT)
                    {
                        am->vvNew[info.GetNewBucket(am->nKey)].insert(n);
                        info.nRefCount++;
                    }
                }
                am->nIdCount = am->nNew;
                int nLost = 0;
                for (int n = 0; n < am->nTried; n++)
                {
                    CAddrInfo info;
                    READWRITE(info);
                    std::vector<int> &vTried = am->vvTried[info.GetTriedBucket(am->nKey)];
                    if (vTried.size() < ADDRMAN_TRIED_BUCKET_SIZE)
                    {
                        info.nRandomPos = vRandom.size();
                        info.fInTried = true;
                        am->vRandom.push_back(am->nIdCount);
                        am->mapInfo[am->nIdCount] = info;
                        am->mapAddr[info] = am->nIdCount;
                        vTried.push_back(am->nIdCount);
                        am->nIdCount++;
                    } else {
                        nLost++;
                    }
                }
                am->nTried -= nLost;
                for (int b = 0; b < nUBuckets; b++)
                {
                    std::set<int> &vNew = am->vvNew[b];
                    int nSize = 0;
                    READWRITE(nSize);
                    for (int n = 0; n < nSize; n++)
                    {
                        int nIndex = 0;
                        READWRITE(nIndex);
                        CAddrInfo &info = am->mapInfo[nIndex];
                        if (nUBuckets == ADDRMAN_NEW_BUCKET_COUNT && info.nRefCount < ADDRMAN_NEW_BUCKETS_PER_ADDRESS)
                        {
                            info.nRefCount++;
                            vNew.insert(nIndex);
                        }
                    }
                }
            }
        }
    });)

    CAddrMan() : vRandom(0), vvTried(ADDRMAN_TRIED_BUCKET_COUNT, std::vector<int>(0)), vvNew(ADDRMAN_NEW_BUCKET_COUNT, std::set<int>())
    {
         nKey.resize(32);
         RAND_bytes(&nKey[0], 32);

         nIdCount = 0;
         nTried = 0;
         nNew = 0;
    }

    // Return the number of (unique) addresses in all tables.           возвращает количество (уникальных) адресов во всех таблицах
    int size()
    {
        return vRandom.size();
    }

    // Consistency check                                                проверка согласованность
    void Check()
    {
#ifdef DEBUG_ADDRMAN
        {
            LOCK(cs);
            int err;
            if ((err=Check_()))
                printf("ADDRMAN CONSISTENCY CHECK FAILED!!! err=%i\n", err);
        }
#endif
    }

    // Add a single address.                                            добавить один адрес
    bool Add(const CAddress &addr, const CNetAddr& source, int64 nTimePenalty = 0)
    {
        bool fRet = false;
        {
            LOCK(cs);
            Check();
            fRet |= Add_(addr, source, nTimePenalty);
            Check();
        }
        if (fRet)
            printf("Added %s from %s: %i tried, %i new\n", addr.ToStringIPPort().c_str(), source.ToString().c_str(), nTried, nNew);
        return fRet;
    }

    // Add multiple addresses.                                          добавить несколько адресов
    bool Add(const std::vector<CAddress> &vAddr, const CNetAddr& source, int64 nTimePenalty = 0)
    {
        int nAdd = 0;
        {
            LOCK(cs);
            Check();
            for (std::vector<CAddress>::const_iterator it = vAddr.begin(); it != vAddr.end(); it++)
                nAdd += Add_(*it, source, nTimePenalty) ? 1 : 0;
            Check();
        }
        if (nAdd)
            printf("Added %i addresses from %s: %i tried, %i new\n", nAdd, source.ToString().c_str(), nTried, nNew);
        return nAdd > 0;
    }

    // Mark an entry as accessible.                                     отметить запись как доступную
    void Good(const CService &addr, int64 nTime = GetAdjustedTime())
    {
        {
            LOCK(cs);
            Check();
            Good_(addr, nTime);
            Check();
        }
    }

    // Mark an entry as connection attempted to.                        отметить запись как попытка подключения
    void Attempt(const CService &addr, int64 nTime = GetAdjustedTime())
    {
        {
            LOCK(cs);
            Check();
            Attempt_(addr, nTime);
            Check();
        }
    }

    // Choose an address to connect to.                                 выбор адреса для подключения
    // nUnkBias determines how much "new" entries are favored over "tried" ones (0-100).
    //                              определяет, скольким "новым" записям отдается предпочтение перед "проверенными" (0-100)
    CAddress Select(int nUnkBias = 50)
    {
        CAddress addrRet;
        {
            LOCK(cs);
            Check();
            addrRet = Select_(nUnkBias);
            Check();
        }
        return addrRet;
    }

    // Return a bunch of addresses, selected at random.                 вернуться кучу адресов, выбранных наугад
    std::vector<CAddress> GetAddr()
    {
        Check();
        std::vector<CAddress> vAddr;
        {
            LOCK(cs);
            GetAddr_(vAddr);
        }
        Check();
        return vAddr;
    }

    // Mark an entry as currently-connected-to.                         отметить запись как в настоящее_время_подключен
    void Connected(const CService &addr, int64 nTime = GetAdjustedTime())
    {
        {
            LOCK(cs);
            Check();
            Connected_(addr, nTime);
            Check();
        }
    }
};

#endif
