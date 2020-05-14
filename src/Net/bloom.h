// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_BLOOM_H
#define BITCOIN_BLOOM_H

#include <vector>

#include "Helpers/uint256.h"
#include "Helpers/serialize.h"

class COutPoint;
class CTransaction;

// 20,000 items with fp rate < 0.1% or 10,000 items and <0.0001%                    20,000 пунктов с fp оценкой < 0,1 % или 10,000 пунктов и <0,0001 %
static const unsigned int MAX_BLOOM_FILTER_SIZE = 36000; // bytes
static const unsigned int MAX_HASH_FUNCS = 50;

// First two bits of nFlags control how much IsRelevantAndUpdate actually updates   первые два бита nFlags управления сколько IsRelevantAndUpdate фактически обновился
// The remaining bits are reserved                                                  остальные биты зарезервированы
enum bloomflags
{
    BLOOM_UPDATE_NONE = 0,
    BLOOM_UPDATE_ALL = 1,
    // Only adds outpoints to the filter if the output is a pay-to-pubkey/pay-to-multisig script
    //      Только добавляет выходы в фильтр, если выход pay-to-pubkey/pay-to-multisig script
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
    BLOOM_UPDATE_MASK = 3,
};

/**
 * BloomFilter is a probabilistic filter which SPV clients provide                  BloomFilter - вероятностный фильтр, который обеспечивает SPV клиентам возможность
 * so that we can filter the transactions we sends them.                            чтобы мы могли фильтровать сделки, которые мы посылаем им.
 * 
 * This allows for significantly more efficient transaction and block downloads.    Это позволяет значительно повысить эффективность загрузки транзакций и блоков.
 * 
 * Because bloom filters are probabilistic, an SPV node can increase the false-     Поскольку блум фильтры являются вероятностными, узел SPV может увеличить
 * positive rate, making us send them transactions which aren't actually theirs,    ложно-положительную оценку, позволяя нам отправить им сделок, которые на самом
 * allowing clients to trade more bandwidth for more privacy by obfuscating which   деле не принадлежат им, что позволяет клиентам использовать большую полосы пропускания
 * keys are owned by them.                                                          для большей конфиденциальности для запутывая ключей, которые принадлежат им.
 */
class CBloomFilter
{
private:
    std::vector<unsigned char> vData;
    unsigned int nHashFuncs;
    unsigned int nTweak;
    unsigned char nFlags;

    unsigned int Hash(unsigned int nHashNum, const std::vector<unsigned char>& vDataToHash) const;

public:
    // Creates a new bloom filter which will provide the given fp rate when filled with the given number of elements
    // Note that if the given parameters will result in a filter outside the bounds of the protocol limits,
    // the filter created will be as close to the given parameters as possible within the protocol limits.
    // This will apply if nFPRate is very low or nElements is unreasonably high.
    // nTweak is a constant which is added to the seed value passed to the hash function
    // It should generally always be a random value (and is largely only exposed for unit testing)
    // nFlags should be one of the BLOOM_UPDATE_* enums (not _MASK)
    //      Создает новый блум фильтр, который обеспечит данную FP скорость, когда заполнился заданное число элементов
    //      Заметим, что если заданные параметры приведут фильтр за пределы предела протокола,
    //      фильтр будет создан как можно ближе к заданным параметрам, как это возможно в рамках протокола.
    //      Это будет применяться, если nFPRate очень низкое или nElements неоправданно высокий.
    //      nTweak постоянная, которая добавляется к начальному значению, переданному в хэш-функции
    //      Оно должено быть как правило всегда случайным значением (и в значительной степени доступно только для модульного тестирования)
    //      nFlags должно быть одним из BLOOM_UPDATE_* enums (не _MASK)
    CBloomFilter(unsigned int nElements, double nFPRate, unsigned int nTweak, unsigned char nFlagsIn);
    // Using a filter initialized with this results in undefined behavior
    // Should only be used for deserialization
    //      Использование инициализации фильтра с этими результатами(приводит к) с непредсказуемым поведением
    //      Следует использовать только для десериализации
    CBloomFilter() {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vData);
        READWRITE(nHashFuncs);
        READWRITE(nTweak);
        READWRITE(nFlags);
    )

    void insert(const std::vector<unsigned char>& vKey);
    void insert(const COutPoint& outpoint);
    void insert(const uint256& hash);

    bool contains(const std::vector<unsigned char>& vKey) const;
    bool contains(const COutPoint& outpoint) const;
    bool contains(const uint256& hash) const;

    // True if the size is <= MAX_BLOOM_FILTER_SIZE and the number of hash functions is <= MAX_HASH_FUNCS
    // (catch a filter which was just deserialized which was too big)
    //      True, если размер <= MAX_BLOOM_FILTER_SIZE и количество хеш-функции <= MAX_HASH_FUNCS
    //      (поймайте фильтр, который был только десериализованн, который был слишком большим),
    bool IsWithinSizeConstraints() const;

    // Also adds any outputs which match the filter to the filter (to match their spending txes)
    //      Также добавляет любые выходы, которые соответствуют фильтру для фильтра (для соответствия их расходов txes)
    bool IsRelevantAndUpdate(const CTransaction& tx, const uint256& hash);
};

#endif /* BITCOIN_BLOOM_H */
