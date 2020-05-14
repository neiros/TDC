// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_PARAMS_H
#define BITCOIN_CHAIN_PARAMS_H

#include "bignum.h"
#include "Utils/uint256.h"

#include <vector>

using namespace std;

#define MESSAGE_START_SIZE 4
typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

class CAddress;
class CBlock;

struct CDNSSeedData {
    string name, host;
    CDNSSeedData(const string &strName, const string &strHost) : name(strName), host(strHost) {}
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 *                  CChainParams определяет различные настраиваемые параметры данного экземпляра
 *                  системы Биткойн. Существует три: основная сеть, в которой люди торгуют товарами
 *                  и услугами, сеть общего теста, который получает сброс время от времени и
 *                  режим регрессионного тестирования, который предназначен только для частных сетей. Он имеет
 *                  минимальную сложность чтобы блоки могли быть найдены мгновенно.
 */
class CChainParams
{
public:
    enum Network {
        MAIN,
        TESTNET,
        REGTEST,
    };

    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,

        MAX_BASE58_TYPES
    };

    const uint256& HashGenesisBlock() const { return hashGenesisBlock; }
    const MessageStartChars& MessageStart() const { return pchMessageStart; }
    const vector<unsigned char>& AlertKey() const { return vAlertPubKey; }
    int GetDefaultPort() const { return nDefaultPort; }
    const CBigNum& ProofOfWorkLimit() const { return bnProofOfWorkLimit; }
    int SubsidyHalvingInterval() const { return nSubsidyHalvingInterval; }
    virtual const CBlock& GenesisBlock() const = 0;
    virtual bool RequireRPCPassword() const { return true; }
    const string& DataDir() const { return strDataDir; }
    virtual Network NetworkID() const = 0;
    const vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    int Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    virtual const vector<CAddress>& FixedSeeds() const = 0;
    int RPCPort() const { return nRPCPort; }
protected:
    CChainParams() {};

    uint256 hashGenesisBlock;
    MessageStartChars pchMessageStart;
    // Raw pub key bytes for the broadcast alert signing key.               Сырой публичный ключ байтов для трансляции оповещения, подписанного ключём
    vector<unsigned char> vAlertPubKey;
    int nDefaultPort;
    int nRPCPort;
    CBigNum bnProofOfWorkLimit;
    int nSubsidyHalvingInterval;
    string strDataDir;
    vector<CDNSSeedData> vSeeds;
    int base58Prefixes[MAX_BASE58_TYPES];
};

/**
 * Return the currently selected parameters. This won't change after app startup
 * outside of the unit tests.
 *                  Возвращение текущих выбранных параметров. Это не изменится после запуска приложения
 *                  вне модульных тестов.
 */
const CChainParams &Params();

/** Sets the params returned by Params() to those for the given network.    Устанавливает параметры возвращаемые Params() для данной сети.*/
void SelectParams(CChainParams::Network network);

/**
 * Looks for -regtest or -testnet and then calls SelectParams as appropriate.
 * Returns false if an invalid combination is given.
 *
 *                  Ищет -regtest или -testnet и затем вызывает SelectParams по мере необходимости.
 *                  Возвращает FALSE, если недопустимое сочетание выдается.
 */
bool SelectParamsFromCommandLine();

inline bool TestNet() {
    // Note: it's deliberate that this returns "false" for regression test mode.    Это преднамеренно возвращает "false" для регрессионного тестового режима
    return Params().NetworkID() == CChainParams::TESTNET;
}

#endif
