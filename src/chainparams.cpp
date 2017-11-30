// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

//
// Main network                                                                 Основная сеть
//

unsigned int pnSeed[] =
{
    0x5abc5813          // 90.188.88.19
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data. Сообщение начала строки - это вряд ли произойдет в обычных данных.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce  Символы редко используют верхний ASCII, не действует как UTF-8, и производят
        // a large 4-byte int at any alignment.                                         большое 4-байт int в любое выравнивание.
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        vAlertPubKey = ParseHex("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");
        nDefaultPort = 17511;   // 8333
        nRPCPort = 17510;       // 8332
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 24);    // 32 // лимит оставить

        nSubsidyHalvingInterval = 210000;

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //                  Построение начального блока. Заметьте, что вывод генезиса coinbase не может
        //                  быть потрачен так как его первоначально не существует в базе данных.
        const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 150 * COIN;      ////////// новое //////////
        txNew.tBlock = 0;                       ////////// новое //////////
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1511875500;
        genesis.nBits    = 0x1e00ffff;
        //genesis.nBits    = 0x1d00ffff;      // http://ru.bitcoinwiki.org/%D0%A1%D0%BB%D0%BE%D0%B6%D0%BD%D0%BE%D1%81%D1%82%D1%8C
        genesis.nNonce   = 70357979;

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x00000009efba3f88db6f03373c7ff6f6be1b6f9ad21306b4eb26f65dfdffac8d"));

        base58Prefixes[PUBKEY_ADDRESS] = 65;    // T https://en.bitcoin.it/wiki/List_of_address_prefixes
        base58Prefixes[SCRIPT_ADDRESS] = 5;
        base58Prefixes[SECRET_KEY] = 128;

        // Convert the pnSeeds array into usable address objects.                       Преобразование массива pnSeeds в используемые адреса объектов
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,    Оно будет подключиться только к одной или двум сидам узла, потому что, как только
            // it'll get a pile of addresses with newer timestamps.                     он подключается, он будет получать кучу адресов с новыми временными метками.
            // Seed nodes are given a random 'last seen time' of between one and two    Сиды узлов дают случайный 'время последнего появления' от одного до двух
            // weeks ago.                                                               недель назад.
            const int64 nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data. Сообщение начала строки - это вряд ли произойдет в обычных данных.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce  Символы редко используют верхний ASCII, не действует как UTF-8, и производят
        // a large 4-byte int at any alignment.                                         большое 4-байт int в любое выравнивание.
        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        vAlertPubKey = ParseHex("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");
        nDefaultPort = 57511;
        nRPCPort = 57510;
        strDataDir = "testnet3";

        // Modify the testnet genesis block so the timestamp is valid for a later start.    Измените блок генезис testnet так чтобы временная метка была действительна для позднего старта.
        genesis.nTime = 1511875961;
        genesis.nNonce = 162350271;

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x00000005a3478dec5f338f967df456a862e72b7fd614ff972053ce8ebd0f5329"));

        vFixedSeeds.clear();
        vSeeds.clear();
//        vSeeds.push_back(CDNSSeedData("bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org"));
//        vSeeds.push_back(CDNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));

        base58Prefixes[PUBKEY_ADDRESS] = 111;
        base58Prefixes[SCRIPT_ADDRESS] = 196;
        base58Prefixes[SECRET_KEY] = 239;

    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test (Регрессионное тестирование)
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nSubsidyHalvingInterval = 2100;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 10);    // 1
        genesis.nTime = 1511877324; // 1296688602;
        genesis.nBits = 0x1f0fffff; // 0x207fffff
        genesis.nNonce = 77288;
        nDefaultPort = 57555;// 18444
        strDataDir = "regtest";

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x0000258dea59ccf550f83fa9d76c7e1d2182f2f1236e0d5bd1017fec682b8ee2"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.                    Regtest режим не имеет любых DNS сидов.

        base58Prefixes[PUBKEY_ADDRESS] = 65;
        base58Prefixes[SCRIPT_ADDRESS] = 5;
        base58Prefixes[SECRET_KEY] = 128;
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
        //SelectParams(CChainParams::REGTEST);
    }
    return true;
}
