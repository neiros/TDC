#include <map>
#include <string>
#include <boost/test/unit_test.hpp>
#include "json_spirit_writer_template.h"

#include "main.h"
#include "Wallet/wallet.h"

using namespace std;
using namespace json_spirit;

// In script_tests.cpp
extern Array read_json(const std::string& filename);
extern CScript ParseScript(string s);

BOOST_AUTO_TEST_SUITE(transaction_tests)

BOOST_AUTO_TEST_CASE(tx_valid)
{
    // Read tests from test/data/tx_valid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"], serializedTransaction, enforceP2SH
    // ... where all scripts are stringified scripts.
    Array tests = read_json("tx_valid.json");

    BOOST_FOREACH(Value& tv, tests)
    {
        Array test = tv.get_array();
        string strTest = write_string(tv, false);
        if (test[0].type() == array_type)
        {
            if (test.size() != 3 || test[1].type() != str_type || test[2].type() != bool_type)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            map<COutPoint, CScript> mapprevOutScriptPubKeys;
            Array inputs = test[0].get_array();
            bool fValid = true;
            BOOST_FOREACH(Value& input, inputs)
            {
                if (input.type() != array_type)
                {
                    fValid = false;
                    break;
                }
                Array vinput = input.get_array();
                if (vinput.size() != 3)
                {
                    fValid = false;
                    break;
                }

                mapprevOutScriptPubKeys[COutPoint(uint256(vinput[0].get_str()), vinput[1].get_int())] = ParseScript(vinput[2].get_str());
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK, PROTOCOL_VERSION);
            CTransaction tx;
            stream >> tx;

            CValidationState state;
            BOOST_CHECK_MESSAGE(CheckTransaction(tx, state), strTest);
            BOOST_CHECK(state.IsValid());

            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout))
                {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[i].scriptSig, mapprevOutScriptPubKeys[tx.vin[i].prevout], tx, i, test[2].get_bool() ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE, 0), strTest);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_invalid)
{
    // Read tests from test/data/tx_invalid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"], serializedTransaction, enforceP2SH
    // ... where all scripts are stringified scripts.
    Array tests = read_json("tx_invalid.json");

    BOOST_FOREACH(Value& tv, tests)
    {
        Array test = tv.get_array();
        string strTest = write_string(tv, false);
        if (test[0].type() == array_type)
        {
            if (test.size() != 3 || test[1].type() != str_type || test[2].type() != bool_type)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            map<COutPoint, CScript> mapprevOutScriptPubKeys;
            Array inputs = test[0].get_array();
            bool fValid = true;
            BOOST_FOREACH(Value& input, inputs)
            {
                if (input.type() != array_type)
                {
                    fValid = false;
                    break;
                }
                Array vinput = input.get_array();
                if (vinput.size() != 3)
                {
                    fValid = false;
                    break;
                }

                mapprevOutScriptPubKeys[COutPoint(uint256(vinput[0].get_str()), vinput[1].get_int())] = ParseScript(vinput[2].get_str());
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK, PROTOCOL_VERSION);
            CTransaction tx;
            stream >> tx;

            CValidationState state;
            fValid = CheckTransaction(tx, state) && state.IsValid();

            for (unsigned int i = 0; i < tx.vin.size() && fValid; i++)
            {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout))
                {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                fValid = VerifyScript(tx.vin[i].scriptSig, mapprevOutScriptPubKeys[tx.vin[i].prevout], tx, i, test[2].get_bool() ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE, 0);
            }

            BOOST_CHECK_MESSAGE(!fValid, strTest);
        }
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests)
{
    // Random real TDC transaction (71f22c2d47fb4351c3fa369a18e85ed57e3d6e5b08524ffec877d4c92968481d)
    unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x5e, 0x13, 0x60, 0xa2, 0xee, 0x21, 0x53, 0x3e, 0x4c, 0xde, 0x14, 0x17, 0x59, 0x21, 0x40, 0x9c, 0x82, 0x4a, 0xc6, 0xe5, 0x85, 0xac, 0x11, 0x7c, 0x49, 0xae, 0x45, 0x4e, 0x8b, 0xc2, 0xc9, 0x5c, 0x01, 0x00, 0x00, 0x00, 0x6a, 0x47, 0x30, 0x44, 0x02, 0x20, 0x79, 0xb3, 0x73, 0xf6, 0xe3, 0x0f, 0x8f, 0xd4, 0xf9, 0x7e, 0xd0, 0xb4, 0xf5, 0x05, 0xdb, 0x87, 0x64, 0x43, 0x28, 0x22, 0x42, 0xd2, 0x7b, 0xee, 0xa7, 0xcc, 0x79, 0xfc, 0x58, 0xb1, 0x21, 0x29, 0x02, 0x20, 0x65, 0x1b, 0xd7, 0x95, 0x99, 0x8b, 0x1b, 0x8c, 0x81, 0x9b, 0xe2, 0xaa, 0x16, 0x9f, 0x21, 0x42, 0xa9, 0x02, 0xcc, 0xf0, 0x28, 0x07, 0x42, 0xa5, 0xa6, 0x72, 0x23, 0xb5, 0x8a, 0xb4, 0x0f, 0x95, 0x01, 0x21, 0x02, 0x29, 0x1f, 0x79, 0x2f, 0x0d, 0x40, 0x14, 0x1d, 0x44, 0xb2, 0x3f, 0x60, 0x2e, 0x35, 0x0c, 0xd3, 0xc0, 0x27, 0xb8, 0x73, 0x9f, 0x21, 0x30, 0x5f, 0x58, 0xd6, 0x08, 0x98, 0x33, 0xf6, 0x78, 0x56, 0xff, 0xff, 0xff, 0xff, 0x02, 0x70, 0xaa, 0xf0, 0x08, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0x78, 0x47, 0x8e, 0x86, 0xd3, 0xcd, 0xc2, 0x15, 0xd3, 0xbc, 0xe2, 0x3c, 0x7f, 0xd3, 0x5f, 0x63, 0x39, 0x78, 0xbc, 0xd7, 0x88, 0xac, 0x80, 0xf0, 0xfa, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xd6, 0x24, 0xd6, 0x5d, 0x22, 0x22, 0xa5, 0xff, 0xca, 0x94, 0x5b, 0xb0, 0x5b, 0x2d, 0xf1, 0xc8, 0x2a, 0xa8, 0xf0, 0x97, 0x88, 0xac, 0xe1, 0x9e, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    vector<unsigned char> vch(ch, ch + sizeof(ch) -1);
    CDataStream stream(vch, SER_DISK, CLIENT_VERSION);
    CTransaction tx;
    stream >> tx;
    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(tx, state) && state.IsValid(), "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckTransaction(tx, state) || !state.IsValid(), "Transaction with duplicate txins should be invalid.");
}

//
// Helper: create two dummy transactions, each with
// two outputs.  The first has 11 and 50 CENT outputs
// paid to a TX_PUBKEY, the second 21 and 22 CENT outputs
// paid to a TX_PUBKEYHASH.
//
static std::vector<CTransaction>
SetupDummyInputs(CBasicKeyStore& keystoreRet, CCoinsView & coinsRet)
{
    std::vector<CTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 11*CENT;
    dummyTransactions[0].vout[0].scriptPubKey << key[0].GetPubKey() << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = 50*CENT;
    dummyTransactions[0].vout[1].scriptPubKey << key[1].GetPubKey() << OP_CHECKSIG;
    coinsRet.SetCoins(dummyTransactions[0].GetHash(), CCoins(dummyTransactions[0], 0));

    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = 21*CENT;
    dummyTransactions[1].vout[0].scriptPubKey.SetDestination(key[2].GetPubKey().GetID());
    dummyTransactions[1].vout[1].nValue = 22*CENT;
    dummyTransactions[1].vout[1].scriptPubKey.SetDestination(key[3].GetPubKey().GetID());
    coinsRet.SetCoins(dummyTransactions[1].GetHash(), CCoins(dummyTransactions[1], 0));

    return dummyTransactions;
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(coinsDummy);
    std::vector<CTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(t1, coins));
    BOOST_CHECK_EQUAL(coins.GetValueIn(t1), (50+21+22)*CENT);

    // Adding extra junk to the scriptSig should make it non-standard:
    t1.vin[0].scriptSig << OP_11;
    BOOST_CHECK(!AreInputsStandard(t1, coins));

    // ... as should not having enough:
    t1.vin[0].scriptSig = CScript();
    BOOST_CHECK(!AreInputsStandard(t1, coins));
}

BOOST_AUTO_TEST_CASE(test_IsStandard)
{
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(coinsDummy);
    std::vector<CTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t.vin[0].prevout.n = 1;
    t.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90*CENT;
    CKey key;
    key.MakeNewKey(true);
    t.vout[0].scriptPubKey.SetDestination(key.GetPubKey().GetID());

    string reason;
    BOOST_CHECK(IsStandardTx(t, reason));

    t.vout[0].nValue = 5011; // dust
    BOOST_CHECK(!IsStandardTx(t, reason));

    t.vout[0].nValue = 6011; // not dust
    BOOST_CHECK(IsStandardTx(t, reason));

    t.vout[0].scriptPubKey = CScript() << OP_1;
    BOOST_CHECK(!IsStandardTx(t, reason));
}

BOOST_AUTO_TEST_SUITE_END()
