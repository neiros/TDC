// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


//
// Why base-58 instead of standard base-64 encoding?                                           Почему base-58 вместо стандартной кодировки base-64?
// - Don't want 0OIl characters that look the same in some fonts and                           - Не хочу 0OIl символы, которые выглядят похожими в некоторых шрифтах и
//      could be used to create visually identical looking account numbers.                        могут быть использованы для создания визуально идентичных номером счетов.
// - A string with non-alphanumeric characters is not as easily accepted as an account number. - Строка с не-алфавитно-цифровыми символами не так легко примается в качестве номера счета
// - E-mail usually won't line-break if there's no punctuation to break at.                    - E-mail обычно нет разрыва строки, если нет никаких знаков препинания разрыва.
// - Double-clicking selects the whole number as one word if it's all alphanumeric.            - Двойной щелчок выбирает целый ряд как одно слово, если это все алфавитно-цифровое.
//
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include <string>
#include <vector>

#include "chainparams.h"
#include "bignum.h"
#include "key.h"
#include "script.h"
#include "allocators.h"

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Encode a byte sequence as a base58-encoded string                                    Закодировать последовательность байтов как base58-кодированную строку
inline std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;

    // Convert big endian data to little endian                                         Преобразовать big-endian(порядок от старшего к младшему) данных в little-endian(порядок от младшего к старшему)
    // Extra zero at the end make sure bignum will interpret as a positive number       Дополнительный ноль в конце означает, что bignum будет интерпретироваться как положительное число
    std::vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum                                             Преобразование little-endian данных в bignum
    CBigNum bn;
    bn.setvch(vchTmp);

    // Convert bignum to std::string                                                    Преобразование bignum в std::string
    std::string str;
    // Expected size increase from base58 conversion is approximately 137%              Ожидаемое увеличение размера от преобразования base58 примерно 137%
    // use 138% to be safe                                                              используется 138%, чтобы быть безопасным
    str.reserve((pend - pbegin) * 138 / 100 + 1);

    // TODO: Implement div in CBigNum and refactor this.
    // I'll burn in hell because of this.
    CBigNum res;
    CBigNum rem;
    while (bn > bn0)
    {
        try {
            res = bn/bn58;
            rem = bn%bn58;
        }
        catch (bignum_error) {
            cout << "EncodeBase58 : BN_div failed";
        }
        bn = res;
        unsigned int c = rem.getulong();
        str += pszBase58[c];
    }

    // Leading zeroes encoded as base58 zeros                                           Ведущие нули кодируются как base58 нули
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
        str += pszBase58[0];

    // Convert little endian std::string to big endian                                  Преобразование little-endian std::string в big-endian
    reverse(str.begin(), str.end());
    return str;
}

// Encode a byte vector as a base58-encoded string                                      Кодировать байт вектор как base58-кодированную строку
inline std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

// Decode a base58-encoded string psz into byte vector vchRet                           Декодирование base58-кодированной строки psz в байт вектор vchRet
// returns true if decoding is successful                                               вернуть true если декодирование успешно
inline bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet)
{
    vchRet.clear();
    CBigNum bn58 = 58;
    CBigNum bn = 0;
    CBigNum bnChar;
    while (isspace(*psz))
        psz++;

    // Convert big endian string to bignum                                              Преобразование big-endian строки в bignum
    for (const char* p = psz; *p; p++)
    {
        const char* p1 = strchr(pszBase58, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                return false;
            break;
        }
        bnChar.setulong(p1 - pszBase58);
        bn *= bn58;
        bn += bnChar;
    }

    // Get bignum as little endian data                                                 Получить bignum как little-endian данные
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present                                                    Отрезать байт знака(подписи), если присутствует
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros                                                            Восстановить начальные нули
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == pszBase58[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian                                         Преобразование little-endian данных в big-endian
    reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return true;
}

// Decode a base58-encoded string psz into byte vector vchRet                           Декодирование base58-кодированной строки psz в байт вектор vchRet
// returns true if decoding is successful                                               вернуть true если декодирование успешно
inline bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}




// Encode a byte vector to a base58-encoded string, including checksum                  Кодирование байт вектора в base58-кодированную строку, включающую контрольную сумму
inline std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end                                                 Добавить 4-байт хеш проверки в конец
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

// Decode a base58-encoded string psz that includes a checksum, into byte vector vchRet Декодирование base58-кодированной строки psz с checksum в байт вектор vchRet
// returns true if decoding is successful                                               вернуть true если декодирование успешно
inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

// Decode a base58-encoded string psz that includes a checksum, into byte vector vchRet Декодирование base58-кодированной строки psz с checksum в байт вектор vchRet
// returns true if decoding is successful                                               вернуть true если декодирование успешно
inline bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}





/** Base class for all base58-encoded data                                              Базовый класс для всех base58-кодированных данных */
class CBase58Data
{
protected:
    // the version byte                                                                 Версия байт
    unsigned char nVersion;

    // the actually encoded data                                                        фактически закодированные данные
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > vector_uchar;
    vector_uchar vchData;

    CBase58Data()
    {
        nVersion = 0;
        vchData.clear();
    }

    void SetData(int nVersionIn, const void* pdata, size_t nSize)
    {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (!vchData.empty())
            memcpy(&vchData[0], pdata, nSize);
    }

    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend)
    {
        SetData(nVersionIn, (void*)pbegin, pend - pbegin);
    }

public:
    bool SetString(const char* psz)
    {
        std::vector<unsigned char> vchTemp;
        DecodeBase58Check(psz, vchTemp);
        if (vchTemp.empty())
        {
            vchData.clear();
            nVersion = 0;
            return false;
        }
        nVersion = vchTemp[0];
        vchData.resize(vchTemp.size() - 1);
        if (!vchData.empty())
            memcpy(&vchData[0], &vchTemp[1], vchData.size());
        OPENSSL_cleanse(&vchTemp[0], vchData.size());
        return true;
    }

    bool SetString(const std::string& str)
    {
        return SetString(str.c_str());
    }

    std::string ToString() const
    {
        std::vector<unsigned char> vch(1, nVersion);
        vch.insert(vch.end(), vchData.begin(), vchData.end());
        return EncodeBase58Check(vch);
    }

    int CompareTo(const CBase58Data& b58) const
    {
        if (nVersion < b58.nVersion) return -1;
        if (nVersion > b58.nVersion) return  1;
        if (vchData < b58.vchData)   return -1;
        if (vchData > b58.vchData)   return  1;
        return 0;
    }

    bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }
};

/** base58-encoded Bitcoin addresses.                                                   Base58-кодированные Bitcoin адреса
 * Public-key-hash-addresses have version 0 (or 111 testnet).                           Публичный-ключ-хеш-адреса имеет версию 0 (или 111 testnet)
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.          Вектор данных содержит RIPEMD160(SHA256(pubkey)), где pubkey является сериализованным открытым ключём
 * Script-hash-addresses have version 5 (or 196 testnet).                               Скрипт-хеш-адреса имеет версию 5 (или 196 testnet)
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script. Вектор данных содержит RIPEMD160(SHA256(cscript)), где cscript является сериализованным сценарий освобождения(выкупа)
 */
class CBitcoinAddress;
class CBitcoinAddressVisitor : public boost::static_visitor<bool>
{
private:
    CBitcoinAddress *addr;
public:
    CBitcoinAddressVisitor(CBitcoinAddress *addrIn) : addr(addrIn) { }
    bool operator()(const CKeyID &id) const;
    bool operator()(const CScriptID &id) const;
    bool operator()(const CNoDestination &no) const;
};

class CBitcoinAddress : public CBase58Data
{
public:
    bool Set(const CKeyID &id) {
        SetData(Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS), &id, 20);
        return true;
    }

    bool Set(const CScriptID &id) {
        SetData(Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS), &id, 20);
        return true;
    }

    bool Set(const CTxDestination &dest)
    {
        return boost::apply_visitor(CBitcoinAddressVisitor(this), dest);
    }

    bool IsValid() const
    {
        bool fCorrectSize = vchData.size() == 20;
        bool fKnownVersion = nVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS) ||
                             nVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        return fCorrectSize && fKnownVersion;
    }

    CBitcoinAddress()
    {
    }

    CBitcoinAddress(const CTxDestination &dest)
    {
        Set(dest);
    }

    CBitcoinAddress(const std::string& strAddress)
    {
        SetString(strAddress);
    }

    CBitcoinAddress(const char* pszAddress)
    {
        SetString(pszAddress);
    }

    CTxDestination Get() const {
        if (!IsValid())
            return CNoDestination();
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        if (nVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
            return CKeyID(id);
        else if (nVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS))
            return CScriptID(id);
        else
            return CNoDestination();
    }

    bool GetKeyID(CKeyID &keyID) const {
        if (!IsValid() || nVersion != Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
            return false;
        uint160 id;
        memcpy(&id, &vchData[0], 20);
        keyID = CKeyID(id);
        return true;
    }

    bool IsScript() const {
        return IsValid() && nVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS);
    }
};

bool inline CBitcoinAddressVisitor::operator()(const CKeyID &id) const         { return addr->Set(id); }
bool inline CBitcoinAddressVisitor::operator()(const CScriptID &id) const      { return addr->Set(id); }
bool inline CBitcoinAddressVisitor::operator()(const CNoDestination &id) const { return false; }

/** A base58-encoded secret key                                                         секретный ключ base58-кодировки */
class CBitcoinSecret : public CBase58Data
{
public:
    void SetKey(const CKey& vchSecret)
    {
        assert(vchSecret.IsValid());
        SetData(Params().Base58Prefix(CChainParams::SECRET_KEY), vchSecret.begin(), vchSecret.size());
        if (vchSecret.IsCompressed())
            vchData.push_back(1);
    }

    CKey GetKey()
    {
        CKey ret;
        ret.Set(&vchData[0], &vchData[32], vchData.size() > 32 && vchData[32] == 1);
        return ret;
    }

    bool IsValid() const
    {
        bool fExpectedFormat = vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1);
        bool fCorrectVersion = nVersion == Params().Base58Prefix(CChainParams::SECRET_KEY);
        return fExpectedFormat && fCorrectVersion;
    }

    bool SetString(const char* pszSecret)
    {
        return CBase58Data::SetString(pszSecret) && IsValid();
    }

    bool SetString(const std::string& strSecret)
    {
        return SetString(strSecret.c_str());
    }

    CBitcoinSecret(const CKey& vchSecret)
    {
        SetKey(vchSecret);
    }

    CBitcoinSecret()
    {
    }
};

#endif // BITCOIN_BASE58_H
