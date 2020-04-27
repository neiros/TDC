// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <stdexcept>
#include <vector>
#include <openssl/bn.h>

#include "util.h" // for uint64

/** Errors thrown by the bignum class                              ошибки, выброшенные bignum классом */
class bignum_error : public std::runtime_error
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};


/** RAII encapsulated(скрытый, изолированный, инкапсулированный) BN_CTX (OpenSSL bignum context(контекст)) */
class CAutoBN_CTX
{
protected:
    BN_CTX* pctx;
    BN_CTX* operator=(BN_CTX* pnew) { return pctx = pnew; }

public:
    CAutoBN_CTX()
    {
        pctx = BN_CTX_new();
        if (pctx == NULL)
            throw bignum_error("CAutoBN_CTX : BN_CTX_new() returned NULL");
    }

    ~CAutoBN_CTX()
    {
        if (pctx != NULL)
            BN_CTX_free(pctx);
    }

    operator BN_CTX*() { return pctx; }
    BN_CTX& operator*() { return *pctx; }
    BN_CTX** operator&() { return &pctx; }
    bool operator!() { return (pctx == NULL); }
};


/** C++ wrapper for BIGNUM (OpenSSL bignum) */
class CBigNum
{
protected:
    BIGNUM *value;

public:
    CBigNum()
    {
        value = BN_new();
        if (value == NULL)
            throw bignum_error("CBigNum : CBigNum() returned NULL");
    }

    CBigNum(const CBigNum& b)
    {
        value = BN_dup(b.value);
        if (value == NULL)
        {
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_dup failed");
        }
    }

    /**
     * '=' Operator overloading.
     * Provided functionality
     * CBigNum b = 0
     * CBigNum a = b
     */
    CBigNum& operator=(const CBigNum& b)
    {
        value = BN_dup(b.value);
        if (value == NULL)
            throw bignum_error("CBigNum::operator= : BN_dup failed");
        return (*this);
    }

    CBigNum(signed char n)      { value = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(short n)            { value = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(int n)              { value = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(long n)             { value = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(int64 n)            { value = BN_new(); setint64(n); }
    CBigNum(unsigned char n)    { value = BN_new(); setulong(n); }
    CBigNum(unsigned short n)   { value = BN_new(); setulong(n); }
    CBigNum(unsigned int n)     { value = BN_new(); setulong(n); }
    CBigNum(unsigned long n)    { value = BN_new(); setulong(n); }
    CBigNum(uint64 n)           { value = BN_new(); setuint64(n); }
    explicit CBigNum(uint256 n) { value = BN_new(); setuint256(n); }

    explicit CBigNum(const std::vector<unsigned char>& vch)
    {
        value = BN_new();
        setvch(vch);
    }

    ~CBigNum()
    {
        // TODO: According to the openSSL docs it's safe to BN_clear_free(NULL)
        BN_clear_free(value);
    }

    void setulong(unsigned long n)
    {
        if (!BN_set_word(value, n))
            throw bignum_error("CBigNum conversion from unsigned long : BN_set_word failed");
    }

    unsigned long getulong() const
    {
        return BN_get_word(value);
    }

    unsigned int getuint() const
    {
        return BN_get_word(value);
    }

    int getint() const
    {
        unsigned long n = BN_get_word(value);
        if (!BN_is_negative(value))
            return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : n);
        else
            return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::min() : -(int)n);
    }

    void setint64(int64 sn)
    {
        unsigned char pch[sizeof(sn) + 6];
        unsigned char* p = pch + 4;
        bool fNegative;
        uint64 n;

        if (sn < (int64)0)
        {
            // Since the minimum signed integer cannot be represented as positive so long as its type is signed, 
            // and it's not well-defined what happens if you make it unsigned before negating it,
            // we instead increment the negative integer by 1, convert it, then increment the (now positive) unsigned integer by 1 to compensate
            //      Поскольку минимальное целое число не может быть представлено как положительное до тех пор пока его не подписали,
            //      и это не четко, что произойдет, если вы сделаете его беззнаковым до отрицания этого,
            //      мы вместо этого увеличиваем отрицательное целое число на 1, преобразовываем его, затем увеличиваем (теперь положительное) целое число без знака на 1 для компенсации
            n = -(sn + 1);
            ++n;
            fNegative = true;
        } else {
            n = sn;
            fNegative = false;
        }

        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = (fNegative ? 0x80 : 0);
                else if (fNegative)
                    c |= 0x80;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, value);
    }

    void setuint64(uint64 n)
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, value);
    }

    void setuint256(uint256 n)
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        unsigned char* pbegin = (unsigned char*)&n;
        unsigned char* psrc = pbegin + sizeof(n);
        while (psrc != pbegin)
        {
            unsigned char c = *(--psrc);
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize >> 0) & 0xff;
        BN_mpi2bn(pch, p - pch, value);
    }

    uint256 getuint256() const
    {
        unsigned int nSize = BN_bn2mpi(value, NULL);
        if (nSize < 4)
            return 0;
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(value, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint256 n = 0;
        for (unsigned int i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((unsigned char*)&n)[i] = vch[j];
        return n;
    }

    void setvch(const std::vector<unsigned char>& vch)
    {
        std::vector<unsigned char> vch2(vch.size() + 4);
        unsigned int nSize = vch.size();
        // BIGNUM's byte stream format expects 4 bytes of                   BIGNUM's байты потокового формата ожидают 4 байта
        // big endian size data info at the front                           от старшего к младшему(big-endian) информации данных на фронте
        vch2[0] = (nSize >> 24) & 0xff;
        vch2[1] = (nSize >> 16) & 0xff;
        vch2[2] = (nSize >> 8) & 0xff;
        vch2[3] = (nSize >> 0) & 0xff;
        // swap data to big endian                                          обмен данных от старшего к младшему(big-endian)
        reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);
        BN_mpi2bn(&vch2[0], vch2.size(), value);
    }

    std::vector<unsigned char> getvch() const
    {
        unsigned int nSize = BN_bn2mpi(value, NULL);
        if (nSize <= 4)
            return std::vector<unsigned char>();
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(value, &vch[0]);
        vch.erase(vch.begin(), vch.begin() + 4);
        reverse(vch.begin(), vch.end());
        return vch;
    }

    // The "compact" format is a representation of a whole                  'Компактный' формат представления целого числа N использующий
    // number N using an unsigned 32bit number similar to a                 unsigned 32bit числа похож на формат с плавающей точкой.
    // floating point format.
    // The most significant 8 bits are the unsigned exponent of base 256.   8 старших бит без знака показателя базы 256
    // This exponent can be thought of as "number of bytes of N".           Этот показатель можно рассматривать как "число байтов N".
    // The lower 23 bits are the mantissa.                                  Нижние 23 бита это mantissa.
    // Bit number 24 (0x800000) represents the sign of N.                   Бит номер 24 (0x800000) представляет собой знак N.
    // N = (-1^sign) * mantissa * 256^(exponent-3)
    //
    // Satoshi's original implementation used(использовал оригинальную реализацию) BN_bn2mpi() and BN_mpi2bn().
    // MPI uses the most significant bit of the first byte as sign. (интерфейс передачи сообщений(MPI) использует старший бит первого байта, как знак)
    // Thus(поэтому) 0x1234560000 is compact (0x05123456)
    // and  0xc0de000000 is compact (0x0600c0de)
    // (0x05c0de00) would be(будет) -0x40de000000
    //
    // Bitcoin only uses this "compact" format for encoding difficulty      Bitcoin использует только этот "compact" формат для кодирования цели трудности,
    // targets, which are unsigned 256bit quantities.  Thus, all the        которые являются беззнаковые(unsigned) 256-разрядные величины.
    // complexities of the sign bit and using base 256 are probably an      Таким образом, некоторые значения сложности могут привестик к аварии.
    //
    // This implementation directly uses shifts instead of going            Это внедрение непосредственно использует изменения вместо того,
    // through an intermediate MPI representation.                          чтобы пройти промежуточное представление MPI
    CBigNum& SetCompact(unsigned int nCompact)
    {
        unsigned int nSize = nCompact >> 24;
        bool fNegative     =(nCompact & 0x00800000) != 0;
        unsigned int nWord = nCompact & 0x007fffff;
        if (nSize <= 3)
        {
            nWord >>= 8*(3-nSize);
            BN_set_word(value, nWord);
        }
        else
        {
            BN_set_word(value, nWord);
            BN_lshift(value, value, 8*(nSize-3)); //BN_lshift() shifts a left by n bits and places the result in r.
        }
        BN_set_negative(value, fNegative);
        return *this;
    }

    unsigned int GetCompact() const
    {
        unsigned int nSize = BN_num_bytes(value);
        unsigned int nCompact = 0;
        if (nSize <= 3)
            nCompact = BN_get_word(value) << 8*(3-nSize);
        else
        {
            CBigNum bn;
            BN_rshift(bn.value, value, 8*(nSize-3)); //BN_rshift() shifts a right by n bits and places the result in r.
            nCompact = BN_get_word(bn.value);
        }
        // The 0x00800000 bit denotes the sign.                                              0x00800000 бит обозначает знак
        // Thus, if it is already set, divide the mantissa by 256 and increase the exponent. Таким образом, если он уже установлен, разделите мантиссы на 256 и увеличте показатель.
        if (nCompact & 0x00800000)
        {
            nCompact >>= 8;
            nSize++;
        }
        nCompact |= nSize << 24;
        nCompact |= (BN_is_negative(value) ? 0x00800000 : 0);
        return nCompact;
    }

    void SetHex(const std::string& str)
    {
        // skip(пропустить) 0x
        const char* psz = str.c_str();
        while (isspace(*psz))
            psz++;
        bool fNegative = false;
        if (*psz == '-')
        {
            fNegative = true;
            psz++;
        }
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;
        while (isspace(*psz))
            psz++;

        // hex string to bignum     шестнадцатеричная строка для bignum
        static const signed char phexdigit[256] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0 };
        *this = 0;
        while (isxdigit(*psz))
        {
            *this <<= 4;
            int n = phexdigit[(unsigned char)*psz++];
            *this += n;
        }
        if (fNegative)
            *this = 0 - *this;
    }

    std::string ToString(int nBase=10) const
    {
        CAutoBN_CTX pctx;
        CBigNum bnBase = nBase;
        CBigNum bn0 = 0;
        std::string str;
        CBigNum bn = *this;
        BN_set_negative(bn.value, false);
        CBigNum dv;
        CBigNum rem;
        if (BN_cmp(bn.value, bn0.value) == 0)
            return "0";
        while (BN_cmp(bn.value, bn0.value) > 0)
        {
            if (!BN_div(dv.value, rem.value, bn.value, bnBase.value, pctx))
                throw bignum_error("CBigNum::ToString() : BN_div failed");
            bn = dv;
            unsigned int c = rem.getulong();
            str += "0123456789abcdef"[c];
        }
        if (BN_is_negative(value))
            str += "-";
        reverse(str.begin(), str.end());
        return str;
    }

    std::string GetHex() const
    {
        return ToString(16);
    }

    unsigned int GetSerializeSize(int nType=0, int nVersion=PROTOCOL_VERSION) const
    {
        return ::GetSerializeSize(getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION) const
    {
        ::Serialize(s, getvch(), nType, nVersion);      // Указание члена(функции) глобального пространства ( :: оператором разрешения(изменения) области видимости. )
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION)
    {
        std::vector<unsigned char> vch;
        ::Unserialize(s, vch, nType, nVersion);
        setvch(vch);
    }


    bool operator!() const
    {
        return BN_is_zero(value);
    }

    CBigNum& operator+=(const CBigNum& b)
    {
        if (!BN_add(value, value, b.value))
            throw bignum_error("CBigNum::operator+= : BN_add failed");
        return *this;
    }

    CBigNum& operator-=(const CBigNum& b)
    {
        *this = *this - b;
        return *this;
    }

    CBigNum& operator*=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_mul(this->value, this->value, b.value, pctx))
            throw bignum_error("CBigNum::operator*= : BN_mul failed");
        return *this;
    }

    CBigNum& operator/=(const CBigNum& b)
    {
        *this = *this / b;
        return *this;
    }

    CBigNum& operator%=(const CBigNum& b)
    {
        *this = *this % b;
        return *this;
    }

    CBigNum& operator<<=(unsigned int shift)
    {
        if (!BN_lshift(this->value, this->value, shift))
            throw bignum_error("CBigNum:operator<<= : BN_lshift failed");
        return *this;
    }

    CBigNum& operator>>=(unsigned int shift)
    {
        // Note: BN_rshift segfaults on 64-bit if 2^shift is greater than the number  Примечание: ошибка сегментации BN_rshift на 64-битных если 2^shift больше, чем число
        //   if built on ubuntu 9.04 or 9.10, probably depends on version of OpenSSL  Если собирается на ubuntu 9.04 или 9.10, возможно, зависит от версии OpenSSL
        CBigNum a = 1;
        a <<= shift;
        if (BN_cmp(a.value, this->value) > 0)
        {
            *this = 0;
            return *this;
        }

        if (!BN_rshift(this->value, this->value, shift))
            throw bignum_error("CBigNum:operator>>= : BN_rshift failed");
        return *this;
    }


    CBigNum& operator++()
    {
        // prefix operator
        if (!BN_add(this->value, this->value, BN_value_one()))
            throw bignum_error("CBigNum::operator++ : BN_add failed");
        return *this;
    }

    const CBigNum operator++(int)
    {
        // postfix operator
        const CBigNum ret = *this;
        ++(*this);
        return ret;
    }

    CBigNum& operator--()
    {
        // prefix operator
        CBigNum r;
        if (!BN_sub(r.value, this->value, BN_value_one()))
            throw bignum_error("CBigNum::operator-- : BN_sub failed");
        *this = r;
        return *this;
    }

    const CBigNum operator--(int)
    {
        // postfix operator
        const CBigNum ret = *this;
        --(*this);
        return ret;
    }

    friend inline const CBigNum operator+(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator-(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator-(const CBigNum& a);
    friend inline const CBigNum operator*(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator/(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator%(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator<<(const CBigNum& a, unsigned int shift);

    friend inline bool operator==(const CBigNum& a, const CBigNum& b);
    friend inline bool operator!=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator>=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<(const CBigNum& a, const CBigNum& b);
    friend inline bool operator>(const CBigNum& a, const CBigNum& b);
};



inline const CBigNum operator+(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_add(r.value, a.value, b.value))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_sub(r.value, a.value, b.value))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a)
{
    CBigNum r(a);
    BN_set_negative(r.value, !BN_is_negative(r.value));
    return r;
}

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mul(r.value, a.value, b.value, pctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    return r;
}

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_div(r.value, NULL, a.value, b.value, pctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    return r;
}

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mod(r.value, a.value, b.value, pctx))
        throw bignum_error("CBigNum::operator% : BN_div failed");
    return r;
}

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r;
    if (!BN_lshift(r.value, a.value, shift))
        throw bignum_error("CBigNum:operator<< : BN_lshift failed");
    return r;
}

inline const CBigNum operator>>(const CBigNum& a, unsigned int shift)
{
    //TODO: chek how this works. I'm not sure.
    CBigNum r = a;
    r >>= shift;
    return r;
}

inline bool operator==(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.value, b.value) == 0); }
inline bool operator!=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.value, b.value) != 0); }
inline bool operator<=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.value, b.value) <= 0); }
inline bool operator>=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.value, b.value) >= 0); }
inline bool operator<(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.value, b.value) < 0); }
inline bool operator>(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.value, b.value) > 0); }

#endif
