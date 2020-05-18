// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <vector>

#include "Helpers/allocators.h"
#include "Helpers/serialize.h"
#include "Helpers/uint256.h"

#include "Helpers/hash.h"

// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push

/** A reference to a CKey: the Hash160 of its serialized public key                 Ссылка на CKey: Hash160 сериализованного публичного ключа */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160(0) { }
    CKeyID(const uint160 &in) : uint160(in) { }
};

/** A reference to a CScript: the Hash160 of its serialization (see script.h)       Ссылка на CScript: Hash160 его сериализации (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160(0) { }
    CScriptID(const uint160 &in) : uint160(in) { }
};

/** An encapsulated public key.     (инкапсуляция(изолирование) открытого ключа)*/
class CPubKey {
private:
    // Just store the serialized data.                                              Просто хранить упорядоченные данные.
    // Its length can very cheaply be computed from the first byte.                 Его длина может быть вычислена очень дешево от первого байта.
    unsigned char vch[65];

    // Compute the length of a pubkey with a given first byte.                      Вычисление длины pubkey с данного первого байта.
    unsigned int static GetLen(unsigned char chHeader) {
        if (chHeader == 2 || chHeader == 3)
            return 33;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return 65;
        return 0;
    }

    // Set this key data to be invalid                                              Установление данных для этого ключа, недействителными
    void Invalidate() {
        vch[0] = 0xFF;
    }

public:
    // Construct an invalid public key.                                             Конструктор инвалидного публичного ключа.
    CPubKey() {
        Invalidate();
    }

    // Initialize a public key using begin/end iterators to byte data.              Инициализация использования публичного ключа начала/конца итераторов в байтах данных.
    template<typename T>
    void Set(const T pbegin, const T pend) {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend-pbegin))
            memcpy(vch, (unsigned char*)&pbegin[0], len);
        else
            Invalidate();
    }

    // Construct a public key using begin/end iterators to byte data.               Конструктор использования публичного ключа начала/конца итераторов в байтах данных.
    template<typename T>
    CPubKey(const T pbegin, const T pend) {
        Set(pbegin, pend);
    }

    // Construct a public key from a byte vector.                                   Конструктор публичного ключа из вектора байтов.
    CPubKey(const std::vector<unsigned char> &vch) {
        Set(vch.begin(), vch.end());
    }

    // Simple read-only vector-like interface to the pubkey data.                   Простой только-для-чтения вектор-подобный интерфейс для публичных данных.
    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char *begin() const { return vch; }
    const unsigned char *end() const { return vch+size(); }
    const unsigned char &operator[](unsigned int pos) const { return vch[pos]; }

    // Comparator implementation.                                                   Компаратор реализации
    friend bool operator==(const CPubKey &a, const CPubKey &b) {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey &a, const CPubKey &b) {
        return !(a == b);
    }
    friend bool operator<(const CPubKey &a, const CPubKey &b) {
        return a.vch[0] < b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    // Implement serialization, as if this was a byte vector.                       Осуществление преобразования, как если бы это был байт вектор.
    unsigned int GetSerializeSize(int nType, int nVersion) const {
        return size() + 1;
    }
    template<typename Stream> void Serialize(Stream &s, int nType, int nVersion) const {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s.write((char*)vch, len);
    }
    template<typename Stream> void Unserialize(Stream &s, int nType, int nVersion) {
        unsigned int len = ::ReadCompactSize(s);
        if (len <= 65) {
            s.read((char*)vch, len);
        } else {
            // invalid pubkey, skip available data                                  Неверный pubkey, пропуск имеющихся данных
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    // Get the KeyID of this public key (hash of its serialization)                 Получение KeyID этого публичного ключа (хеша его сериализации)
    CKeyID GetID() const {
        return CKeyID(Hash160(vch, vch+size()));
    }

    // Get the 256-bit hash of this public key.                                     Получение 256-битного хеша этого публичного ключа
    uint256 GetHash() const {
        return Hash(vch, vch+size());
    }

    // just check syntactic correctness.                                            Просто проверить корректность синтаксиса
    bool IsValid() const {
        return size() > 0;
    }

    // fully validate whether this is a valid public key (more expensive than IsValid())   Полная проверка, является ли это действительным открытым ключём (дороже, чем IsValid ())
    bool IsFullyValid() const;

    // Check whether this is a compressed public key.                               Проверить, является ли это сжатый открытый ключ
    bool IsCompressed() const {
        return size() == 33;
    }

    // Verify a DER signature (~72 bytes).                                          Проверить DER подпись (~72 байт).
    // If this public key is not fully valid, the return value will be false.       Если этот открытый ключ не полностью действителен, возвращаемое значение будет false.
    bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const;

    // Verify a compact signature (~65 bytes).                                      Проверить компактную подпись (~65 байт).
    // See CKey::SignCompact.
    bool VerifyCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) const;

    // Recover a public key from a compact signature.                               Востановление публичного ключа из компактной подписи
    bool RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig);

    // Turn this public key into an uncompressed public key.                        Вернуть этот публичный ключ не сжатым публичным ключом
    bool Decompress();
};


// secure_allocator is defined in allocators.h                                      безопасный_распределитель определяется в allocators.h
// CPrivKey is a serialized private key, with all parameters included (279 bytes)   CPrivKey является сериализованным приватным ключом, со всеми включеными параметрами (279 байт)
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

/** An encapsulated private key.     (инкапсуляция(изолирование) приватного ключа)*/
class CKey {
private:
    // Whether this private key is valid. We check for correctness when modifying   Действителен ли этот частный ключ. Мы проверяем для правильности, изменяя ключевые данные
    // the key data, so fValid should always correspond to the actual state.        таким образом fValid должен всегда соответствовать фактическому состоянию.
    bool fValid;

    // Whether the public key corresponding to this private key is (to be) compressed.   Если открытый ключ, соответствует этому секретный ключ (будет) сжать
    bool fCompressed;

    // The actual byte data                                                         Актуальные байтовые данные
    unsigned char vch[32];

    // Check whether the 32-byte array pointed to be vch is valid keydata.          Убедитесь в том, 32-байтовый массив vch с действительным keydata.
    bool static Check(const unsigned char *vch);
public:

    // Construct an invalid private key.                                            Конструктор инвалидного приватного ключа
    CKey() : fValid(false) {
        LockObject(vch);
    }

    // Copy constructor. This is necessary because of memlocking.                   Копия конструктора. Это необходимо из-за memlocking.
    CKey(const CKey &secret) : fValid(secret.fValid), fCompressed(secret.fCompressed) {
        LockObject(vch);
        memcpy(vch, secret.vch, sizeof(vch));
    }

    // Destructor (again necessary because of memlocking).                          Деструктор (опять же необходимо из-за memlocking)
    ~CKey() {
        UnlockObject(vch);
    }

    // Initialize using begin and end iterators to byte data.                       Инициализация использует начальный и конечный итераторы байт данных.
    template<typename T>
    void Set(const T pbegin, const T pend, bool fCompressedIn) {
        if (pend - pbegin != 32) {
            fValid = false;
            return;
        }
        if (Check(&pbegin[0])) {
            memcpy(vch, (unsigned char*)&pbegin[0], 32);
            fValid = true;
            fCompressed = fCompressedIn;
        } else {
            fValid = false;
        }
    }

    // Simple read-only vector-like interface.                                      Простой только-для-чтения вектор-подобный интерфейс.
    unsigned int size() const { return (fValid ? 32 : 0); }
    const unsigned char *begin() const { return vch; }
    const unsigned char *end() const { return vch + size(); }

    // Check whether this private key is valid.                                     Проверьте этот закрытый ключ на валидность.
    bool IsValid() const { return fValid; }

    // Check whether the public key corresponding to this private key is (to be) compressed. (Проверьте, является ли общественный ключ, соответствующий этому частному ключу (чтобы быть) сжатым)
    bool IsCompressed() const { return fCompressed; }

    // Initialize from a CPrivKey (serialized OpenSSL private key data).            Инициализация от CPrivKey (сериализация OpenSSL данных приватного ключа)
    bool SetPrivKey(const CPrivKey &vchPrivKey, bool fCompressed);

    // Generate a new private key using a cryptographic PRNG.                       Создать новый закрытый ключ с использованием криптографической PRNG(генератор псевдо-случайных чисел)
    void MakeNewKey(bool fCompressed);

    // Convert the private key to a CPrivKey (serialized OpenSSL private key data). Преобразование частного ключа в CPrivKey (сериализация OpenSSL данных приватного ключа),
    // This is expensive.                                                           Это дорого
    CPrivKey GetPrivKey() const;

    // Compute the public key from a private key.                                   Вычисление публичного ключа из приватного ключа
    // This is expensive.                                                           Это дорого
    CPubKey GetPubKey() const;

    // Create a DER-serialized signature.                                           Создание DER-сериализованной подписи
    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig) const;

    // Create a compact signature (65 bytes), which allows reconstructing the used public key.          Создание компактной подписи (65 байтов), которая позволяет восстанавливать используемый общественный ключ.
    // The format is one header byte, followed by two times 32 bytes for the serialized r and s values. Форматом из одного байта заголовка, а затем два раза 32 байт для сериализованных r и s значений
    // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,                      Байт заголовка: 0x1B = первый ключ с четным у, 0x1C = первый ключ с нечетными у,
    //                  0x1D = second key with even y, 0x1E = second key with odd y,                                    0x1D = второй ключ с четным y, 0x1E = второй ключ с нечетными y,
    //                  add 0x04 for compressed keys.                                                                   добавить 0x04 для сжатия ключей
    bool SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const;
};

#endif
