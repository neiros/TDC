//
// Created by prism-lab on 14-May-20.
//

#ifndef TDC_CORE_BLOCK_H
#define TDC_CORE_BLOCK_H

#include "Utils/uint256.h"
#include "Utils/serialize.h"
#include "Lyra2RE.h"

#include "transaction.h"

#include <stdio.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 *
 * Узлы собирают новые транзакции в блок, хеш-их в хеш-дерево
 * и сканируют прошлые nonce значения в блоках хеш требования proof-of-work.
 * Когда они решить доказательство-работы, они передаются в блок для всех, и блок добавляется в block chain.
 * Первая транзакция в блоке - это специальный одна, создающая новую монету, принадлежащую создателю блока.
 *
 */
class CBlockHeader
{
public:
    // header (заголовок)
    static const int CURRENT_VERSION=2;
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    CBlockHeader()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
    READWRITE(this->nVersion);
    nVersion = this->nVersion;
    READWRITE(hashPrevBlock);
    READWRITE(hashMerkleRoot);
    READWRITE(nTime);
    READWRITE(nBits);
    READWRITE(nNonce);
    )

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHashFork(int tHeight) const;

    uint256 GetHash() const;

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    IMPLEMENT_SERIALIZE
    (
    READWRITE(*(CBlockHeader*)this);
    READWRITE(vtx);
    )

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vMerkleTree.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    uint256 BuildMerkleTree() const;

    const uint256 &GetTxHash(unsigned int nIndex) const {
        assert(vMerkleTree.size() > 0); // BuildMerkleTree must have been called first  (BuildMerkleTree должен быть вызван первым)
        assert(nIndex < vtx.size());
        return vMerkleTree[nIndex];
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const;               // Branch - ветка
    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);
    void print() const;
};

#endif //TDC_CORE_BLOCK_H
