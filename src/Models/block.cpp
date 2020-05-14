//
// Created by prism-lab on 14-May-20.
//

#include "block.h"

#include "main.h"

uint256 CBlockHeader::GetHashFork(int tHeight) const
{
    uint256 thash;
    if (tHeight > HEIGHT_OTHER_ALGO)
        lyra2TDC(BEGIN(nVersion), BEGIN(thash), 80);
    else
        lyra2re2_hashTX(BEGIN(nVersion), BEGIN(thash), 80);
    return thash;
}

uint256 CBlockHeader::GetHash() const
{
    uint256 thash;
    if (mapBlockIndex.count(hashPrevBlock))
    {
        CBlockIndex* pindexPrev = mapBlockIndex[hashPrevBlock];
        if (pindexPrev->nHeight + 1 > HEIGHT_OTHER_ALGO)
            lyra2TDC(BEGIN(nVersion), BEGIN(thash), 80);
        else
            lyra2re2_hashTX(BEGIN(nVersion), BEGIN(thash), 80);
    }
//    else if (mapBlockIndex.size() <= (unsigned int)HEIGHT_OTHER_ALGO)
    else if (mapBlockIndex.size() <= (unsigned int)HEIGHT_OTHER_ALGO && nTime < 1534063443)
        lyra2re2_hashTX(BEGIN(nVersion), BEGIN(thash), 80);
    else
        lyra2TDC(BEGIN(nVersion), BEGIN(thash), 80);

    return thash;
}

uint256 CBlock::BuildMerkleTree() const
{
    vMerkleTree.clear();
    BOOST_FOREACH(const CTransaction& tx, vtx)
    vMerkleTree.push_back(tx.GetHash());
    int j = 0;
    for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
    {
        for (int i = 0; i < nSize; i += 2)
        {
            int i2 = std::min(i+1, nSize-1);
            vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                       BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
        }
        j += nSize;
    }
    return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
}

std::vector<uint256> CBlock::GetMerkleBranch(int nIndex) const          // Branch - ветка
{
    if (vMerkleTree.empty())
        BuildMerkleTree();
    std::vector<uint256> vMerkleBranch;
    int j = 0;
    for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
    {
        int i = std::min(nIndex^1, nSize-1);
        vMerkleBranch.push_back(vMerkleTree[j+i]);
        nIndex >>= 1;
        j += nSize;
    }
    return vMerkleBranch;
}

uint256 CBlock::CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
{
    if (nIndex == -1)
        return 0;
    BOOST_FOREACH(const uint256& otherside, vMerkleBranch)
    {
        if (nIndex & 1)
            hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
        else
            hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
        nIndex >>= 1;
    }
    return hash;
}

void CBlock::print() const
{
    printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%" PRIszu")\n",
            GetHash().ToString().c_str(),
            nVersion,
            hashPrevBlock.ToString().c_str(),
            hashMerkleRoot.ToString().c_str(),
            nTime, nBits, nNonce,
            vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        printf("  ");
        vtx[i].print();
    }
    printf("  vMerkleTree: ");
    for (unsigned int i = 0; i < vMerkleTree.size(); i++)
        printf("%s ", vMerkleTree[i].ToString().c_str());
    printf("\n");
}
