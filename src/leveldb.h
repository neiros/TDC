// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_LEVELDB_H
#define BITCOIN_LEVELDB_H

#include "Utils/serialize.h"

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include <boost/filesystem/path.hpp>

class leveldb_error : public std::runtime_error
{
public:
    leveldb_error(const std::string &msg) : std::runtime_error(msg) {}
};

void HandleError(const leveldb::Status &status) throw(leveldb_error);

// Batch of changes queued to be written to a CLevelDB                              серия изменений в очереди, которые должны быть записаны в CLevelDB
class CLevelDBBatch
{
    friend class CLevelDB;

private:
    leveldb::WriteBatch batch;

public:
    template<typename K, typename V> void Write(const K& key, const V& value) {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(ssValue.GetSerializeSize(value));
        ssValue << value;
        leveldb::Slice slValue(&ssValue[0], ssValue.size());

        batch.Put(slKey, slValue);
    }

    template<typename K> void Erase(const K& key) {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        batch.Delete(slKey);
    }
};

class CLevelDB
{
private:
    // custom environment this database is using (may be NULL in case of default environment)  пользовательская среда этой используемой базы данных (может иметь значение NULL в случае среды по умолчанию)
    leveldb::Env *penv;

    // database options used                                                        параметры использования базы данных
    leveldb::Options options;

    // options used when reading from the database                                  параметры, используемые при чтении из базы данных
    leveldb::ReadOptions readoptions;

    // options used when iterating over values of the database                      параметры, используемые при итерации значений базы данных
    leveldb::ReadOptions iteroptions;

    // options used when writing to the database                                    параметры, используемые при записи в базу данных
    leveldb::WriteOptions writeoptions;

    // options used when sync writing to the database                               параметры, использованные при синхронизации записи в базу
    leveldb::WriteOptions syncoptions;

    // the database itself                                                          сама база данных
    leveldb::DB *pdb;

public:
    CLevelDB(const boost::filesystem::path &path, size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    ~CLevelDB();

    template<typename K, typename V> bool Read(const K& key, V& value) throw(leveldb_error) {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            printf("LevelDB read failure: %s\n", status.ToString().c_str());
            HandleError(status);
        }
        try {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue >> value;
        } catch(std::exception &e) {
            return false;
        }
        return true;
    }

    template<typename K, typename V> bool Write(const K& key, const V& value, bool fSync = false) throw(leveldb_error) {
        CLevelDBBatch batch;
        batch.Write(key, value);
        return WriteBatch(batch, fSync);
    }

    template<typename K> bool Exists(const K& key) throw(leveldb_error) {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            printf("LevelDB read failure: %s\n", status.ToString().c_str());
            HandleError(status);
        }
        return true;
    }

    template<typename K> bool Erase(const K& key, bool fSync = false) throw(leveldb_error) {
        CLevelDBBatch batch;
        batch.Erase(key);
        return WriteBatch(batch, fSync);
    }

    bool WriteBatch(CLevelDBBatch &batch, bool fSync = false) throw(leveldb_error);

    // not available for LevelDB; provide for compatibility with BDB                не доступны для LevelDB; обеспечена совместимость с BDB
    bool Flush() {
        return true;
    }

    bool Sync() throw(leveldb_error) {
        CLevelDBBatch batch;
        return WriteBatch(batch, true);
    }

    // not exactly clean encapsulation, but it's easiest for now                    не совсем чистые инкапсуляции, но это является самым легким пока
    leveldb::Iterator *NewIterator() {
        return pdb->NewIterator(iteroptions);
    }
};

#endif // BITCOIN_LEVELDB_H
