// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

#include "clientversion.h"
#include <string>

//
// client versioning                                                                Управление версиями клиента
//

static const int CLIENT_VERSION =
                           1000000 * CLIENT_VERSION_MAJOR
                         +   10000 * CLIENT_VERSION_MINOR
                         +     100 * CLIENT_VERSION_REVISION
                         +       1 * CLIENT_VERSION_BUILD;

extern const std::string CLIENT_NAME;
extern const std::string CLIENT_BUILD;
extern const std::string CLIENT_DATE;

//
// network protocol versioning                                                      Управления версиями сетевого протокола
//

static const int PROTOCOL_VERSION = 70001;

// earlier versions not supported as of Feb 2012, and are disconnected              Более ранние версии не поддерживаются начиная с февраля 2012 года и являются отключенными
static const int MIN_PROTO_VERSION = 209;

// nTime field added to CAddress, starting with this version;                       Ntime поле добавляется в CAddress, начиная с этой версии;
// if possible, avoid requesting addresses nodes older than this                    Если возможно, избегайте запросов адресов нодов, старше чем это
static const int CADDR_TIME_VERSION = 31402;

// only request blocks from nodes outside this range of versions                    только запрашивайте блоки от узлов за пределами этого диапазона версий
static const int NOBLKS_VERSION_START = 32000;
static const int NOBLKS_VERSION_END = 32400;

// BIP 0031, pong message, is enabled for all versions AFTER this one               понг сообщение, включено для всех версий ПОСЛЕ этого
static const int BIP0031_VERSION = 60000;

// "mempool" command, enhanced "getdata" behavior starts with this version:         команда, усиливающая "getdata" поведение(режим) начиная с этой версии:
static const int MEMPOOL_GD_VERSION = 60002;

#endif
