// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UI_INTERFACE_H
#define BITCOIN_UI_INTERFACE_H

#include <string>
#include "util.h" // for int64
#include <boost/signals2/signal.hpp>
#include <boost/signals2/last_value.hpp>

class CBasicKeyStore;
class CWallet;
class uint256;

/** General change type (added, updated, removed).                              Общие типы изменения (добавление, обновление, удаление) */
enum ChangeType
{
    CT_NEW,
    CT_UPDATED,
    CT_DELETED
};

/** Signals for UI communication.                                               сигналы для UI коммуникации */
class CClientUIInterface
{
public:
    /** Flags for CClientUIInterface::ThreadSafeMessageBox                      флаги */
    enum MessageBoxFlags
    {
        ICON_INFORMATION    = 0,
        ICON_WARNING        = (1U << 0),
        ICON_ERROR          = (1U << 1),
        /**
         * Mask of all available icons in CClientUIInterface::MessageBoxFlags   Маска всех доступных иконок в CClientUIInterface::MessageBoxFlags
         * This needs to be updated, when icons are changed there!              Это нуждается в обновлении, когда иконки меняются там!
         */
        ICON_MASK = (ICON_INFORMATION | ICON_WARNING | ICON_ERROR),

        /** These values are taken(взяты) from qmessagebox.h "enum StandardButton" to be directly usable(чтобы быть напрямую пользоваными) */
        BTN_OK      = 0x00000400U, // QMessageBox::Ok
        BTN_YES     = 0x00004000U, // QMessageBox::Yes
        BTN_NO      = 0x00010000U, // QMessageBox::No
        BTN_ABORT   = 0x00040000U, // QMessageBox::Abort
        BTN_RETRY   = 0x00080000U, // QMessageBox::Retry
        BTN_IGNORE  = 0x00100000U, // QMessageBox::Ignore
        BTN_CLOSE   = 0x00200000U, // QMessageBox::Close
        BTN_CANCEL  = 0x00400000U, // QMessageBox::Cancel
        BTN_DISCARD = 0x00800000U, // QMessageBox::Discard
        BTN_HELP    = 0x01000000U, // QMessageBox::Help
        BTN_APPLY   = 0x02000000U, // QMessageBox::Apply
        BTN_RESET   = 0x04000000U, // QMessageBox::Reset
        /**
         * Mask of all available buttons in CClientUIInterface::MessageBoxFlags Маска всех доступных кнопок в CClientUIInterface::MessageBoxFlags
         * This needs to be updated, when buttons are changed there!            Это нуждается в обновлении, когда кнопки меняются там!
         */
        BTN_MASK = (BTN_OK | BTN_YES | BTN_NO | BTN_ABORT | BTN_RETRY | BTN_IGNORE |
                    BTN_CLOSE | BTN_CANCEL | BTN_DISCARD | BTN_HELP | BTN_APPLY | BTN_RESET),

        /** Force blocking, modal message box dialog (not just OS notification) Силовое блокирование, модальный диалог окна сообщения (не только ОС уведомления)*/
        MODAL               = 0x10000000U,

        /** Predefined combinations for certain default usage cases             Предопределенные комбинации для определенных случаев использования по умолчанию */
        MSG_INFORMATION = ICON_INFORMATION,
        MSG_WARNING = (ICON_WARNING | BTN_OK | MODAL),
        MSG_ERROR = (ICON_ERROR | BTN_OK | MODAL)
    };

    /** Show message box.                                                       Показать окно сообщений */
    boost::signals2::signal<bool (const std::string& message, const std::string& caption, unsigned int style), boost::signals2::last_value<bool> > ThreadSafeMessageBox;

    /** Ask the user whether they want to pay a fee or not.                     Спросите пользователя, хочет ли он заплатить коммиссию или нет */
    boost::signals2::signal<bool (int64 nFeeRequired), boost::signals2::last_value<bool> > ThreadSafeAskFee;

    /** Handle a URL passed at the command line.                                Обрабатывать URL-адрес, переданный в командной строке */
    boost::signals2::signal<void (const std::string& strURI)> ThreadSafeHandleURI;

    /** Progress message during initialization.                                 Сообщение о ходе выполнения во время инициализации. */
    boost::signals2::signal<void (const std::string &message)> InitMessage;

    /** Translate a message to the native language of the user.                 Перевод сообщения на роднй язык пользователя. */
    boost::signals2::signal<std::string (const char* psz)> Translate;

    /** Block chain changed.                                                    Цепь блоков изменилась */
    boost::signals2::signal<void ()> NotifyBlocksChanged;

    /** Number of network connections changed.                                  Изменение количества сетевых подключений */
    boost::signals2::signal<void (int newNumConnections)> NotifyNumConnectionsChanged;

    /**
     * New, updated or cancelled alert.                                         Новоее, обновленное или предупреждение отмены
     * @note called with lock cs_mapAlerts held.                                @note вызывается с закрытым cs_mapAlerts проведением
     */
    boost::signals2::signal<void (const uint256 &hash, ChangeType status)> NotifyAlertChanged;
};

extern CClientUIInterface uiInterface;

/**
 * Translation function: Call Translate signal on UI interface, which returns a boost::optional result.
 * If no translation slot is registered, nothing is returned, and simply return the input.
 *                  Функция перевода: Вызывает сигнал перевода в UI интерфейсе, который возвращает boost::optional результаты.
 *                  Если нет переводимого слота, ничего не возвращается, а просто возвращается ввод
 */
inline std::string _(const char* psz)
{
    boost::optional<std::string> rv = uiInterface.Translate(psz);
    return rv ? (*rv) : psz;
}

#endif
