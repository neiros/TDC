// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_ALLOCATORS_H
#define BITCOIN_ALLOCATORS_H

#include <string.h>
#include <string>
#include <boost/thread/mutex.hpp>
#include <map>
#include <openssl/crypto.h> // for OPENSSL_cleanse()

#ifdef WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// This is used to attempt to keep keying material out of swap                          Это используется для попытки сохранения материала из (свопа)подкачки
// Note that VirtualLock does not provide this as a guarantee on Windows,               Обратите внимание, что VirtualLock не поддерживает это гарантированно в Windows,
// but, in practice, memory that has been VirtualLock'd almost never gets written to    но на практике, память, которая была получена VirtualLock никогда не записывается
// the pagefile except in rare circumstances where memory is extremely low.             в файл подкачки, за исключением редких случаях, когда памяти крайне мало.

#else
#include <sys/mman.h>
#include <limits.h> // for PAGESIZE
#include <unistd.h> // for sysconf
#endif

/**
 * Thread-safe class to keep track of locked (ie, non-swappable) memory pages.          Потокобезопасный класс отслеживает заблокированные (т.е. незаменяемые) страницы памяти
 *
 * Memory locks do not stack, that is, pages which have been locked several times by calls to mlock()
 * will be unlocked by a single call to munlock(). This can result in keying material ending up in swap when
 * those functions are used naively. This class simulates stacking memory locks by keeping a counter per page.
 *
 *                  Блокировки памяти не складываются, то есть страницы, которые были заблокированы несколько раз путем вызовов mlock()
 *                  будет разблокированы с помощью одного вызова munlock(). Это может привести к оседают ключевого материала в своп, когда
 *                  эти функции используются наивно. Этот класс моделирует наложение блокировки памяти, сохраняя счетчик страниц.
 *
 * @note By using a map from each page base address to lock count, this class is optimized for
 * small objects that span up to a few pages, mostly smaller than a page. To support large allocations,
 * something like an interval tree would be the preferred data structure.
 *
 *                  Для использования карты из каждой страницы базового адреса для блокировки счета, этот класс оптимизирован для
 *                  небольших объектов, которые охватывают до нескольких страниц, в основном меньше чем страница.
 *                  Для поддержки крупных локализаций, что-то вроде дерева интервалов будет предпочтительным структуры данных.
 */
template <class Locker> class LockedPageManagerBase
{
public:
    LockedPageManagerBase(size_t page_size):
        page_size(page_size)
    {
        // Determine bitmask for extracting page from address                       Определение битовой маски для извлечения страницы от адреса
        assert(!(page_size & (page_size-1))); // size must be power of two          размер должен быть степенью(мощностью) двойки
        page_mask = ~(page_size - 1);
    }

    // For all pages in affected range, increase lock count                         Для всех страниц в обрабатываемом диапазоне увеличить количество блокировок
    void LockRange(void *p, size_t size)
    {
        boost::mutex::scoped_lock lock(mutex);
        if(!size) return;
        const size_t base_addr = reinterpret_cast<size_t>(p);
        const size_t start_page = base_addr & page_mask;
        const size_t end_page = (base_addr + size - 1) & page_mask;
        for(size_t page = start_page; page <= end_page; page += page_size)
        {
            Histogram::iterator it = histogram.find(page);
            if(it == histogram.end()) // Newly locked page                          Недавно заблокированная страница
            {
                locker.Lock(reinterpret_cast<void*>(page), page_size);
                histogram.insert(std::make_pair(page, 1));
            }
            else // Page was already locked; increase counter                       Страница уже заблокирована; увеличение счетчика
            {
                it->second += 1;
            }
        }
    }

    // For all pages in affected range, increase lock count                         Для всех страниц в обрабатываемом диапазоне увеличить количество блокировок
    void UnlockRange(void *p, size_t size)
    {
        boost::mutex::scoped_lock lock(mutex);
        if(!size) return;
        const size_t base_addr = reinterpret_cast<size_t>(p);
        const size_t start_page = base_addr & page_mask;
        const size_t end_page = (base_addr + size - 1) & page_mask;
        for(size_t page = start_page; page <= end_page; page += page_size)
        {
            Histogram::iterator it = histogram.find(page);
            assert(it != histogram.end()); // Cannot unlock an area that was not locked     Нельза разблокировать область, которая не была заблокирована
            // Decrease counter for page, when it is zero, the page will be unlocked        Уменьшение счетчика для страницы, когда он равен нулю, страница будет разблокирована
            it->second -= 1;
            if(it->second == 0) // Nothing on the page anymore that keeps it locked         Ничего на странице больше нет, что держить её заблокированной
            {
                // Unlock page and remove the count from histogram                  Разблокировать страницу и удалить счетчик из гистограммы
                locker.Unlock(reinterpret_cast<void*>(page), page_size);
                histogram.erase(it);
            }
        }
    }

    // Get number of locked pages for diagnostics                                   Получить количество заблокированных страницах для диагностики.
    int GetLockedPageCount()
    {
        boost::mutex::scoped_lock lock(mutex);
        return histogram.size();
    }

private:
    Locker locker;
    boost::mutex mutex;
    size_t page_size, page_mask;
    // map of page base address to lock count                                       карта страницы базового адреса для блокировки счетчика
    typedef std::map<size_t,int> Histogram;
    Histogram histogram;
};

/** Determine system page size in bytes                                 Определение размера страницы системы в байтах  */
static inline size_t GetSystemPageSize()
{
    size_t page_size;
#if defined(WIN32)
    SYSTEM_INFO sSysInfo;
    GetSystemInfo(&sSysInfo);
    page_size = sSysInfo.dwPageSize;
#elif defined(PAGESIZE) // defined in limits.h
    page_size = PAGESIZE;
#else // assume some POSIX OS
    page_size = sysconf(_SC_PAGESIZE);
#endif
    return page_size;
}

/**
 * OS-dependent memory page locking/unlocking.                          OS-зависимое блокирование/разблокирование страниц памяти
 * Defined as policy class to make stubbing for test possible.          Определяется как класс политики, чтобы сделать возможным использование заглушек для тестирования.
 */
class MemoryPageLocker
{
public:
    /** Lock memory pages.                                              Блокировка страниц памяти.
     * addr and len must be a multiple of the system page size          addr и len должны быть кратны размеру страницы системы
     */
    bool Lock(const void *addr, size_t len)
    {
#ifdef WIN32
        return VirtualLock(const_cast<void*>(addr), len);
#else
        return mlock(addr, len) == 0;
#endif
    }
    /** Unlock memory pages.                                            Разблокировка страниц памяти.
     * addr and len must be a multiple of the system page size          addr и len должны быть кратны размеру страницы системы
     */
    bool Unlock(const void *addr, size_t len)
    {
#ifdef WIN32
        return VirtualUnlock(const_cast<void*>(addr), len);
#else
        return munlock(addr, len) == 0;
#endif
    }
};

/**
 * Singleton class to keep track of locked (ie, non-swappable) memory pages, for use in
 * std::allocator templates.
 *
 *                  Единственный класс отслеживающий заблокированные (т.е. не-замещяемые) страницы памяти, для использования в
 *                  std::allocator шаблонах
 */
class LockedPageManager: public LockedPageManagerBase<MemoryPageLocker>
{
public:
    static LockedPageManager instance; // instantiated in util.cpp      конкретизированный в util.cpp
private:
    LockedPageManager():
        LockedPageManagerBase<MemoryPageLocker>(GetSystemPageSize())
    {}
};

//
// Functions for directly locking/unlocking memory objects.             Функции для непосредственно блокировка/разблокировка объектов памяти.
// Intended for non-dynamically allocated structures.                   Предназначено для не-динамически выделяемых структур.
//
template<typename T> void LockObject(const T &t) {
    LockedPageManager::instance.LockRange((void*)(&t), sizeof(T));
}

template<typename T> void UnlockObject(const T &t) {
    OPENSSL_cleanse((void*)(&t), sizeof(T));
    LockedPageManager::instance.UnlockRange((void*)(&t), sizeof(T));
}

//
// Allocator that locks its contents from being paged                   Распределитель блокирует его содержимое от выгружаемый из памяти
// out of memory and clears its contents before deletion.               и очищает его содержание до удаления.
//
template<typename T>
struct secure_allocator : public std::allocator<T>
{
    // MSVC8 default copy constructor is broken
    typedef std::allocator<T> base;
    typedef typename base::size_type size_type;
    typedef typename base::difference_type  difference_type;
    typedef typename base::pointer pointer;
    typedef typename base::const_pointer const_pointer;
    typedef typename base::reference reference;
    typedef typename base::const_reference const_reference;
    typedef typename base::value_type value_type;
    secure_allocator() throw() {}
    secure_allocator(const secure_allocator& a) throw() : base(a) {}
    template <typename U>
    secure_allocator(const secure_allocator<U>& a) throw() : base(a) {}
    ~secure_allocator() throw() {}
    template<typename _Other> struct rebind
    { typedef secure_allocator<_Other> other; };

    T* allocate(std::size_t n, const void *hint = 0)
    {
        T *p;
        p = std::allocator<T>::allocate(n, hint);
        if (p != NULL)
            LockedPageManager::instance.LockRange(p, sizeof(T) * n);
        return p;
    }

    void deallocate(T* p, std::size_t n)
    {
        if (p != NULL)
        {
            OPENSSL_cleanse(p, sizeof(T) * n);
            LockedPageManager::instance.UnlockRange(p, sizeof(T) * n);
        }
        std::allocator<T>::deallocate(p, n);
    }
};


//
// Allocator that clears its contents before deletion.                  Распределитель, который очищает его содержимое перед удалением.
//
template<typename T>
struct zero_after_free_allocator : public std::allocator<T>
{
    // MSVC8 default copy constructor is broken                         MSVC8 по умолчанию конструктор копирования разбит
    typedef std::allocator<T> base;
    typedef typename base::size_type size_type;
    typedef typename base::difference_type  difference_type;
    typedef typename base::pointer pointer;
    typedef typename base::const_pointer const_pointer;
    typedef typename base::reference reference;
    typedef typename base::const_reference const_reference;
    typedef typename base::value_type value_type;
    zero_after_free_allocator() throw() {}
    zero_after_free_allocator(const zero_after_free_allocator& a) throw() : base(a) {}
    template <typename U>
    zero_after_free_allocator(const zero_after_free_allocator<U>& a) throw() : base(a) {}
    ~zero_after_free_allocator() throw() {}
    template<typename _Other> struct rebind
    { typedef zero_after_free_allocator<_Other> other; };

    void deallocate(T* p, std::size_t n)
    {
        if (p != NULL)
            OPENSSL_cleanse(p, sizeof(T) * n);
        std::allocator<T>::deallocate(p, n);
    }
};

// This is exactly like std::string, but with a custom allocator.       Это точно как std::string, но с пользовательский распределителем
typedef std::basic_string<char, std::char_traits<char>, secure_allocator<char> > SecureString;

#endif
