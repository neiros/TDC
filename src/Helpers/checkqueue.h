// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef CHECKQUEUE_H
#define CHECKQUEUE_H

#include <boost/thread/mutex.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/condition_variable.hpp>

#include <vector>
#include <algorithm>

template<typename T> class CCheckQueueControl;

/** Queue for verifications that have to be performed.                              Очередь для проверок, которые должны быть выполнены
  * The verifications are represented by a type T, which must provide an            Проверки представлены как тип T, который должен обеспечить
  * operator(), returning a bool.operator(),                                        operator(), возвращая bool.operator()
  *
  * One thread (the master) is assumed to push batches of verifications             Один поток (master) предполагается передаёт порции проверок
  * onto the queue, where they are processed by N-1 worker threads. When            в очередь, где они обрабатываются N-1 рабочими потокамию. Когда
  * the master is done adding work, it temporarily joins the worker pool            мастер выполняет добавление работы, она временно присоединяется как
  * as an N'th worker, until all jobs are done.                                     работник пула из N работников, до тех пор пока все задания будут выполнены.
  */
template<typename T> class CCheckQueue {
private:
    // Mutex to protect the inner state                                             Mutex для защиты внутреннего состояния
    boost::mutex mutex;

    // Worker threads block on this when out of work                                Блокировка рабочих потоков, когда нет работы
    boost::condition_variable condWorker;

    // Master thread blocks on this when out of work                                Блокировка мастер-потока, когда нет работы
    boost::condition_variable condMaster;

    // The queue of elements to be processed.                                       очередь элементов для обработки
    // As the order of booleans doesn't matter, it is used as a LIFO (stack)        как порядок логические значения не имеющих значения, это используется как LIFO (стек)
    std::vector<T> queue;

    // The number of workers (including the master) that are idle.                  Количество работников (в том числе мастер), что простаивают
    int nIdle;

    // The total number of workers (including the master).                          Общее количество работников (в том числе мастер)
    int nTotal;

    // The temporary evaluation result.                                             Результат временный оценки
    bool fAllOk;

    // Number of verifications that haven't completed yet.                          Количество проверок, которые еще не завершены.
    // This includes elements that are not anymore in queue, but still in           Это включает в себя элементы, которые больше не в очереди, но по-прежнему
    // worker's own batches.                                                        у работников в их пакетах(партиях)
    unsigned int nTodo;

    // Whether we're shutting down.                                                 Закрываемся ли мы
    bool fQuit;

    // The maximum number of elements to be processed in one batch                  Максимальное количество элементов, которые должны быть обработаны в одной партии
    unsigned int nBatchSize;

    // Internal function that does bulk of the verification work.                   Внутренние функции, которые выполняет основную часть работа по контролю
    bool Loop(bool fMaster = false) {
        boost::condition_variable &cond = fMaster ? condMaster : condWorker;
        std::vector<T> vChecks;
        vChecks.reserve(nBatchSize);
        unsigned int nNow = 0;
        bool fOk = true;
        do {
            {
                boost::unique_lock<boost::mutex> lock(mutex);
                // first do the clean-up of the previous loop run (allowing us to do it in the same critsect)
                //                      Сначала делаем очистку предыдущего цикла запуска (что позволяет нам делать это в том же critsect)
                if (nNow) {
                    fAllOk &= fOk;
                    nTodo -= nNow;
                    if (nTodo == 0 && !fMaster)
                        // We processed the last element; inform the master he can exit and return the result
                        //              Мы обработали последний элемент; сообщить мастеру, что он может выйти и вернуть результат
                        condMaster.notify_one();
                } else {
                    // first iteration                                              Первая итерация
                    nTotal++;
                }
                // logically, the do loop starts here                               Вполне логично, что цикл начинается здесь
                while (queue.empty()) {
                    if ((fMaster || fQuit) && nTodo == 0) {
                        nTotal--;
                        bool fRet = fAllOk;
                        // reset the status for new work later                      Сброс статуса для новой работы позднее
                        if (fMaster)
                            fAllOk = true;
                        // return the current status                                Вернуть текущее состояние
                        return fRet;
                    }
                    nIdle++;
                    cond.wait(lock); // wait                                        ждать
                    nIdle--;
                }
                // Decide how many work units to process now.
                // * Do not try to do everything at once, but aim for increasingly smaller batches so
                //   all workers finish approximately simultaneously.
                // * Try to account for idle jobs which will instantly start helping.
                // * Don't do batches smaller than 1 (duh), or larger than nBatchSize.
                //                      Решить, сколько рабочих юнитов для обработки теперь.
                //                      * Не пытайтесь сделать все сразу, но стремиться к более мелких партиям, так что бы
                //                        все работники закончить приблизительно одновременно
                //                      * Попробуйте учет для незанятых рабочих мест, которые станут мгновенно начинать помогать
                //                      * Не делайте части(партии) меньше, чем 1 (duh), или больше чем nBatchSize
                nNow = std::max(1U, std::min(nBatchSize, (unsigned int)queue.size() / (nTotal + nIdle + 1)));
                vChecks.resize(nNow);
                for (unsigned int i = 0; i < nNow; i++) {
                     // We want the lock on the mutex to be as short as possible, so swap jobs from the global
                     // queue to the local batch vector instead of copying.
                    //                  Мы хотим, чтобы замок на mutex был как можно короче, как замена работы из глобальной
                    //                  очереди в локальный вектор партии вместо копирования
                     vChecks[i].swap(queue.back());
                     queue.pop_back();
                }
                // Check whether we need to do work at all                          Проверьте, нужно ли нам работать на всех
                fOk = fAllOk;
            }
            // execute work                                                         выполнение работы
            BOOST_FOREACH(T &check, vChecks)
                if (fOk)
                    fOk = check();
            vChecks.clear();
        } while(true);
    }

public:
    // Create a new check queue                                                     создание навой очереди проверки
    CCheckQueue(unsigned int nBatchSizeIn) :
        nIdle(0), nTotal(0), fAllOk(true), nTodo(0), fQuit(false), nBatchSize(nBatchSizeIn) {}

    // Worker thread                                                                Рабочие потоки
    void Thread() {
        Loop();
    }

    // Wait until execution finishes, and return whether all evaluations where succesful.
    //                      Подождать пока выполнение закончится, и вернуть то, где все оценки успешны.
    bool Wait() {
        return Loop(true);
    }

    // Add a batch of checks to the queue                                           добавление пакетов проверки в очередь
    void Add(std::vector<T> &vChecks) {
        boost::unique_lock<boost::mutex> lock(mutex);
        BOOST_FOREACH(T &check, vChecks) {
            queue.push_back(T());
            check.swap(queue.back());
        }
        nTodo += vChecks.size();
        if (vChecks.size() == 1)
            condWorker.notify_one();
        else if (vChecks.size() > 1)
            condWorker.notify_all();
    }

    ~CCheckQueue() {
    }

    friend class CCheckQueueControl<T>;
};

/** RAII-style controller object for a CCheckQueue that guarantees the passed       RAII-style контроллер объекта для CCheckQueue гарантирующий
 *  queue is finished before continuing.                                            завершение передачи очереди прежде чем продолжить
 */
template<typename T> class CCheckQueueControl {
private:
    CCheckQueue<T> *pqueue;
    bool fDone;

public:
    CCheckQueueControl(CCheckQueue<T> *pqueueIn) : pqueue(pqueueIn), fDone(false) {
        // passed queue is supposed to be unused, or NULL                           переданная очередь должна быть неиспользованной, или NULL
        if (pqueue != NULL) {
            assert(pqueue->nTotal == pqueue->nIdle);
            assert(pqueue->nTodo == 0);
            assert(pqueue->fAllOk == true);
        }
    }

    bool Wait() {
        if (pqueue == NULL)
            return true;
        bool fRet = pqueue->Wait();
        fDone = true;
        return fRet;
    }

    void Add(std::vector<T> &vChecks) {
        if (pqueue != NULL)
            pqueue->Add(vChecks);
    }

    ~CCheckQueueControl() {
        if (!fDone)
            Wait();
    }
};

#endif
