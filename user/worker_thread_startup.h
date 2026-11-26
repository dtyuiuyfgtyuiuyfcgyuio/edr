#ifndef EDR_WORKER_THREAD_STARTUP_H
#define EDR_WORKER_THREAD_STARTUP_H

#include <cstddef>
#include <thread>
#include <vector>

namespace edr {

/* Starts a fixed worker set. On failure, rollback must stop, join, and clear
 * every worker already placed in the vector. The vector must be empty on entry. */
template <typename WorkerFactory, typename Rollback>
bool StartWorkerThreads(std::vector<std::thread>& workers, size_t count,
                        WorkerFactory&& factory, Rollback&& rollback) {
    if (!workers.empty()) return false;
    try {
        /* Reserve before constructing any threads so vector growth cannot
         * destroy a temporary joinable thread if allocation fails. */
        workers.reserve(count);
        for (size_t i = 0; i < count; ++i)
            workers.emplace_back(factory(i));
        return true;
    } catch (...) {
        rollback();
        return false;
    }
}

} // namespace edr

#endif // EDR_WORKER_THREAD_STARTUP_H
