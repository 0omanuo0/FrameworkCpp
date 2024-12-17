#pragma once

#include "uvw/src/uvw.hpp"
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <functional>
#include <memory>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace WorkerPool
{

    // Cola de tareas para los workers
    class TaskQueue
    {
    public:
        void push(std::function<void()> task)
        {
            std::unique_lock<std::mutex> lock(mutex);
            tasks.push(std::move(task));
            condition.notify_one();
        }

        std::function<void()> pop()
        {
            std::unique_lock<std::mutex> lock(mutex);
            condition.wait(lock, [&]
                           { return !tasks.empty(); });
            auto task = std::move(tasks.front());
            tasks.pop();
            return task;
        }

        // TaskQueue &operator=(const TaskQueue &other)
        // {
        //     if (this != &other)
        //     {
        //         this->tasks = other.tasks;
        //     }
        //     return *this;
        // }

    private:
        std::queue<std::function<void()>> tasks;
        std::mutex mutex;
        std::condition_variable condition;
    };

    // Pool de workers que ejecutan tareas
    class WorkerPool
    {
    public:
        WorkerPool(size_t numWorkers, TaskQueue &taskQueue)
            : queue(taskQueue), stop(false)
        {
            for (size_t i = 0; i < numWorkers; ++i)
            {
                workers.emplace_back([this]
                                     {
                while (true) {
                    auto task = queue.pop();
                    if (stop) break;
                    task(); // Ejecuta la tarea
                } });
            }
        }

        ~WorkerPool()
        {
            stop = true;
            for (auto &worker : workers)
            {
                if (worker.joinable())
                    worker.join();
            }
        }

        // create operator = for deep copy
        // WorkerPool &operator=(const WorkerPool &other)
        // {
        //     if (this != &other)
        //     {
        //         this->workers = other.workers;
        //         this->queue = other.queue;
        //         this->stop = other.stop;
        //     }
        //     return *this;
        // }

    private:
        std::vector<std::thread> workers;
        TaskQueue &queue;
        bool stop;
    };

}