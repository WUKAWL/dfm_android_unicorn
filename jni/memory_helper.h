/*
 * @Kernel_Hack - ACE Anti-Cheat Coordinate Decryption (ARM64 Android)
 * Copyright (C) 2026 @Kernel_Hack  https://github.com/libtersafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published
 * by the Free Software Foundation.
 *
 * Based on Unicorn Engine (GPLv2) - https://www.unicorn-engine.org/
 */
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <android/log.h>

#ifdef __aarch64__
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/ptrace.h>
#endif

// process_vm_readv may not be declared in older NDK headers (API < 23)
// Use syscall fallback
static inline ssize_t _pvm_readv(pid_t pid,
                                 const struct iovec* lvec, unsigned long liovcnt,
                                 const struct iovec* rvec, unsigned long riovcnt,
                                 unsigned long flags)
{
    return syscall(__NR_process_vm_readv, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

#define LOG_TAG "KernelHack"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ================================================================
//  ProcessMemory - Android process memory reader
//  Uses process_vm_readv (fast) with /proc/pid/mem fallback
// ================================================================
class ProcessMemory
{
public:
    ProcessMemory() : m_pid(0), m_memFd(-1) {}
    ~ProcessMemory() { detach(); }

    bool attach(pid_t pid)
    {
        detach();
        m_pid = pid;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/mem", pid);
        m_memFd = open(path, O_RDONLY);
        if (m_memFd < 0)
            LOGW("open(%s) failed, will use process_vm_readv only", path);

        return true;
    }

    void detach()
    {
        if (m_memFd >= 0) { ::close(m_memFd); m_memFd = -1; }
        m_pid = 0;
    }

    bool read(uintptr_t address, void* buffer, size_t size) const
    {
        if (m_pid <= 0 || !buffer || size == 0) return false;

        // 1) process_vm_readv  (single syscall, no seek)
        struct iovec local  = { buffer,          size };
        struct iovec remote = { (void*)address,  size };
        ssize_t n = _pvm_readv(m_pid, &local, 1, &remote, 1, 0);
        if (n == (ssize_t)size) return true;

        // 2) /proc/pid/mem fallback
        if (m_memFd >= 0) {
            n = pread64(m_memFd, buffer, size, (off64_t)address);
            if (n == (ssize_t)size) return true;
        }

        memset(buffer, 0, size);
        return false;
    }

    template <typename T>
    T read(uintptr_t address) const
    {
        T val{};
        read(address, &val, sizeof(T));
        return val;
    }

    pid_t pid() const { return m_pid; }

    // --------------------------------------------------------
    //  Find the main thread's TID (lowest /proc/pid/task/*)
    // --------------------------------------------------------
    static pid_t findMainTid(pid_t pid)
    {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/task", pid);
        DIR* dir = opendir(path);
        if (!dir) return pid;   // fallback: assume pid == main tid

        pid_t minTid = 0x7FFFFFFF;
        struct dirent* ent;
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_name[0] == '.') continue;
            pid_t tid = (pid_t)atoi(ent->d_name);
            if (tid > 0 && tid < minTid) minTid = tid;
        }
        closedir(dir);
        return (minTid != 0x7FFFFFFF) ? minTid : pid;
    }

    // --------------------------------------------------------
    //  按名称查找线程 TID (如 "GameThread")
    //  通过扫描 /proc/pid/task/*/comm 实现
    //  Find thread TID by name (e.g. "GameThread")
    //  Scans /proc/pid/task/*/comm
    // --------------------------------------------------------
    static pid_t findThreadByName(pid_t pid, const char* threadName)
    {
        char taskPath[64];
        snprintf(taskPath, sizeof(taskPath), "/proc/%d/task", (int)pid);
        DIR* dir = opendir(taskPath);
        if (!dir) return 0;

        struct dirent* ent;
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_name[0] == '.') continue;
            pid_t tid = (pid_t)atoi(ent->d_name);

            char commPath[128];
            snprintf(commPath, sizeof(commPath),
                     "/proc/%d/task/%d/comm", (int)pid, (int)tid);
            FILE* f = fopen(commPath, "r");
            if (!f) continue;

            char comm[64] = {};
            if (fgets(comm, sizeof(comm), f)) {
                // 去掉换行 / Remove trailing newline
                char* nl = strchr(comm, '\n');
                if (nl) *nl = '\0';

                if (strcmp(comm, threadName) == 0) {
                    fclose(f);
                    closedir(dir);
                    return tid;
                }
            }
            fclose(f);
        }
        closedir(dir);
        return 0;  // 未找到 / Not found
    }

    // --------------------------------------------------------
    //  通过 ptrace 获取线程的 TPIDR_EL0
    //  使用 PTRACE_GETREGSET + NT_ARM_TLS (0x401)
    //  注意: ptrace 会短暂暂停目标线程
    //
    //  Get thread TPIDR_EL0 via ptrace
    //  Uses PTRACE_GETREGSET + NT_ARM_TLS (0x401)
    //  Note: ptrace briefly suspends the target thread
    // --------------------------------------------------------
    static uint64_t getTpidrEL0(pid_t tid)
    {
#ifdef __aarch64__
        // Attach 到目标线程 / Attach to target thread
        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {
            LOGW("ptrace ATTACH tid=%d failed", (int)tid);
            return 0;
        }
        waitpid(tid, NULL, 0);

        // 读取 TPIDR_EL0 / Read TPIDR_EL0
        // NT_ARM_TLS = 0x401
        uint64_t tpidr = 0;
        struct iovec iov;
        iov.iov_base = &tpidr;
        iov.iov_len  = sizeof(tpidr);

        long ret = ptrace(PTRACE_GETREGSET, tid, (void*)0x401, &iov);
        if (ret < 0) {
            LOGW("ptrace GETREGSET NT_ARM_TLS tid=%d failed", (int)tid);
        }

        // Detach / 分离
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
        return tpidr;
#else
        (void)tid;
        LOGW("getTpidrEL0: not supported on non-aarch64");
        return 0;
#endif
    }

private:
    pid_t m_pid;
    int   m_memFd;
};

// ================================================================
//  Callback type for pluggable memory reader
// ================================================================
typedef bool (*ReadMemoryFunc)(uintptr_t address, void* buffer, size_t size);
