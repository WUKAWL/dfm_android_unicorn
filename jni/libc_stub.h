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
#include <string>
#include <vector>
#include <unordered_map>
#include <elf.h>

#include <unicorn/unicorn.h>

// ================================================================
//  ModuleInfo — parsed from /proc/<pid>/maps
// ================================================================
struct ModuleInfo {
    uintptr_t   base;
    uintptr_t   end;
    std::string path;

    uintptr_t size() const { return end - base; }
};

// ================================================================
//  Parse /proc/<pid>/maps to find loaded modules
// ================================================================
static std::vector<ModuleInfo> ParseMaps(pid_t pid)
{
    std::vector<ModuleInfo> modules;
    char mapPath[64];
    snprintf(mapPath, sizeof(mapPath), "/proc/%d/maps", (int)pid);

    FILE* f = fopen(mapPath, "r");
    if (!f) return modules;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8] = {};
        unsigned long offset;
        int dev_major, dev_minor;
        unsigned long inode;
        char pathname[256] = {};

        int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255s",
                       &start, &end, perms, &offset,
                       &dev_major, &dev_minor, &inode, pathname);
        if (n < 7) continue;
        if (pathname[0] == '\0') continue;

        // Only first mapping of each module (offset == 0)
        if (offset != 0) continue;

        // Skip non-file mappings
        if (pathname[0] != '/') continue;

        ModuleInfo m;
        m.base = start;
        m.end  = end;
        m.path = pathname;
        modules.push_back(m);
    }
    fclose(f);

    // Update end address by scanning all maps for same path
    f = fopen(mapPath, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            uintptr_t start, end;
            char perms[8] = {};
            unsigned long offset;
            int dev_major, dev_minor;
            unsigned long inode;
            char pathname[256] = {};

            sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255s",
                   &start, &end, perms, &offset,
                   &dev_major, &dev_minor, &inode, pathname);

            for (auto& m : modules) {
                if (m.path == pathname && end > m.end)
                    m.end = end;
            }
        }
        fclose(f);
    }

    return modules;
}

// Find a module by name (partial match)
static ModuleInfo FindModule(pid_t pid, const char* name)
{
    auto modules = ParseMaps(pid);
    for (auto& m : modules) {
        if (m.path.find(name) != std::string::npos)
            return m;
    }
    return {0, 0, ""};
}

// ================================================================
//  ELF symbol resolver — reads .dynsym from process memory
//  to find exported function addresses
// ================================================================
typedef bool (*ElfReadFunc)(uintptr_t addr, void* buf, size_t len);

struct ElfSymbol {
    std::string name;
    uintptr_t   addr;   // absolute address in process
};

static std::vector<ElfSymbol> ResolveElfSymbols(
    uintptr_t moduleBase,
    ElfReadFunc readMem,
    const std::vector<std::string>& targetNames)
{
    std::vector<ElfSymbol> result;

    // Read ELF header
    Elf64_Ehdr ehdr;
    if (!readMem(moduleBase, &ehdr, sizeof(ehdr))) return result;

    // Verify ELF magic
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return result;

    // Read program headers to find PT_DYNAMIC
    uintptr_t phdrAddr = moduleBase + ehdr.e_phoff;
    uintptr_t dynAddr = 0;
    uint64_t  dynSize = 0;

    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (!readMem(phdrAddr + i * sizeof(Elf64_Phdr), &phdr, sizeof(phdr)))
            continue;

        if (phdr.p_type == PT_DYNAMIC) {
            dynAddr = moduleBase + phdr.p_offset;
            dynSize = phdr.p_filesz;
            break;
        }
    }
    if (dynAddr == 0) return result;

    // Parse dynamic section to find .dynsym, .dynstr, hash tables
    uintptr_t symtab = 0, strtab = 0;
    uint64_t  strsz = 0;
    uintptr_t hashAddr = 0;
    uintptr_t gnuHashAddr = 0;
    uint64_t  nSyms = 0;

    for (uint64_t off = 0; off < dynSize; off += sizeof(Elf64_Dyn)) {
        Elf64_Dyn dyn;
        if (!readMem(dynAddr + off, &dyn, sizeof(dyn))) break;

        switch (dyn.d_tag) {
            case DT_SYMTAB:  symtab      = dyn.d_un.d_ptr; break;
            case DT_STRTAB:  strtab      = dyn.d_un.d_ptr; break;
            case DT_STRSZ:   strsz       = dyn.d_un.d_val; break;
            case DT_HASH:    hashAddr    = dyn.d_un.d_ptr; break;
            case DT_GNU_HASH: gnuHashAddr = dyn.d_un.d_ptr; break;
            case DT_NULL:    goto done_dyn;
        }
    }
done_dyn:

    if (symtab == 0 || strtab == 0) return result;

    // Fix addresses if they're relative (not pre-relocated)
    if (symtab < moduleBase) symtab += moduleBase;
    if (strtab < moduleBase) strtab += moduleBase;
    if (hashAddr && hashAddr < moduleBase) hashAddr += moduleBase;

    // Get number of symbols from DT_HASH
    if (hashAddr != 0) {
        uint32_t hashHdr[2]; // nbucket, nchain
        if (readMem(hashAddr, hashHdr, sizeof(hashHdr)))
            nSyms = hashHdr[1]; // nchain = number of symbols
    }

    // Fallback: estimate from strtab - symtab gap
    if (nSyms == 0 && strtab > symtab) {
        nSyms = (strtab - symtab) / sizeof(Elf64_Sym);
    }
    if (nSyms == 0) nSyms = 4096; // reasonable upper bound

    // Build a set for fast lookup
    std::unordered_map<std::string, bool> targets;
    for (auto& n : targetNames) targets[n] = true;

    // Iterate symbols
    for (uint64_t i = 0; i < nSyms && result.size() < targetNames.size(); i++) {
        Elf64_Sym sym;
        if (!readMem(symtab + i * sizeof(Elf64_Sym), &sym, sizeof(sym)))
            break;

        if (sym.st_name == 0 || sym.st_value == 0) continue;
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;

        // Read symbol name
        char nameBuf[128] = {};
        if (!readMem(strtab + sym.st_name, nameBuf, sizeof(nameBuf) - 1))
            continue;
        nameBuf[sizeof(nameBuf) - 1] = '\0';

        std::string sname(nameBuf);
        if (targets.count(sname)) {
            ElfSymbol es;
            es.name = sname;
            es.addr = moduleBase + sym.st_value;
            result.push_back(es);
        }
    }

    return result;
}

// ================================================================
//  LibcStubber — installs function stubs in Unicorn
// ================================================================
class LibcStubber {
public:
    // ARM64 stub instruction sequences
    // MOV X0, #0; RET → function returns 0
    static constexpr uint32_t STUB_RET0[] = {
        0xD2800000,  // MOV X0, #0
        0xD65F03C0,  // RET
    };

    // MOV X0, #1; RET → function returns 1
    static constexpr uint32_t STUB_RET1[] = {
        0xD2800020,  // MOV X0, #1
        0xD65F03C0,  // RET
    };

    // MOV X0, #-1; RET → function returns -1 (error)
    static constexpr uint32_t STUB_RET_NEG1[] = {
        0x92800000,  // MOV X0, #-1
        0xD65F03C0,  // RET
    };

    // MOV X0, #0x1000; RET → sysconf(_SC_PAGESIZE) = 4096
    static constexpr uint32_t STUB_RET_PAGESIZE[] = {
        0xD2820000,  // MOV X0, #0x1000
        0xD65F03C0,  // RET
    };

    // Just RET (preserve X0)
    static constexpr uint32_t STUB_RET[] = {
        0xD65F03C0,  // RET
    };

    enum StubType {
        STUB_TYPE_RET0,         // return 0 (success / NULL)
        STUB_TYPE_RET1,         // return 1
        STUB_TYPE_RET_NEG1,     // return -1 (error)
        STUB_TYPE_RET_PAGESIZE, // return 0x1000 (sysconf)
        STUB_TYPE_NOP_RET,      // just RET
    };

    struct StubInfo {
        std::string funcName;
        uintptr_t   addr;
        StubType    type;
        bool        applied;
    };

    // Find libc and install stubs for all functions the ACE shellcode calls
    bool Init(pid_t pid, uc_engine* uc, ElfReadFunc readMem)
    {
        m_uc = uc;
        m_pid = pid;

        // Find libc.so
        m_libc = FindModule(pid, "libc.so");
        if (m_libc.base == 0) {
            m_libc = FindModule(pid, "/libc-");
            if (m_libc.base == 0)
                m_libc = FindModule(pid, "libc-2.");
        }
        if (m_libc.base == 0) return false;

        // ---- Stub definitions ----
        // {function_name, stub_type}
        struct StubDef {
            const char* name;
            StubType    type;
        };

        StubDef stubDefs[] = {
            // Sync primitives — must NOP to avoid deadlock
            {"pthread_mutex_lock",       STUB_TYPE_RET0},
            {"pthread_mutex_unlock",     STUB_TYPE_RET0},
            {"pthread_mutex_trylock",    STUB_TYPE_RET0},
            {"pthread_mutex_init",       STUB_TYPE_RET0},
            {"pthread_mutex_destroy",    STUB_TYPE_RET0},
            {"pthread_once",             STUB_TYPE_RET0},
            {"pthread_rwlock_rdlock",    STUB_TYPE_RET0},
            {"pthread_rwlock_wrlock",    STUB_TYPE_RET0},
            {"pthread_rwlock_unlock",    STUB_TYPE_RET0},
            {"pthread_cond_wait",        STUB_TYPE_RET0},
            {"pthread_cond_signal",      STUB_TYPE_RET0},
            {"pthread_cond_broadcast",   STUB_TYPE_RET0},
            {"__cxa_guard_acquire",      STUB_TYPE_RET0},
            {"__cxa_guard_release",      STUB_TYPE_RET0},

            // TLS — shellcode uses pthread_key for its own TLS
            {"pthread_key_create",       STUB_TYPE_RET0},
            {"pthread_key_delete",       STUB_TYPE_RET0},
            {"pthread_getspecific",      STUB_TYPE_RET0},  // returns NULL
            {"pthread_setspecific",      STUB_TYPE_RET0},

            // File I/O — shellcode reads /proc/self/maps, ACE cache
            // Return NULL/0 so shellcode skips file-based checks
            {"fopen",                    STUB_TYPE_RET0},  // returns NULL
            {"fclose",                   STUB_TYPE_RET0},
            {"fgets",                    STUB_TYPE_RET0},  // returns NULL
            {"remove",                   STUB_TYPE_RET0},

            // System — sysconf(_SC_PAGESIZE) must return 4096
            {"sysconf",                  STUB_TYPE_RET_PAGESIZE},
            {"syscall",                  STUB_TYPE_RET0},
            {"getpid",                   STUB_TYPE_RET1},   // fake PID
            {"gettid",                   STUB_TYPE_RET1},   // fake TID
            {"usleep",                   STUB_TYPE_RET0},   // skip sleep

            // Memory management — return success
            {"munmap",                   STUB_TYPE_RET0},
            {"mprotect",                 STUB_TYPE_RET0},
            {"mincore",                  STUB_TYPE_RET_NEG1}, // fail = skip check

            // Device — /dev/kgsl-3d0 GPU anti-debug
            {"ioctl",                    STUB_TYPE_RET0},

            // Environment
            {"unsetenv",                 STUB_TYPE_RET0},

            // String — wmemset (wide memset, not commonly needed)
            {"wmemset",                  STUB_TYPE_NOP_RET}, // preserve X0 (return dest)
        };

        std::vector<std::string> names;
        std::unordered_map<std::string, StubType> typeMap;
        for (auto& d : stubDefs) {
            names.push_back(d.name);
            typeMap[d.name] = d.type;
        }

        auto syms = ResolveElfSymbols(m_libc.base, readMem, names);

        for (auto& sym : syms) {
            StubInfo si;
            si.funcName = sym.name;
            si.addr     = sym.addr;
            si.type     = typeMap.count(sym.name) ? typeMap[sym.name] : STUB_TYPE_RET0;
            si.applied  = false;
            m_stubs.push_back(si);
        }

        return true;
    }

    // Get stub bytes for a given type
    static const uint32_t* GetStubCode(StubType t, size_t& outSize)
    {
        switch (t) {
            case STUB_TYPE_RET0:         outSize = sizeof(STUB_RET0);         return STUB_RET0;
            case STUB_TYPE_RET1:         outSize = sizeof(STUB_RET1);         return STUB_RET1;
            case STUB_TYPE_RET_NEG1:     outSize = sizeof(STUB_RET_NEG1);     return STUB_RET_NEG1;
            case STUB_TYPE_RET_PAGESIZE: outSize = sizeof(STUB_RET_PAGESIZE); return STUB_RET_PAGESIZE;
            case STUB_TYPE_NOP_RET:      outSize = sizeof(STUB_RET);          return STUB_RET;
            default:                     outSize = sizeof(STUB_RET0);         return STUB_RET0;
        }
    }

    // Apply stubs — call this AFTER lazy page mapping has loaded the pages
    void PreApplyStubs()
    {
        for (auto& s : m_stubs) {
            if (s.applied) continue;

            uint64_t page = s.addr & ~0xFFFULL;
            uc_mem_map(m_uc, page, 0x1000, UC_PROT_ALL);

            size_t codeSize;
            const uint32_t* code = GetStubCode(s.type, codeSize);
            uc_err err = uc_mem_write(m_uc, s.addr, code, codeSize);
            if (err == UC_ERR_OK) {
                s.applied = true;
            }
        }
    }

    // Called from OnUnmapped hook after a page is mapped
    // Re-applies stubs if the mapped page overlaps a stub address
    void OnPageMapped(uint64_t pageAddr, uint64_t pageSize)
    {
        for (auto& s : m_stubs) {
            uint64_t funcPage = s.addr & ~(pageSize - 1);
            if (funcPage == pageAddr) {
                size_t codeSize;
                const uint32_t* code = GetStubCode(s.type, codeSize);
                uc_mem_write(m_uc, s.addr, code, codeSize);
                s.applied = true;
            }
        }
    }

    // Check if an address is within libc range
    bool IsInLibc(uint64_t addr) const
    {
        return addr >= m_libc.base && addr < m_libc.end;
    }

    uintptr_t GetLibcBase() const { return m_libc.base; }
    uintptr_t GetLibcEnd()  const { return m_libc.end; }

    const std::vector<StubInfo>& GetStubs() const { return m_stubs; }

    // Resolve a single function address (for debugging/tracing)
    uintptr_t FindFunc(const char* name, ElfReadFunc readMem) const
    {
        std::vector<std::string> names = { name };
        auto syms = ResolveElfSymbols(m_libc.base, readMem, names);
        if (!syms.empty()) return syms[0].addr;
        return 0;
    }

private:
    uc_engine*             m_uc   = nullptr;
    pid_t                  m_pid  = 0;
    ModuleInfo             m_libc = {};
    std::vector<StubInfo>  m_stubs;
};
