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
#include "sjz_dec_arm64.h"
#include "memory_helper.h"
#include "libc_stub.h"

#include <unicorn/unicorn.h>

#include <elf.h>

#include <unordered_map>
#include <vector>
#include <cstring>
#include <cstdarg>
#include <algorithm>

// ================================================================
//  常量 / Constants
// ================================================================
static constexpr uint64_t EMU_PAGE_SIZE   = 0x1000;
static constexpr uint64_t STACK_SIZE      = 0x40000;       // 256 KB
static constexpr uint64_t STACK_BASE      = 0x7000000000ULL;
static constexpr uint64_t RET_STUB_ADDR   = 0x7100000000ULL;
static constexpr uint64_t CIPHER_ADDR     = 0x7200000000ULL;
static constexpr uint64_t TLS_EMU_ADDR    = 0x7300000000ULL;
static constexpr uint64_t EMU_TIMEOUT     = 500000;        // 500ms (like PoP)
static constexpr size_t   PAGE_CACHE_MAX  = 256;

// ================================================================
//  页面缓存条目 / Page cache entry
// ================================================================
struct CachePage {
    uint8_t  data[EMU_PAGE_SIZE];
    uint64_t tick;
};

// ================================================================
//  Shellcode ELF 符号解析结果 (like PoP)
//  从 shellcode 的 ELF 符号表动态解析函数边界
// ================================================================
struct ShellcodeSyms {
    uint64_t entry              = 0;   // "entry"
    uint64_t hashEnd            = 0;   // "hash_end"           → until 地址
    uint64_t hashDirectStart    = 0;   // "hash_direct_start"  → begin 地址
    uint64_t hashDirectInitStart= 0;   // "hash_direct_init_start"
    uint64_t hashDirectInitEnd  = 0;   // "hash_direct_init_end"
    uint64_t ringCalcStart      = 0;   // "ring_calc_start"
    uint64_t allParamsExecEnd   = 0;   // "all_params_exec_end"
    uint64_t v87End             = 0;   // "v87_end"
    bool     resolved           = false;
};

// ================================================================
//  模拟器上下文 (单例) / Emulator context (singleton)
// ================================================================
struct EmuCtx {
    uc_engine*       uc          = nullptr;
    ProcessMemory    mem;
    GameOffsets      off         = {};
    ReadMemoryFunc   customRead  = nullptr;
    BrkResolveFunc   brkResolver = nullptr;

    // page cache
    std::unordered_map<uint64_t, CachePage> cache;
    uint64_t tick = 0;

    // state
    bool     inited     = false;

    // TPIDR_EL0 value for MRS interception
    uint64_t tpidrEL0   = 0;

    // libc stub system
    LibcStubber      libcStub;
    uintptr_t        libcBase = 0;
    uintptr_t        libcEnd  = 0;

    // Shellcode mapping
    bool     shellcodeMapped = false;

    // Shellcode 符号解析结果
    ShellcodeSyms    syms;

    // Trace 模式 / Trace mode
    bool     traceEnabled = false;
    int      traceCount   = 0;
};

static EmuCtx g;

static bool MapShellcode();
static bool ResolveShellcodeSymbols();

// ================================================================
//  内存读取封装 / Memory read wrappers
// ================================================================
static bool RdMem(uintptr_t addr, void* buf, size_t len)
{
    if (g.customRead) return g.customRead(addr, buf, len);
    return g.mem.read(addr, buf, len);
}

template <typename T>
static T RdVal(uintptr_t addr)
{
    T v{};
    RdMem(addr, &v, sizeof(T));
    return v;
}

// 模块偏移转绝对地址 / Absolute address from module-relative offset
static inline uintptr_t GA(uintptr_t off) { return g.off.moduleBase + off; }

// ================================================================
//  页面缓存辅助 / Page cache helpers
// ================================================================
static bool ReadPageCached(uint64_t pageAddr, void* outBuf)
{
    auto it = g.cache.find(pageAddr);
    if (it != g.cache.end()) {
        memcpy(outBuf, it->second.data, EMU_PAGE_SIZE);
        it->second.tick = ++g.tick;
        return true;
    }

    CachePage cp;
    bool ok = RdMem(pageAddr, cp.data, EMU_PAGE_SIZE);
    if (!ok) memset(cp.data, 0, EMU_PAGE_SIZE);
    memcpy(outBuf, cp.data, EMU_PAGE_SIZE);

    // LRU eviction
    if (g.cache.size() >= PAGE_CACHE_MAX) {
        uint64_t minTick = UINT64_MAX;
        uint64_t minAddr = 0;
        for (auto& [a, e] : g.cache) {
            if (e.tick < minTick) { minTick = e.tick; minAddr = a; }
        }
        g.cache.erase(minAddr);
    }
    cp.tick = ++g.tick;
    g.cache[pageAddr] = cp;
    return ok;
}

// 清空缓存并卸载所有延迟映射的页面
// Clear cache AND unmap all lazily-mapped pages from Unicorn
// 这很重要: 否则不同 RootComponent 的数据会互相污染
void InvalidatePageCache()
{
    if (!g.uc) { g.cache.clear(); return; }

    // shellcode 预映射页面不在 cache 里，但仍需安全跳过
    uint64_t scBase = g.off.shellcodeBase & ~(EMU_PAGE_SIZE - 1);
    uint64_t scEnd  = (g.off.shellcodeBase + g.off.shellcodeSize +
                       EMU_PAGE_SIZE - 1) & ~(EMU_PAGE_SIZE - 1);

    for (auto it = g.cache.begin(); it != g.cache.end(); ) {
        uint64_t addr = it->first;
        if (g.shellcodeMapped && addr >= scBase && addr < scEnd) {
            ++it;
            continue;
        }
        uc_mem_unmap(g.uc, addr, EMU_PAGE_SIZE);
        it = g.cache.erase(it);
    }
}

// 只失效指定地址范围覆盖的数据页，shellcode 页保持常驻
void InvalidateDataPages(uint64_t addr, size_t size)
{
    if (!g.uc || size == 0) return;

    uint64_t scBase = g.off.shellcodeBase & ~(EMU_PAGE_SIZE - 1);
    uint64_t scEnd  = (g.off.shellcodeBase + g.off.shellcodeSize +
                       EMU_PAGE_SIZE - 1) & ~(EMU_PAGE_SIZE - 1);

    uint64_t pageStart = addr & ~(EMU_PAGE_SIZE - 1);
    uint64_t pageEnd   = (addr + size + EMU_PAGE_SIZE - 1) & ~(EMU_PAGE_SIZE - 1);

    for (uint64_t p = pageStart; p < pageEnd; p += EMU_PAGE_SIZE) {
        if (g.shellcodeMapped && p >= scBase && p < scEnd) continue;
        auto it = g.cache.find(p);
        if (it != g.cache.end()) {
            uc_mem_unmap(g.uc, p, EMU_PAGE_SIZE);
            g.cache.erase(it);
        }
    }
}

// ================================================================
//  MTE 标签去除 — Android 12+ 指针高字节含 MTE tag (如 0xB4)
//  Strip MTE tag from top byte for real memory access
// ================================================================
static inline uint64_t StripMteTag(uint64_t addr)
{
    return addr & 0x00FFFFFFFFFFFFFFULL;
}

// ================================================================
//  Unicorn 钩子 — 延迟页面映射 (MTE 感知)
//  Unicorn hook — lazy page mapping (MTE-aware)
//  当 Unicorn 访问未映射地址时:
//  1. 去掉 MTE tag 得到真实地址, 从游戏进程读取页面数据
//  2. 在 Unicorn 中映射到原始(带tag)地址, 保证 BR X16 等跳转正常
// ================================================================
static bool OnUnmapped(uc_engine* uc, uc_mem_type type,
                        uint64_t addr, int size,
                        int64_t /*value*/, void* /*user*/)
{
    uint64_t page     = addr & ~(EMU_PAGE_SIZE - 1);
    uint64_t realPage = StripMteTag(page);

    if (g.traceEnabled) {
        const char* typeStr = (type == UC_MEM_FETCH_UNMAPPED) ? "FETCH" :
                              (type == UC_MEM_READ_UNMAPPED)  ? "READ"  : "WRITE";
        printf("  [PAGE] %s 0x%lx -> real 0x%lx\n",
               typeStr, (unsigned long)page, (unsigned long)realPage);
    }

    uint8_t buf[EMU_PAGE_SIZE];
    ReadPageCached(realPage, buf);
    uc_mem_map(uc, page, EMU_PAGE_SIZE, UC_PROT_ALL);
    uc_mem_write(uc, page, buf, EMU_PAGE_SIZE);

    // 检查是否命中 libc stub
    bool stubHit = false;
    for (auto& s : g.libcStub.GetStubs()) {
        uint64_t funcPage = s.addr & ~(EMU_PAGE_SIZE - 1);
        if (funcPage == page) {
            if (g.traceEnabled)
                printf("  [STUB] %s @ 0x%lx\n", s.funcName.c_str(), (unsigned long)s.addr);
            stubHit = true;
        }
    }
    g.libcStub.OnPageMapped(page, EMU_PAGE_SIZE);

    return true;
}

// ================================================================
//  ARM64 指令解码辅助 / ARM64 instruction decode helpers
// ================================================================

// BRK #imm16 编码: 0xD4200000 | (imm16 << 5)
// ARM64 间接跳转: BR Xn, 间接调用: BLR Xn
// BRK #imm16 encoding: 0xD4200000 | (imm16 << 5)
static inline bool IsBrkInsn(uint32_t insn)         { return (insn & 0xFFE0001F) == 0xD4200000; }
static inline uint16_t BrkImm(uint32_t insn)        { return (uint16_t)((insn >> 5) & 0xFFFF); }

// MRS Xt, TPIDR_EL0  encoding: 0xD53BD040 | Rt
static inline bool IsMrsTpidr(uint32_t insn)        { return (insn & 0xFFFFFFE0) == 0xD53BD040; }
static inline uint32_t MrsRt(uint32_t insn)         { return insn & 0x1F; }

// ================================================================
//  中断钩子 — 处理 BRK 间接跳转
//  Interrupt hook — handles BRK indirect jumps
// ================================================================
static void OnInterrupt(uc_engine* uc, uint32_t intno, void* user)
{
    uint64_t pc = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

    if (pc == RET_STUB_ADDR || pc == RET_STUB_ADDR + 4) {
        uc_emu_stop(uc);
        return;
    }

    uint32_t insn = 0;
    uc_mem_read(uc, pc, &insn, 4);

    if (IsBrkInsn(insn) && g.brkResolver) {
        uint16_t imm = BrkImm(insn);
        uint64_t target = g.brkResolver(imm, pc);
        if (target != 0) {
            uc_reg_write(uc, UC_ARM64_REG_PC, &target);
            return;
        }
    }

    uc_emu_stop(uc);
}

// ================================================================
//  代码钩子 — 拦截 MRS TPIDR_EL0 指令
//  Code hook — intercepts MRS TPIDR_EL0 instructions
// ================================================================
static void OnCode(uc_engine* uc, uint64_t address, uint32_t size, void* user)
{
    if (g.traceEnabled && g.traceCount < 200) {
        g.traceCount++;
        uint32_t insn = 0;
        uc_mem_read(uc, address, &insn, 4);
        uint64_t x0 = 0;
        uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
        printf("  [%04d] PC=0x%lx insn=0x%08X X0=0x%lx\n",
               g.traceCount, (unsigned long)address, insn, (unsigned long)x0);
    }

    if (size != 4) return;

    uint32_t insn = 0;
    uc_mem_read(uc, address, &insn, 4);

    if (IsMrsTpidr(insn)) {
        uint32_t rt = MrsRt(insn);
        int reg_id = UC_ARM64_REG_X0 + (int)rt;
        uc_reg_write(uc, reg_id, &g.tpidrEL0);

        uint64_t next_pc = address + 4;
        uc_reg_write(uc, UC_ARM64_REG_PC, &next_pc);
    }
}

// ================================================================
//  返回桩 (ARM64: NOP + BRK #0) / Return stub
// ================================================================
static void InstallRetStub(uc_engine* uc)
{
    uc_mem_map(uc, RET_STUB_ADDR, EMU_PAGE_SIZE,
               UC_PROT_READ | UC_PROT_EXEC);
    uint32_t stub[] = {
        0xD503201F,   // NOP
        0xD4200000,   // BRK #0
    };
    uc_mem_write(uc, RET_STUB_ADDR, stub, sizeof(stub));
}

// ================================================================
//  初始化 / 清理 / Init / Cleanup
// ================================================================
bool InitEmulatorARM64(int pid, const GameOffsets& offsets)
{
    if (g.inited) CleanupEmulator();

    g.off = offsets;

    if (!g.mem.attach((pid_t)pid)) {
        LOGE("attach pid %d failed", pid);
        return false;
    }

    uc_err e = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &g.uc);
    if (e != UC_ERR_OK) {
        LOGE("uc_open: %s", uc_strerror(e));
        return false;
    }

    // CPU model → Unicorn 自动启用 NEON/FP (like PoP: uc_ctl(uc, 0x44000007, 3))
#if defined(UC_CTL_CPU_MODEL)
    uc_ctl_set_cpu_model(g.uc, UC_CPU_ARM64_MAX);
#else
    // fallback: 手动启用 NEON/FP (CPACR_EL1.FPEN = 0b11)
    uint64_t cpacr = 3ULL << 20;
    uc_reg_write(g.uc, UC_ARM64_REG_CPACR_EL1, &cpacr);
#endif

    // 栈 / Stack
    uc_mem_map(g.uc, STACK_BASE, STACK_SIZE,
               UC_PROT_READ | UC_PROT_WRITE);

    // 未映射内存钩子 / Unmapped-memory hooks
    uc_hook hMem;
    uc_hook_add(g.uc, &hMem,
                UC_HOOK_MEM_READ_UNMAPPED  |
                UC_HOOK_MEM_WRITE_UNMAPPED |
                UC_HOOK_MEM_FETCH_UNMAPPED,
                (void*)OnUnmapped, nullptr, 1, 0);

    // 中断钩子 — 捕获 BRK 用于间接跳转解析
    // Interrupt hook — catches BRK for indirect jump resolution
    uc_hook hIntr;
    uc_hook_add(g.uc, &hIntr, UC_HOOK_INTR,
                (void*)OnInterrupt, nullptr, 1, 0);

    // 代码钩子 — 拦截 MRS TPIDR_EL0
    // 仅在性能可接受时启用；不调用 SetTpidrEL0() 即可禁用
    // Code hook — intercepts MRS TPIDR_EL0
    uc_hook hCode;
    uc_hook_add(g.uc, &hCode, UC_HOOK_CODE,
                (void*)OnCode, nullptr, 1, 0);

    // TLS 区域 (TPIDR_EL0) / TLS area
    uc_mem_map(g.uc, TLS_EMU_ADDR, EMU_PAGE_SIZE,
               UC_PROT_READ | UC_PROT_WRITE);
    uint64_t tls = TLS_EMU_ADDR;
    uc_reg_write(g.uc, UC_ARM64_REG_TPIDR_EL0, &tls);

    // TLS 由 shellcode 的 pthread_key_* 处理 (已在 libc_stub.h 中 stub)
    // 用户调用 SetTpidrEL0() 会更新模拟 TLS 区域
    // TLS handled by shellcode's pthread_key_* (stubbed in libc_stub.h)

    // 密文缓冲区 / Cipher buffer
    uc_mem_map(g.uc, CIPHER_ADDR, EMU_PAGE_SIZE,
               UC_PROT_READ | UC_PROT_WRITE);

    InstallRetStub(g.uc);

    // 初始化 libc stub 系统
    // 封装 RdMem 用于 ELF 符号解析
    // Initialize libc stub system
    auto elfRead = [](uintptr_t a, void* b, size_t l) -> bool {
        return RdMem(a, b, l);
    };
    if (g.libcStub.Init((pid_t)pid, g.uc, elfRead)) {
        g.libcBase = g.libcStub.GetLibcBase();
        g.libcEnd  = g.libcStub.GetLibcEnd();
        g.libcStub.PreApplyStubs();
        LOGI("libc stub: base=0x%lx end=0x%lx stubs=%zu",
             (unsigned long)g.libcBase,
             (unsigned long)g.libcEnd,
             g.libcStub.GetStubs().size());
    } else {
        LOGW("libc stub init failed — sync functions may hang");
    }

    g.inited = true;

    // pre-map shellcode + resolve ELF symbols (like PoP: init 时一次性完成)
    MapShellcode();
    if (ResolveShellcodeSymbols()) {
        LOGI("shellcode symbols resolved: direct=0x%lx end=0x%lx",
             (unsigned long)g.syms.hashDirectStart,
             (unsigned long)g.syms.hashEnd);
    }

    LOGI("ARM64 emulator OK  pid=%d  base=0x%lx",
         pid, (unsigned long)offsets.moduleBase);
    return true;
}

void CleanupEmulator()
{
    if (g.uc) { uc_close(g.uc); g.uc = nullptr; }
    g.mem.detach();
    g.cache.clear();
    g.inited = false;
}

void SetMemoryReadFunc(ReadMemoryFunc fn) { g.customRead = fn; }
uc_engine* GetEmulatorUc() { return g.uc; }
void SetBrkResolver(BrkResolveFunc fn)     { g.brkResolver = fn; }
void EnableTrace(bool on) { g.traceEnabled = on; g.traceCount = 0; }

void SetTpidrEL0(uint64_t value)
{
    g.tpidrEL0 = value;
    if (g.uc) {
        uc_reg_write(g.uc, UC_ARM64_REG_TPIDR_EL0, &value);
        uc_mem_write(g.uc, TLS_EMU_ADDR, &value, sizeof(value));
    }
}

// ================================================================
//  每次模拟调用前重置寄存器
//  优化: 只清除栈帧区域, 不清除整个 256 KB
//  Reset registers before each emulated call
// ================================================================
static void ResetForCall()
{
    uint64_t zero = 0;
    for (int r = UC_ARM64_REG_X0; r <= UC_ARM64_REG_X28; r++)
        uc_reg_write(g.uc, r, &zero);
    uc_reg_write(g.uc, UC_ARM64_REG_FP, &zero);   // X29
    uc_reg_write(g.uc, UC_ARM64_REG_LR, &zero);   // X30

    // SP 在 AArch64 上必须 16 字节对齐 / SP must be 16-byte aligned on AArch64
    uint64_t sp = (STACK_BASE + STACK_SIZE - 0x100) & ~0xFULL;
    uc_reg_write(g.uc, UC_ARM64_REG_SP, &sp);

    // 仅清除栈顶 2 KB (优化) / Clear only top 2 KB of stack (optimisation)
    uint8_t zeroBlk[0x800] = {};
    uc_mem_write(g.uc, sp - 0x600, zeroBlk, sizeof(zeroBlk));
}

// ================================================================
//  模拟调用 — ARM64 调用约定
//  X0 = 密文缓冲区地址 (模拟器空间)
//  X1 = 大小, X2 = 密钥, X3 = v4
//  LR = RET_STUB_ADDR (函数 RET 跳转到此处 → 模拟停止)
//  EmulateCall — ARM64 calling convention
// ================================================================
static uint64_t EmulateCall(uint64_t funcAddr,
                            void* localCipherPtr,
                            uint32_t size,
                            uint32_t key,
                            uint64_t v4)
{
    ResetForCall();

    // 写入 16 字节密文数据到模拟器内存 / Write 16 bytes cipher data into emu memory
    uc_mem_write(g.uc, CIPHER_ADDR, localCipherPtr, 0x10);

    // 设置 ARM64 参数 / Set ARM64 parameters
    uint64_t x0 = CIPHER_ADDR;
    uint64_t x1 = (uint64_t)size;
    uint64_t x2 = (uint64_t)key;
    uint64_t x3 = v4;
    uc_reg_write(g.uc, UC_ARM64_REG_X0, &x0);
    uc_reg_write(g.uc, UC_ARM64_REG_X1, &x1);
    uc_reg_write(g.uc, UC_ARM64_REG_X2, &x2);
    uc_reg_write(g.uc, UC_ARM64_REG_X3, &x3);

    // 设置链接寄存器 → 返回桩 / Set link register → return stub
    uint64_t lr = RET_STUB_ADDR;
    uc_reg_write(g.uc, UC_ARM64_REG_LR, &lr);

    uc_err err = uc_emu_start(g.uc, funcAddr, RET_STUB_ADDR,
                              EMU_TIMEOUT, 0);
    if (err != UC_ERR_OK && err != UC_ERR_FETCH_UNMAPPED) {
        LOGE("emu 0x%lx: %s", (unsigned long)funcAddr, uc_strerror(err));
    }

    // 读取返回值 (X0) / Read return value (X0)
    uint64_t ret = 0;
    uc_reg_read(g.uc, UC_ARM64_REG_X0, &ret);

    // 读回解密后的密文数据 / Read back decrypted cipher data
    uc_mem_read(g.uc, CIPHER_ADDR, localCipherPtr, 0x10);

    return ret;
}

// ================================================================
//  通用 ARM64 调用 (最多 4 个参数)
//  Generic ARM64 call with up to 4 args
// ================================================================
uint64_t CallARM64(uint64_t funcAddr, int argc, ...)
{
    uint64_t a[4] = {};
    va_list ap;
    va_start(ap, argc);
    for (int i = 0; i < argc && i < 4; i++)
        a[i] = va_arg(ap, uint64_t);
    va_end(ap);

    ResetForCall();

    if (argc > 0) uc_reg_write(g.uc, UC_ARM64_REG_X0, &a[0]);
    if (argc > 1) uc_reg_write(g.uc, UC_ARM64_REG_X1, &a[1]);
    if (argc > 2) uc_reg_write(g.uc, UC_ARM64_REG_X2, &a[2]);
    if (argc > 3) uc_reg_write(g.uc, UC_ARM64_REG_X3, &a[3]);

    uint64_t lr = RET_STUB_ADDR;
    uc_reg_write(g.uc, UC_ARM64_REG_LR, &lr);

    uc_err err = uc_emu_start(g.uc, funcAddr, RET_STUB_ADDR, EMU_TIMEOUT, 0);
    if (err != UC_ERR_OK && err != UC_ERR_FETCH_UNMAPPED)
        LOGE("CallARM64(0x%lx): %s",
             (unsigned long)funcAddr, uc_strerror(err));

    uint64_t ret = 0;
    uc_reg_read(g.uc, UC_ARM64_REG_X0, &ret);
    return ret;
}

// ================================================================
//  映射 Shellcode — 预加载 shellcode 到 Unicorn
//  不依赖延迟页面映射 (shellcode 较大, ~940KB)
//  MapShellcode — pre-map the shellcode into Unicorn
// ================================================================
static bool MapShellcode()
{
    if (g.shellcodeMapped) return true;
    if (g.off.shellcodeBase == 0 || g.off.shellcodeSize == 0) return false;

    uint64_t base = g.off.shellcodeBase;
    size_t   size = (g.off.shellcodeSize + EMU_PAGE_SIZE - 1)
                    & ~(EMU_PAGE_SIZE - 1);

    uc_err err = uc_mem_map(g.uc, base, size, UC_PROT_ALL);
    if (err != UC_ERR_OK && err != UC_ERR_MAP) {
        LOGE("MapShellcode: map 0x%lx +0x%lx: %s",
             (unsigned long)base, (unsigned long)size, uc_strerror(err));
        return false;
    }

    // 从目标进程读取 shellcode 页面到 Unicorn
    // Read shellcode pages from target process into Unicorn
    std::vector<uint8_t> buf(EMU_PAGE_SIZE);
    for (size_t off = 0; off < size; off += EMU_PAGE_SIZE) {
        if (RdMem(base + off, buf.data(), EMU_PAGE_SIZE)) {
            uc_mem_write(g.uc, base + off, buf.data(), EMU_PAGE_SIZE);
        }
    }

    g.shellcodeMapped = true;
    LOGI("Shellcode mapped: 0x%lx +0x%lx (%zu KB)",
         (unsigned long)base, (unsigned long)size, size / 1024);
    return true;
}

// ================================================================
//  Shellcode ELF 符号解析 (like PoP)
//  从 shellcode RWX 区域的 ELF 符号表解析函数边界
//  支持 section header (.symtab) 和 program header (.dynsym) 两种路径
// ================================================================
static bool ResolveShellcodeSymbols()
{
    if (g.syms.resolved) return true;
    uintptr_t base = g.off.shellcodeBase;
    size_t    total = g.off.shellcodeSize;
    if (base == 0 || total == 0) return false;

    Elf64_Ehdr ehdr;
    if (!RdMem(base, &ehdr, sizeof(ehdr))) return false;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return false;
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) return false;

    // 需要解析的符号名 → 目标指针
    struct SymLookup { const char* name; uint64_t* dst; };
    SymLookup lookups[] = {
        {"entry",                   &g.syms.entry},
        {"hash_end",                &g.syms.hashEnd},
        {"hash_direct_start",       &g.syms.hashDirectStart},
        {"hash_direct_init_start",  &g.syms.hashDirectInitStart},
        {"hash_direct_init_end",    &g.syms.hashDirectInitEnd},
        {"ring_calc_start",         &g.syms.ringCalcStart},
        {"all_params_exec_end",     &g.syms.allParamsExecEnd},
        {"v87_end",                 &g.syms.v87End},
    };
    constexpr int NUM_LOOKUPS = sizeof(lookups) / sizeof(lookups[0]);

    // 通用解析: 给定 symtab 偏移/大小/entsize 和 strtab 偏移/大小
    auto resolveFromTable = [&](uint64_t symOff, uint64_t symSz, uint64_t entSz,
                                uint64_t strOff, uint64_t strSz) -> int {
        if (entSz < sizeof(Elf64_Sym) || symSz == 0 || strSz == 0) return 0;
        size_t count = symSz / entSz;
        if (count > 100000) count = 100000;

        std::vector<uint8_t> symBuf(symSz);
        std::vector<char>    strBuf(strSz);
        if (!RdMem(base + symOff, symBuf.data(), symSz)) return 0;
        if (!RdMem(base + strOff, strBuf.data(), strSz)) return 0;

        int found = 0;
        for (size_t i = 0; i < count; i++) {
            auto* sym = (Elf64_Sym*)(symBuf.data() + i * entSz);
            if (sym->st_name >= strSz || sym->st_value == 0) continue;
            const char* name = strBuf.data() + sym->st_name;
            for (int j = 0; j < NUM_LOOKUPS; j++) {
                if (*lookups[j].dst == 0 && strcmp(name, lookups[j].name) == 0) {
                    *lookups[j].dst = base + sym->st_value;
                    found++;
                    LOGI("  sym %-28s = 0x%lx (sc+0x%lx)",
                         name, (unsigned long)*lookups[j].dst,
                         (unsigned long)sym->st_value);
                    break;
                }
            }
        }
        return found;
    };

    int totalFound = 0;

    // --- 路径 1: Section Headers (.symtab + .strtab) ---
    if (ehdr.e_shoff != 0 && ehdr.e_shnum != 0 &&
        ehdr.e_shoff + (uint64_t)ehdr.e_shnum * ehdr.e_shentsize <= total)
    {
        size_t shdrBufSz = ehdr.e_shnum * ehdr.e_shentsize;
        std::vector<uint8_t> shdrBuf(shdrBufSz);
        if (RdMem(base + ehdr.e_shoff, shdrBuf.data(), shdrBufSz)) {
            for (int i = 0; i < ehdr.e_shnum; i++) {
                auto* sh = (Elf64_Shdr*)(shdrBuf.data() + i * ehdr.e_shentsize);
                if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) continue;
                if (sh->sh_link >= ehdr.e_shnum) continue;
                auto* strSh = (Elf64_Shdr*)(shdrBuf.data() + sh->sh_link * ehdr.e_shentsize);
                totalFound += resolveFromTable(sh->sh_offset, sh->sh_size, sh->sh_entsize,
                                               strSh->sh_offset, strSh->sh_size);
            }
        }
    }

    // --- 路径 2: Program Headers → PT_DYNAMIC → DT_SYMTAB/DT_STRTAB ---
    if (totalFound < 2 && ehdr.e_phoff != 0 && ehdr.e_phnum != 0) {
        size_t phdrBufSz = ehdr.e_phnum * ehdr.e_phentsize;
        std::vector<uint8_t> phdrBuf(phdrBufSz);
        if (RdMem(base + ehdr.e_phoff, phdrBuf.data(), phdrBufSz)) {
            for (int i = 0; i < ehdr.e_phnum; i++) {
                auto* ph = (Elf64_Phdr*)(phdrBuf.data() + i * ehdr.e_phentsize);
                if (ph->p_type != PT_DYNAMIC) continue;

                size_t dynCnt = ph->p_filesz / sizeof(Elf64_Dyn);
                if (dynCnt > 4096) dynCnt = 4096;
                std::vector<Elf64_Dyn> dyns(dynCnt);
                if (!RdMem(base + ph->p_offset, dyns.data(), dynCnt * sizeof(Elf64_Dyn)))
                    break;

                uint64_t dtSymtab = 0, dtStrtab = 0, dtStrsz = 0;
                uint64_t dtHash = 0, dtSyment = sizeof(Elf64_Sym);
                for (size_t d = 0; d < dynCnt && dyns[d].d_tag != DT_NULL; d++) {
                    switch (dyns[d].d_tag) {
                        case DT_SYMTAB:  dtSymtab = dyns[d].d_un.d_val; break;
                        case DT_STRTAB:  dtStrtab = dyns[d].d_un.d_val; break;
                        case DT_STRSZ:   dtStrsz  = dyns[d].d_un.d_val; break;
                        case DT_HASH:    dtHash   = dyns[d].d_un.d_val; break;
                        case DT_SYMENT:  dtSyment = dyns[d].d_un.d_val; break;
                    }
                }
                if (dtSymtab && dtStrtab && dtStrsz) {
                    uint64_t symOff = dtSymtab;
                    uint64_t strOff = dtStrtab;
                    // DT_HASH: first word = nbucket, second = nchain = symbol count
                    uint32_t nchain = 0;
                    if (dtHash) {
                        uint32_t hashHdr[2];
                        if (RdMem(base + dtHash, hashHdr, 8))
                            nchain = hashHdr[1];
                    }
                    if (nchain == 0) nchain = 8192;
                    uint64_t symSz = nchain * dtSyment;
                    totalFound += resolveFromTable(symOff, symSz, dtSyment, strOff, dtStrsz);
                }
                break;
            }
        }
    }

    g.syms.resolved = (totalFound >= 2 && g.syms.hashDirectStart != 0 && g.syms.hashEnd != 0);

    if (g.syms.resolved) {
        LOGI("Shellcode symbols resolved: %d found, begin=0x%lx until=0x%lx",
             totalFound,
             (unsigned long)g.syms.hashDirectStart,
             (unsigned long)g.syms.hashEnd);
    } else if (totalFound > 0) {
        LOGW("Shellcode symbols partial (%d found), falling back to fixed offsets", totalFound);
    } else {
        LOGW("Shellcode has no symbol table, using fixed offsets");
    }
    return g.syms.resolved;
}

// ================================================================
//  调用 Shellcode 函数
//  ARM64 AAPCS64: X0, X1, X2, X3 前 4 个参数
//  LR = RET_STUB_ADDR (函数 RET 跳转到此处 → 模拟停止)
//  CallShellcodeFunc — call a function in the ACE shellcode
// ================================================================
static uint64_t CallShellcodeFunc(uint64_t funcAddr, uint64_t untilAddr,
                                  uint64_t x0, uint64_t x1,
                                  uint64_t x2 = 0, uint64_t x3 = 0)
{
    if (!g.shellcodeMapped) MapShellcode();

    ResetForCall();

    uc_reg_write(g.uc, UC_ARM64_REG_X0, &x0);
    uc_reg_write(g.uc, UC_ARM64_REG_X1, &x1);
    uc_reg_write(g.uc, UC_ARM64_REG_X2, &x2);
    uc_reg_write(g.uc, UC_ARM64_REG_X3, &x3);

    // LR = untilAddr: 函数 RET 跳转到 until 地址 → uc_emu_start 自动停止
    uint64_t lr = untilAddr;
    uc_reg_write(g.uc, UC_ARM64_REG_LR, &lr);

    // like PoP: begin/until 精确控制 + timeout 兜底, count=0 不限指令数
    uc_err err = uc_emu_start(g.uc, funcAddr, untilAddr, EMU_TIMEOUT, 0);
    if (err != UC_ERR_OK && err != UC_ERR_FETCH_UNMAPPED) {
        LOGE("CallShellcode 0x%lx→0x%lx: %s",
             (unsigned long)funcAddr, (unsigned long)untilAddr,
             uc_strerror(err));
    }

    uint64_t ret = 0;
    uc_reg_read(g.uc, UC_ARM64_REG_X0, &ret);
    return ret;
}

// ================================================================
//  坐标解密 — 调用 shellcode 解密函数
//  shellcode 主解密函数 (0x9E000) 参数:
//    X0 = USceneComponent 指针
//    X1 = 源数据指针 (加密坐标)
//  通过延迟页面映射操作 Unicorn 中的游戏内存
//  CoordDecrypt — call shellcode decrypt function
// ================================================================
uint64_t CoordDecrypt(Vector3* /*enc_data*/, uint32_t /*size*/,
                      uint32_t* /*pIndex*/, uint32_t /*currentFrame*/)
{
    // 注意: 手游版的 CoordDecrypt 完全由 shellcode 处理
    // shellcode 直接读写组件内存，本函数仅保留 API 兼容性
    // 实际工作在 DecryptPosition → CallShellcodeFunc 中完成
    // NOTE: On mobile, CoordDecrypt is handled entirely by the shellcode.
    // Kept for API compatibility; actual work in DecryptPosition → CallShellcodeFunc.
    return 0;
}

// ================================================================
//  解密坐标 — 基于 shellcode 的坐标解密
//
//  流程:
//  1. 从 component+0x174 读取 FEncHandler
//  2. 未加密 → 直接返回 component+0x168 的明文坐标
//  3. 已加密 → 调用 shellcode 解密函数
//  4. 重新读取 component+0x168 获取解密结果
//  DecryptPosition — shellcode-based coordinate decryption
// ================================================================
Vector3 DecryptPosition(uintptr_t rootComponent, bool /*isItem*/)
{
    // 读取加密处理器 / Read encryption handler
    FEncHandler eh;
    RdMem(rootComponent + GameOffsets::ENC_HANDLER_OFF, &eh, sizeof(eh));

    // 未加密 → 直接读取明文坐标 / Not encrypted → read plain coordinates
    if (!eh.bEncrypted) {
        return RdVal<Vector3>(rootComponent + GameOffsets::PLAIN_POS_OFF);
    }

    // 读取加密数据区签名 / Read encrypted data area signature
    uint64_t encAddr = rootComponent + GameOffsets::ENC_DATA_OFF;
    uint16_t sign = RdVal<uint16_t>(encAddr + 0x30);

    if (sign == 0xFFFF) {
        // ACE 尚未加密 — 返回原始数据 / Not yet encrypted by ACE — return raw data
        return RdVal<Vector3>(encAddr + 0x10);
    }

    // === 调用 shellcode 解密函数 ===
    // X0 = component pointer, X1 = encrypted coords buffer
    uint64_t beginAddr, untilAddr;
    if (g.syms.resolved) {
        // like PoP: 符号驱动，精确 begin/until
        beginAddr = g.syms.hashDirectStart;
        untilAddr = g.syms.hashEnd;
    } else {
        // fallback: 偏移 + RET_STUB
        beginAddr = g.off.shellcodeBase + g.off.scDecryptFuncOff;
        untilAddr = RET_STUB_ADDR;
    }

    CallShellcodeFunc(beginAddr, untilAddr, rootComponent, encAddr);

    Vector3 pos = RdVal<Vector3>(rootComponent + GameOffsets::PLAIN_POS_OFF);

    if (IsAbnormalFloatCoord(pos)) {
        for (int retry = 0; retry < 20; retry++) {
            CallShellcodeFunc(beginAddr, untilAddr, rootComponent, encAddr);
            pos = RdVal<Vector3>(rootComponent + GameOffsets::PLAIN_POS_OFF);
            if (!IsAbnormalFloatCoord(pos)) break;
        }
    }

    return pos;
}

// ================================================================
//  异常坐标检测 / IsAbnormalFloatCoord
// ================================================================
bool IsAbnormalFloatCoord(const Vector3& v, const Vector3* prev)
{
    constexpr float MIN_VALID   = 1e-4f;
    constexpr float WORLD_LIMIT = 100000.0f;
    constexpr float HARD_LIMIT  = 1e7f;

    auto bad = [](float f) -> bool {
        if (!std::isfinite(f)) return true;
        float a = std::fabs(f);
        if (a > 0.0f && a < MIN_VALID) return true;
        if (std::fpclassify(f) == FP_ZERO) return true;
        return false;
    };

    if (bad(v.x) || bad(v.y) || bad(v.z)) return true;

    if (std::fabs(v.x) > WORLD_LIMIT ||
        std::fabs(v.y) > WORLD_LIMIT ||
        std::fabs(v.z) > WORLD_LIMIT)
        return true;

    if (std::fabs(v.x) > HARD_LIMIT ||
        std::fabs(v.y) > HARD_LIMIT ||
        std::fabs(v.z) > HARD_LIMIT)
        return true;

    if (prev) {
        constexpr float MAX_DELTA = 20000.0f;
        if (std::fabs(v.x - prev->x) > MAX_DELTA ||
            std::fabs(v.y - prev->y) > MAX_DELTA ||
            std::fabs(v.z - prev->z) > MAX_DELTA)
            return true;
    }
    return false;
}

// ================================================================
//  Dec800 (纯计算 — 跨平台) / Dec800 (pure computation)
// ================================================================
static inline uint32_t rol32(uint32_t v, unsigned r)
{
    return (v << r) | (v >> (32 - r));
}

uint64_t Dec800(uint64_t rcx, uint64_t H)
{
    uint32_t ecx = (uint32_t)rcx;
    uint32_t x   = (uint32_t)(H & 0xFFFFFFFFu);
    uint32_t y   = (uint32_t)(H >> 32);

    uint32_t rY  = rol32(y, 25);
    uint32_t rX3 = rol32(x, 3);

    uint32_t val = (x ^ rY) + rX3;
    uint32_t S   = rol32(val, 13);
    uint32_t R   = rol32(val, 21);

    uint32_t out = (uint32_t)(rol32(ecx ^ R, 5) - S);

    return (rcx & 0xFFFFFFFF00000000ULL) | (uint64_t)out;
}
