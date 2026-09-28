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
#include <cmath>

// ================================================================
//  基础类型 / Basic types
// ================================================================
struct Vector3
{
    float x, y, z;
};

struct FEncHandler
{
    uint16_t Index;       // 0x0000
    int8_t   bEncrypted;  // 0x0002
    // 0x0003: bitfield (bDynamic:1, bShareKey:1, bBitwiseCopyable:1)
};

// ================================================================
//  游戏偏移 — Android ARM64 (基于shellcode)
//  已通过 SDK dump v1.201.37110.44 验证
//  Game-specific offsets — Android ARM64 (shellcode-based)
//  Verified from SDK dump v1.201.37110.44
// ================================================================
struct GameOffsets
{
    // === 模块基址 (绝对地址, 来自 /proc/pid/maps) ===
    // === Module bases (absolute, from /proc/pid/maps) ===
    uintptr_t moduleBase;              // libUE4.so base
    uintptr_t shellcodeBase;           // ACE shellcode RWX region base
    size_t    shellcodeSize;           // ACE shellcode size (~940KB)

    // === Shellcode 函数偏移 (相对于 shellcodeBase) ===
    // 这些是 shellcode 内部的 OLLVM CFF 入口点
    // === Shellcode function offsets (relative to shellcodeBase) ===
    uintptr_t scDecryptFuncOff;        // Main decrypt func (e.g. 0x9E000)
    uintptr_t scFindFuncOff;           // Find/resolve func (e.g. 0x50000)

    // === libUE4.so 偏移 (相对于 moduleBase) ===
    // === libUE4.so offsets (relative to moduleBase) ===
    uintptr_t frameCounterOff;         // FrameCounter address

    // === UE 组件偏移 (已通过 SDK dump 验证) ===
    // === UE component offsets (verified from SDK dump) ===
    //  FSceneComponent layout:
    //    0x0168: FEncVector RelativeLocation {X,Y,Z,EncHandler}
    //    0x0174: FEncHandler {Index:u16, bEncrypted:i8, bitfield}
    //    0x0178: FRotator RelativeRotation
    //    0x0210: ACE encrypted data area (runtime injected)
    //  AActor:
    //    0x0180: USceneComponent* RootComponent
    static constexpr uint32_t ROOTCOMP_OFF      = 0x0180;
    static constexpr uint32_t PLAIN_POS_OFF     = 0x0168;  // FEncVector.X/Y/Z
    static constexpr uint32_t ENC_HANDLER_OFF   = 0x0174;  // FEncHandler
    static constexpr uint32_t ENC_DATA_OFF      = 0x0210;  // ACE encrypted area

    // === Shellcode 使用的游戏对象偏移 ===
    // 这些是 ACE 加密上下文对象内的偏移
    // (shellcode 通过 game_obj+offset 访问)
    // === Game object offsets used by shellcode ===
    static constexpr uint32_t VTABLE_ENC_OFF    = 0x06E8;  // encryption vtable ptr
    static constexpr uint32_t VTABLE_FUNC_IDX   = 0x0080;  // vtable[0x80] = decrypt
    static constexpr uint32_t HASH_KEY_OFF      = 0x0980;  // hash key
    static constexpr uint32_t FRAME_CTR_OFF     = 0x05C0;  // frame counter in context
    static constexpr uint32_t CMP_VALUE_OFF     = 0x13E8;  // compare value
    static constexpr uint32_t ENC_FLAG_OFF      = 0x0ACB;  // encryption flag byte
};

// ================================================================
//  回调类型 / Callback types
// ================================================================
typedef bool (*ReadMemoryFunc)(uintptr_t address, void* buffer, size_t size);

// BRK 间接跳转解析回调
// 输入: brk_imm = BRK #imm 的 imm16 (高位携带 ID)
//       pc      = BRK 指令地址
// 返回: 解析后的真实跳转地址, 0 = 停止模拟
// BRK indirect jump resolver callback
typedef uint64_t (*BrkResolveFunc)(uint16_t brk_imm, uint64_t pc);

// ================================================================
//  公共 API / Public API
// ================================================================

// 初始化 ARM64 Unicorn 模拟器 / Initialize ARM64 Unicorn emulator
bool InitEmulatorARM64(int pid, const GameOffsets& offsets);

// 清理模拟器资源 / Cleanup emulator resources
void CleanupEmulator();

// 插入自定义内存读取器 (如 KittyMemoryEx)
// 未设置时使用内置的 process_vm_readv
// Plug in a custom memory reader
void SetMemoryReadFunc(ReadMemoryFunc func);

// 清空页面缓存 (每帧之间调用) / Invalidate page cache
void InvalidatePageCache();

// 从加密的 RootComponent 解密坐标 / Decrypt position from encrypted RootComponent
Vector3 DecryptPosition(uintptr_t rootComponent, bool isItem = false);

// 底层: 原地解密坐标数据 / Low-level: decrypt coordinate data in-place
uint64_t CoordDecrypt(Vector3* enc_data, uint32_t size, uint32_t* pIndex, uint32_t currentFrame);

// 验证浮点坐标是否异常 / Validate a float coordinate
bool IsAbnormalFloatCoord(const Vector3& v, const Vector3* prev = nullptr);

// Dec800 辅助函数 (纯计算, 跨平台) / Dec800 helper (pure computation)
uint64_t Dec800(uint64_t rcx, uint64_t H);

// 通用 ARM64 模拟函数调用 (最多4参数) / Generic ARM64 emulated call
uint64_t CallARM64(uint64_t funcAddr, int argc, ...);

// 获取 Unicorn 引擎指针 (用于直接读写寄存器)
// Get Unicorn engine pointer (for direct register read/write)
struct uc_struct;
typedef struct uc_struct uc_engine;
uc_engine* GetEmulatorUc();

// ================================================================
//  反混淆支持 / Anti-obfuscation support
// ================================================================

// 设置 MRS 指令返回的 TPIDR_EL0 值
// 在 InitEmulatorARM64 之后用目标线程的 TPIDR 调用
// Set the TPIDR_EL0 value for emulated MRS instructions
void SetTpidrEL0(uint64_t value);

// 启用/禁用指令级 trace / Enable/disable instruction trace
void EnableTrace(bool on);

// 注册 BRK 间接跳转解析器
// 模拟代码遇到 BRK #imm 时调用解析器
// 解析器必须返回真实跳转目标地址
// Register a BRK indirect-jump resolver
void SetBrkResolver(BrkResolveFunc resolver);
