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
#include <vector>
#include <functional>

// ================================================================
//  ARM64 Instruction Decode Helpers
// ================================================================

// BL imm26: 1001 01ii iiii iiii iiii iiii iiii iiii
static inline bool IsARM64_BL(uint32_t insn)    { return (insn & 0xFC000000) == 0x94000000; }
static inline int64_t BL_Offset(uint32_t insn)   {
    int32_t imm26 = (int32_t)(insn & 0x03FFFFFF);
    if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000; // sign extend
    return (int64_t)imm26 * 4;
}
static inline uint64_t BL_Target(uint64_t pc, uint32_t insn) {
    return pc + BL_Offset(insn);
}

// B imm26: 0001 01ii iiii iiii iiii iiii iiii iiii
static inline bool IsARM64_B(uint32_t insn)     { return (insn & 0xFC000000) == 0x14000000; }
static inline uint64_t B_Target(uint64_t pc, uint32_t insn) {
    int32_t imm26 = (int32_t)(insn & 0x03FFFFFF);
    if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000;
    return pc + (int64_t)imm26 * 4;
}

// ADRP Xd, label: 1xx1 0000 iiii iiii iiii iiii iiid dddd
static inline bool IsARM64_ADRP(uint32_t insn)  { return (insn & 0x9F000000) == 0x90000000; }
static inline uint32_t ADRP_Rd(uint32_t insn)   { return insn & 0x1F; }
static inline uint64_t ADRP_Page(uint64_t pc, uint32_t insn) {
    int64_t immhi = (int64_t)((insn >> 5) & 0x7FFFF) << 2;
    int64_t immlo = (int64_t)((insn >> 29) & 0x3);
    int64_t imm = (immhi | immlo) << 12;
    if (imm & (1LL << 32)) imm |= ~((1LL << 33) - 1); // sign extend 33 bits
    return (pc & ~0xFFFULL) + imm;
}

// ADD Xd, Xn, #imm12: 1001 0001 00ii iiii iiii iinn nnnd dddd
static inline bool IsARM64_ADD_imm(uint32_t insn) { return (insn & 0xFF800000) == 0x91000000; }
static inline uint32_t ADD_Rd(uint32_t insn)     { return insn & 0x1F; }
static inline uint32_t ADD_Rn(uint32_t insn)     { return (insn >> 5) & 0x1F; }
static inline uint32_t ADD_Imm12(uint32_t insn)  {
    uint32_t imm = (insn >> 10) & 0xFFF;
    uint32_t sh  = (insn >> 22) & 0x1;
    return sh ? (imm << 12) : imm;
}

// LDR Xd, [Xn, #imm12]: 1111 1001 01ii iiii iiii iinn nnnd dddd
static inline bool IsARM64_LDR_imm(uint32_t insn) { return (insn & 0xFFC00000) == 0xF9400000; }
static inline uint32_t LDR_Rd(uint32_t insn)     { return insn & 0x1F; }
static inline uint32_t LDR_Rn(uint32_t insn)     { return (insn >> 5) & 0x1F; }
static inline uint32_t LDR_Imm12(uint32_t insn)  { return ((insn >> 10) & 0xFFF) * 8; } // scaled by 8 for 64-bit

// BLR Xn: 1101 0110 0011 1111 0000 00nn nnn0 0000
static inline bool IsARM64_BLR(uint32_t insn)    { return (insn & 0xFFFFFC1F) == 0xD63F0000; }
static inline uint32_t BLR_Rn(uint32_t insn)     { return (insn >> 5) & 0x1F; }

// BR Xn: 1101 0110 0001 1111 0000 00nn nnn0 0000
static inline bool IsARM64_BR(uint32_t insn)     { return (insn & 0xFFFFFC1F) == 0xD61F0000; }

// RET (Xn): 1101 0110 0101 1111 0000 00nn nnn0 0000  (default Xn=X30)
static inline bool IsARM64_RET(uint32_t insn)    { return (insn & 0xFFFFFC1F) == 0xD65F0000; }

// BRK #imm16: 1101 0100 001i iiii iiii iiii iii0 0000
static inline bool IsARM64_BRK(uint32_t insn)    { return (insn & 0xFFE0001F) == 0xD4200000; }
static inline uint16_t BRK_Imm(uint32_t insn)    { return (uint16_t)((insn >> 5) & 0xFFFF); }

// MRS Xt, TPIDR_EL0  encoding: 0xD53BD040 | Rt
static inline bool IsARM64_MRS_TPIDR(uint32_t insn) { return (insn & 0xFFFFFFE0) == 0xD53BD040; }

// NOP: 1101 0101 0000 0011 0010 0000 0001 1111
static constexpr uint32_t ARM64_NOP = 0xD503201F;
static constexpr uint32_t ARM64_RET_X30 = 0xD65F03C0;

// ================================================================
//  ADRP+ADD / ADRP+LDR pair decoder
//  Reads two consecutive instructions and computes the address
// ================================================================
struct AdrpPairResult {
    bool     valid;
    uint64_t address;     // computed address
    bool     isLoad;      // true if ADRP+LDR (dereference needed)
    uint32_t destReg;     // destination register
};

static inline AdrpPairResult DecodeAdrpPair(uint64_t pc, uint32_t insn0, uint32_t insn1) {
    AdrpPairResult r = {false, 0, false, 0};
    if (!IsARM64_ADRP(insn0)) return r;

    uint32_t adrpRd = ADRP_Rd(insn0);
    uint64_t page = ADRP_Page(pc, insn0);

    if (IsARM64_ADD_imm(insn1) && ADD_Rn(insn1) == adrpRd) {
        r.valid   = true;
        r.address = page + ADD_Imm12(insn1);
        r.isLoad  = false;
        r.destReg = ADD_Rd(insn1);
    } else if (IsARM64_LDR_imm(insn1) && LDR_Rn(insn1) == adrpRd) {
        r.valid   = true;
        r.address = page + LDR_Imm12(insn1);
        r.isLoad  = true;
        r.destReg = LDR_Rd(insn1);
    }
    return r;
}

// ================================================================
//  Auto-finder result structure
// ================================================================
struct AceAddresses {
    uint64_t encTablePtr;           // encryption table pointer address
    uint64_t encBase;               // encryption slot base address
    uint64_t decListCallAddr;       // DecListCallAddress (decrypt function)
    uint64_t findListAddr;          // FindListAddress
    uint64_t dec800KeyPtr;          // Dec800 key pointer
    uint64_t dec800Key;             // Dec800 key value
    uint64_t frameCounter;          // frame counter address
    uint64_t tlsIndex;              // TLS index address
    bool     found;                 // true if all addresses were found
};

// ================================================================
//  Public API
// ================================================================

// Memory read callback type (same as sjz_dec_arm64.h)
typedef bool (*ReadMemFunc)(uintptr_t address, void* buffer, size_t size);

// Auto-find ACE encryption addresses in the game's .so
// moduleBase: base address of the game library (e.g. libUE4.so)
// moduleSize: size of the library in memory
// readMem:    memory read callback
AceAddresses FindAceAddresses(uint64_t moduleBase, uint64_t moduleSize, ReadMemFunc readMem);

// Scan for a byte pattern within a memory region
// Returns offset from scanStart, or -1 if not found
int64_t PatternScan(uint64_t scanStart, size_t scanSize,
                    const uint8_t* pattern, const uint8_t* mask, size_t patternLen,
                    ReadMemFunc readMem);

// Find the first BL instruction within a function body
// Returns absolute target address, or 0 if not found
uint64_t FindFirstBL(uint64_t funcStart, size_t maxSearch, ReadMemFunc readMem);

// Find Nth BL instruction within a function body
uint64_t FindNthBL(uint64_t funcStart, size_t maxSearch, int n, ReadMemFunc readMem);

// Resolve an ADRP+ADD/LDR pair at a given address
AdrpPairResult ResolveAdrpAt(uint64_t addr, ReadMemFunc readMem);

// Follow a BL chain: resolve BL at each address, following N levels deep
uint64_t FollowBLChain(uint64_t startAddr, int depth, ReadMemFunc readMem);
