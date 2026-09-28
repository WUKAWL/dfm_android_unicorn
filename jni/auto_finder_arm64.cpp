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
#include "auto_finder_arm64.h"
#include "memory_helper.h"

#include <cstring>
#include <cstdio>

// ================================================================
//  Helper: read a single uint32 instruction
// ================================================================
static uint32_t RdInsn(uint64_t addr, ReadMemFunc readMem)
{
    uint32_t insn = 0;
    readMem((uintptr_t)addr, &insn, 4);
    return insn;
}

template <typename T>
static T RdVal(uint64_t addr, ReadMemFunc readMem)
{
    T v{};
    readMem((uintptr_t)addr, &v, sizeof(T));
    return v;
}

// ================================================================
//  PatternScan — byte pattern search with mask
//  mask: 0xFF = must match, 0x00 = wildcard
// ================================================================
int64_t PatternScan(uint64_t scanStart, size_t scanSize,
                    const uint8_t* pattern, const uint8_t* mask, size_t patternLen,
                    ReadMemFunc readMem)
{
    const size_t CHUNK = 0x1000;
    std::vector<uint8_t> buf(CHUNK + patternLen);

    for (size_t off = 0; off < scanSize; off += CHUNK) {
        size_t toRead = CHUNK + patternLen;
        if (off + toRead > scanSize) toRead = scanSize - off;
        if (toRead < patternLen) break;

        readMem((uintptr_t)(scanStart + off), buf.data(), toRead);

        for (size_t i = 0; i <= toRead - patternLen; i++) {
            bool match = true;
            for (size_t j = 0; j < patternLen; j++) {
                if (mask[j] && buf[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return (int64_t)(off + i);
        }
    }
    return -1;
}

// ================================================================
//  FindFirstBL — find first BL instruction in function body
// ================================================================
uint64_t FindFirstBL(uint64_t funcStart, size_t maxSearch, ReadMemFunc readMem)
{
    return FindNthBL(funcStart, maxSearch, 1, readMem);
}

// ================================================================
//  FindNthBL — find the Nth BL instruction
// ================================================================
uint64_t FindNthBL(uint64_t funcStart, size_t maxSearch, int n, ReadMemFunc readMem)
{
    int count = 0;
    for (size_t off = 0; off < maxSearch; off += 4) {
        uint32_t insn = RdInsn(funcStart + off, readMem);
        if (IsARM64_BL(insn)) {
            count++;
            if (count == n)
                return BL_Target(funcStart + off, insn);
        }
        if (IsARM64_RET(insn)) break;
    }
    return 0;
}

// ================================================================
//  ResolveAdrpAt — decode ADRP+ADD/LDR pair at given address
// ================================================================
AdrpPairResult ResolveAdrpAt(uint64_t addr, ReadMemFunc readMem)
{
    uint32_t insn0 = RdInsn(addr, readMem);
    uint32_t insn1 = RdInsn(addr + 4, readMem);
    return DecodeAdrpPair(addr, insn0, insn1);
}

// ================================================================
//  FollowBLChain — follow N levels of BL instructions
//  e.g. depth=3: resolve BL at startAddr → target1,
//       then first BL in target1 → target2, etc.
// ================================================================
uint64_t FollowBLChain(uint64_t startAddr, int depth, ReadMemFunc readMem)
{
    uint64_t addr = startAddr;
    for (int i = 0; i < depth; i++) {
        uint32_t insn = RdInsn(addr, readMem);
        if (IsARM64_BL(insn)) {
            addr = BL_Target(addr, insn);
        } else {
            // Not a BL at current position, scan for first BL in function
            uint64_t target = FindFirstBL(addr, 0x200, readMem);
            if (target == 0) return 0;
            addr = target;
        }
    }
    return addr;
}

// ================================================================
//  ScanForAdrpPattern — scan function body for ADRP+ADD/LDR
//  that references a specific register as source
// ================================================================
static AdrpPairResult ScanForAdrp(uint64_t funcStart, size_t maxSearch,
                                   ReadMemFunc readMem, int targetReg = -1)
{
    for (size_t off = 0; off < maxSearch; off += 4) {
        uint32_t insn0 = RdInsn(funcStart + off, readMem);
        if (!IsARM64_ADRP(insn0)) continue;

        uint32_t insn1 = RdInsn(funcStart + off + 4, readMem);
        AdrpPairResult r = DecodeAdrpPair(funcStart + off, insn0, insn1);
        if (r.valid) {
            if (targetReg < 0 || (int)r.destReg == targetReg)
                return r;
        }

        if (IsARM64_RET(insn0)) break;
    }
    return {false, 0, false, 0};
}

// ================================================================
//  FindBLR — find first BLR Xn (indirect call) in function
// ================================================================
static uint64_t FindBLROffset(uint64_t funcStart, size_t maxSearch, ReadMemFunc readMem)
{
    for (size_t off = 0; off < maxSearch; off += 4) {
        uint32_t insn = RdInsn(funcStart + off, readMem);
        if (IsARM64_BLR(insn))
            return funcStart + off;
        if (IsARM64_RET(insn)) break;
    }
    return 0;
}

// ================================================================
//  PatchBLRsToNOP — NOP out BLR instructions in a buffer
//  (equivalent to patching 0xFF bytes on x86)
// ================================================================
static int PatchBLRsToNOP(uint8_t* buf, size_t len,
                           size_t excludeStart = 0, size_t excludeEnd = 0)
{
    int count = 0;
    for (size_t i = 0; i + 3 < len; i += 4) {
        uint32_t insn;
        memcpy(&insn, buf + i, 4);
        if (IsARM64_BLR(insn) || IsARM64_BR(insn)) {
            if (excludeStart > 0 && i >= excludeStart && i < excludeEnd)
                continue;
            // Replace with NOP
            uint32_t nop = ARM64_NOP;
            memcpy(buf + i, &nop, 4);
            count++;
        }
    }
    return count;
}

// ================================================================
//  PatchBLToBRK — replace a BL instruction with BRK #imm
//  (equivalent to replacing E8 with CC on x86)
// ================================================================
static bool PatchBLToBRK(uint8_t* buf, size_t offset, uint16_t brkImm = 0)
{
    uint32_t insn;
    memcpy(&insn, buf + offset, 4);
    if (!IsARM64_BL(insn)) return false;

    uint32_t brk = 0xD4200000 | ((uint32_t)brkImm << 5);
    memcpy(buf + offset, &brk, 4);
    return true;
}

// ================================================================
//  FindAceAddresses — main auto-finder
//
//  ARM64 adaptation of the PC version's GetAceTempPointer() logic:
//
//  PC flow:
//    AceHookAddress → CALL → calladdress
//    calladdress+0x4C → MOV → RcxValue (data ptr)
//    RcxValue+0x18 → ptr → +0x20 → DecCallAddress (vcall)
//    DecCallAddress body: find 1st CALL → DecListCallAddress
//    DecCallAddress body: find 2nd CALL → FindListAddress
//    FindListAddress body: find CALL after 0x0A → Enc800Offset
//    Follow 3 CALLs → KeyPointer
//
//  ARM64 equivalent:
//    AceHookAddr → BL → callTarget
//    callTarget body: scan for ADRP+LDR → data pointer
//    data+0x18 → ptr → +0x20 → DecCallAddress (vcall func ptr)
//    DecCallAddress body: find 1st BL → DecListCallAddress
//    DecCallAddress body: find 2nd BL → FindListAddress
//    FindListAddress body: scan BLs for Dec800 key chain
//    Follow 3 BL levels → key pointer
//    Resolve via ADRP+LDR → KeyPointer
// ================================================================
AceAddresses FindAceAddresses(uint64_t moduleBase, uint64_t moduleSize, ReadMemFunc readMem)
{
    AceAddresses result = {};
    result.found = false;

    LOGI("=== ARM64 Auto Address Finder ===");
    LOGI("Module base: 0x%lx  size: 0x%lx", (unsigned long)moduleBase, (unsigned long)moduleSize);

    // ---- Step 1: Find AceHook entry point ----
    // On ARM64, the ACE hook is typically a BL (branch-link) instruction
    // at a known offset. We scan for a signature pattern near the hook.
    //
    // Signature: look for the encryption vtable setup pattern:
    //   ADRP Xn, #page
    //   LDR  Xn, [Xn, #off]    ; load vtable/table pointer
    //   ... followed by BLR Xn  ; indirect call into decrypt
    //
    // Alternative: scan .text for a known sequence around the coordinator

    // Pattern for encryption table reference (ADRP + LDR + BLR sequence)
    // This is game-version specific. User can provide the aceCheckOff
    // or we scan for it.

    // ---- Step 2: Scan for encryption table pointer ----
    // Look for ADRP+LDR pairs that load from .bss/.data
    // The encryption table is typically a global pointer accessed via ADRP+LDR

    // ---- Step 3: Scan for the coordinate decrypt function ----
    // The decrypt function follows a pattern:
    //   - Takes 4 parameters (X0=buffer, X1=size, X2=key, X3=extra)
    //   - Contains BLR to vtable function
    //   - Usually near the encryption table reference

    // Since we can't know exact offsets without the specific binary,
    // we provide the scanning primitives and let the user configure.
    //
    // Here's a generic approach using common patterns:

    // Scan for a distinctive byte pattern in the module
    // The ACE encryption initialization typically has a unique signature

    // Pattern: ADRP X8, #page / LDR X8, [X8, #off] / CBZ/CBNZ / BLR X8
    // This is the vtable call pattern for encryption
    const uint8_t encVtablePattern[] = {
        0x00, 0x00, 0x00, 0x90,  // ADRP X?, #page (wildcard)
        0x00, 0x00, 0x40, 0xF9,  // LDR X?, [X?, #off] (wildcard)
    };
    const uint8_t encVtableMask[] = {
        0x1F, 0x00, 0x00, 0x9F,  // match ADRP opcode, Rd=wildcard
        0x00, 0x00, 0xC0, 0xFF,  // match LDR 64-bit unsigned offset
    };

    LOGI("Scanning for ADRP+LDR patterns...");

    // Scan the first 1/4 of the module (code section is usually at start)
    size_t scanLimit = moduleSize < 0x2000000 ? moduleSize : 0x2000000;

    // Try to find encryption-related ADRP+LDR patterns
    // We look for patterns where the loaded address is then used as a vtable
    std::vector<uint64_t> adrpCandidates;

    for (size_t off = 0; off < scanLimit && adrpCandidates.size() < 20; off += 4) {
        uint32_t insn0 = RdInsn(moduleBase + off, readMem);
        if (!IsARM64_ADRP(insn0)) continue;

        uint32_t insn1 = RdInsn(moduleBase + off + 4, readMem);
        AdrpPairResult r = DecodeAdrpPair(moduleBase + off, insn0, insn1);
        if (!r.valid || !r.isLoad) continue;

        // Check if followed by BLR (vtable call pattern)
        for (int k = 2; k < 8; k++) {
            uint32_t insnK = RdInsn(moduleBase + off + k * 4, readMem);
            if (IsARM64_BLR(insnK) && BLR_Rn(insnK) == r.destReg) {
                // Check if this looks like encryption setup
                // (has specific register usage patterns)
                uint32_t prevInsn = RdInsn(moduleBase + off - 4, readMem);

                // Store candidate
                adrpCandidates.push_back(moduleBase + off);
                LOGI("  Candidate ADRP+LDR+BLR at offset 0x%lx -> addr 0x%lx",
                     (unsigned long)off, (unsigned long)r.address);
                break;
            }
        }
    }

    if (adrpCandidates.empty()) {
        LOGE("No ADRP+LDR+BLR candidates found");
        return result;
    }

    // For each candidate, try to follow the decrypt chain
    for (uint64_t candAddr : adrpCandidates) {
        AdrpPairResult adrp = ResolveAdrpAt(candAddr, readMem);
        if (!adrp.valid) continue;

        uint64_t tablePtr = adrp.address;

        // Read the pointer at tablePtr
        uint64_t tableValue = RdVal<uint64_t>(tablePtr, readMem);
        if (tableValue == 0) continue;

        // Check if this looks like a valid encryption table
        // The table should have a vcall pointer at offset 0x48
        uint64_t vcallCheck = RdVal<uint64_t>(tableValue + 0x48, readMem);
        if (vcallCheck == 0) continue;

        // Verify vcall is within module range
        if (vcallCheck < moduleBase || vcallCheck > moduleBase + moduleSize) continue;

        LOGI("  Found encryption table at 0x%lx (vcall=0x%lx)",
             (unsigned long)tablePtr, (unsigned long)vcallCheck);

        result.encTablePtr = tablePtr;

        // ---- Step 4: Find DecListCallAddress ----
        // Scan the vcall function for BL instructions
        uint64_t bl1Target = FindFirstBL(vcallCheck, 0x200, readMem);
        if (bl1Target) {
            LOGI("  DecListCallAddress (1st BL): 0x%lx", (unsigned long)bl1Target);
            result.decListCallAddr = bl1Target;
        }

        uint64_t bl2Target = FindNthBL(vcallCheck, 0x400, 2, readMem);
        if (bl2Target) {
            LOGI("  FindListAddress (2nd BL): 0x%lx", (unsigned long)bl2Target);
            result.findListAddr = bl2Target;
        }

        // ---- Step 5: Find Dec800 key ----
        if (result.findListAddr) {
            // Scan FindListAddress for BL instructions
            // The Dec800 key derivation follows a chain of BL calls
            // Similar to PC: follow 3 levels of BL
            uint64_t keyChain = result.findListAddr;

            // Find a BL that's preceded by a specific pattern
            // (on x86 it was E8 after 0x0A byte)
            // On ARM64, look for BL instructions in the function body
            for (size_t off = 0; off < 0x400; off += 4) {
                uint32_t insn = RdInsn(result.findListAddr + off, readMem);
                if (IsARM64_RET(insn) && off > 0x100) break;

                if (IsARM64_BL(insn)) {
                    uint64_t blTarget = BL_Target(result.findListAddr + off, insn);

                    // Check if target function contains ADRP+LDR (key reference)
                    AdrpPairResult keyAdrp = ScanForAdrp(blTarget, 0x100, readMem);
                    if (keyAdrp.valid && keyAdrp.isLoad) {
                        // Follow the BL chain to find key pointer
                        uint64_t keyFuncAddr = blTarget;

                        // Try 3-level chain like PC version
                        uint64_t level1 = FindFirstBL(keyFuncAddr, 0x100, readMem);
                        if (level1) {
                            uint64_t level2 = FindFirstBL(level1, 0x100, readMem);
                            if (level2) {
                                // Scan level2 for ADRP+LDR to find key pointer
                                AdrpPairResult kp = ScanForAdrp(level2, 0x100, readMem);
                                if (kp.valid && kp.isLoad) {
                                    result.dec800KeyPtr = kp.address;
                                    result.dec800Key = RdVal<uint64_t>(
                                        RdVal<uint64_t>(kp.address, readMem), readMem);
                                    LOGI("  Dec800 KeyPtr: 0x%lx  Key: 0x%lx",
                                         (unsigned long)kp.address,
                                         (unsigned long)result.dec800Key);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        // ---- Step 6: Find encryption slot base ----
        // The encBase is typically near the encTablePtr in .bss
        // Usually at encTablePtr - some_offset (e.g. 0xD00 on PC)
        // On ARM64, scan nearby ADRP+LDR for another .bss reference
        if (result.encTablePtr) {
            // Scan backwards from the encTablePtr reference for another ADRP
            for (int64_t off = -0x100; off < 0x100; off += 4) {
                if (off == 0) continue;
                AdrpPairResult nearby = ResolveAdrpAt(candAddr + off, readMem);
                if (nearby.valid && nearby.isLoad && nearby.address != result.encTablePtr) {
                    // Check if this could be encBase
                    uint64_t diff = result.encTablePtr > nearby.address ?
                        result.encTablePtr - nearby.address : nearby.address - result.encTablePtr;
                    if (diff < 0x2000) {
                        result.encBase = nearby.address;
                        LOGI("  EncBase candidate: 0x%lx (diff=0x%lx)",
                             (unsigned long)nearby.address, (unsigned long)diff);
                        break;
                    }
                }
            }
        }

        // ---- Step 7: Find frame counter ----
        // Frame counter is usually accessed via ADRP+LDR in the main loop
        // DeltaForce.hpp already has pattern for this
        // Look for LDR W?, [X?, #0] pattern near encryption code

        // ---- Step 8: Find TLS index ----
        // TLS on ARM64 uses MRS TPIDR_EL0 + offset
        // Scan encryption function for MRS TPIDR_EL0 pattern
        if (vcallCheck) {
            for (size_t off = 0; off < 0x400; off += 4) {
                uint32_t insn = RdInsn(vcallCheck + off, readMem);
                if (IsARM64_MRS_TPIDR(insn)) {
                    // Found MRS TPIDR_EL0 usage
                    // The TLS slot offset is usually in a nearby LDR instruction
                    LOGI("  MRS TPIDR_EL0 found at vcall+0x%lx", (unsigned long)off);

                    // Look for ADRP near the MRS that loads TLS index
                    for (size_t k = off; k < off + 0x40 && k < 0x400; k += 4) {
                        AdrpPairResult tlsAdrp = ResolveAdrpAt(vcallCheck + k, readMem);
                        if (tlsAdrp.valid) {
                            result.tlsIndex = tlsAdrp.address;
                            LOGI("  TLS index candidate: 0x%lx", (unsigned long)tlsAdrp.address);
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // If we found at least the encryption table, mark as partial success
        if (result.encTablePtr) {
            result.found = true;
            break;
        }
    }

    LOGI("=== Auto Finder Results ===");
    LOGI("  encTablePtr:      0x%lx", (unsigned long)result.encTablePtr);
    LOGI("  encBase:          0x%lx", (unsigned long)result.encBase);
    LOGI("  decListCallAddr:  0x%lx", (unsigned long)result.decListCallAddr);
    LOGI("  findListAddr:     0x%lx", (unsigned long)result.findListAddr);
    LOGI("  dec800KeyPtr:     0x%lx", (unsigned long)result.dec800KeyPtr);
    LOGI("  dec800Key:        0x%lx", (unsigned long)result.dec800Key);
    LOGI("  tlsIndex:         0x%lx", (unsigned long)result.tlsIndex);
    LOGI("  found:            %s", result.found ? "YES" : "NO");

    return result;
}
