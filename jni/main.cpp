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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <dirent.h>

#include "sjz_dec_arm64.h"
#include "memory_helper.h"
#include "libc_stub.h"
#include <unicorn/unicorn.h>

// ================================================================
//  Constants
// ================================================================
static const char* PACKAGE_NAME = "com.tencent.tmgp.dfm";
static const char* MODULE_NAME  = "libUE4.so";

// Shellcode size range for detection (800KB ~ 1.2MB anonymous RWX)
static constexpr size_t SC_MIN_SIZE = 0xC0000;   // 768 KB
static constexpr size_t SC_MAX_SIZE = 0x140000;   // 1.25 MB

// ================================================================
//  Auto-find game PID by package name
// ================================================================
static pid_t FindPid(const char* packageName)
{
    DIR* dir = opendir("/proc");
    if (!dir) return 0;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(ent->d_name);

        char path[128];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
        FILE* f = fopen(path, "r");
        if (!f) continue;

        char cmdline[256] = {};
        fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);

        if (strstr(cmdline, packageName)) {
            closedir(dir);
            return pid;
        }
    }
    closedir(dir);
    return 0;
}

// ================================================================
//  Shellcode region info
// ================================================================
struct ShellcodeRegion {
    uintptr_t base;
    size_t    size;
};

// ================================================================
//  Find ACE shellcode RWX region from /proc/pid/maps
//  ACE shellcode is an anonymous mmap'd region with rwxp permissions
//  and size ~940KB. There may be multiple RWX regions, so we look
//  for ones in the expected size range.
// ================================================================
static std::vector<ShellcodeRegion> FindShellcodeRegions(pid_t pid)
{
    std::vector<ShellcodeRegion> regions;
    char mapPath[64];
    snprintf(mapPath, sizeof(mapPath), "/proc/%d/maps", (int)pid);

    FILE* f = fopen(mapPath, "r");
    if (!f) return regions;

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

        // Anonymous RWX region (no pathname, rwxp permissions)
        if (n >= 7 && perms[0] == 'r' && perms[1] == 'w' &&
            perms[2] == 'x' && perms[3] == 'p' &&
            pathname[0] == '\0') {
            size_t regionSize = end - start;
            if (regionSize >= SC_MIN_SIZE && regionSize <= SC_MAX_SIZE) {
                regions.push_back({start, regionSize});
            }
        }
    }
    fclose(f);
    return regions;
}

// ================================================================
//  GName 解析 — 来自绘制项目 / From drawing project
// ================================================================
static std::string DecryptAnsiName(ProcessMemory& mem, uintptr_t strPtr, uint32_t len)
{
    if (len == 0 || len > 256) return "";
    std::string name(len, '\0');
    mem.read(strPtr, name.data(), len);

    uint16_t key = 0;
    switch (len % 9) {
        case 0: key = ((len & 0x1F) + len + 0x80) | 0x7F; break;
        case 1: key = ((len ^ 0xDF) + len + 0x80) | 0x7F; break;
        case 2: key = ((len | 0xCF) + len + 0x80) | 0x7F; break;
        case 3: key = (33 * len + 0x80) | 0x7F; break;
        case 4: key = (len + (len >> 2) + 0x80) | 0x7F; break;
        case 5: key = (3 * len + 133) | 0x7F; break;
        case 6: key = (((4 * len) | 5) + len + 0x80) | 0x7F; break;
        case 7: key = (((len >> 4) | 7) + len + 0x80) | 0x7F; break;
        case 8: key = ((len ^ 0x0C) + len + 0x80) | 0x7F; break;
        default: key = ((len ^ 0x40) + len + 0x80) | 0x7F; break;
    }
    for (uint32_t i = 0; i < len; i++) name[i] ^= (uint8_t)key;
    return name;
}

static std::string GetClassName(ProcessMemory& mem, uintptr_t gname, uint32_t index)
{
    const uint32_t Block  = (index >> 15) & 0x1FFF8;
    const uint32_t Offset = 2 * index & 0x7FFFE;
    uintptr_t FNamePool = gname + 0x38;
    uintptr_t chunk = mem.read<uintptr_t>(FNamePool + Block);
    if (chunk == 0) return "";
    uintptr_t entry = chunk + Offset;
    uint16_t header = mem.read<uint16_t>(entry);
    int strLen = header >> 6;
    return DecryptAnsiName(mem, entry + 2, strLen);
}

// ================================================================
//  libUE4.so 解密函数偏移
//  float sub_D1FBB84(uint64_t rootComponent)
//  内部: LDR X16, =shellcode_addr; BR X16
//  libUE4.so decrypt function offset
//  Internally jumps to shellcode via BR X16
// ================================================================
static constexpr uintptr_t DECRYPT_FUNC_OFF = 0xD1FBB84;

// ================================================================
//  主函数 — 自动发现 + 解密测试
//  Main — auto-discover + decrypt test
// ================================================================
int main(int argc, char** argv)
{
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);

    printf("========================================\n");
    printf(" @Kernel_Hack ACE Decrypt Test\n");
    printf(" https://github.com/libtersafe\n");
    printf("========================================\n");

    // === Step 1: 找游戏进程 / Find game PID ===
    pid_t pid = FindPid(PACKAGE_NAME);
    if (pid <= 0) {
        printf("[!] 游戏未运行: %s\n", PACKAGE_NAME);
        return 1;
    }
    printf("[+] PID: %d\n", (int)pid);

    // === Step 2: 找 libUE4.so / Find libUE4.so ===
    ModuleInfo ue4 = FindModule(pid, MODULE_NAME);
    if (ue4.base == 0) {
        printf("[!] 模块未找到: %s\n", MODULE_NAME);
        return 1;
    }
    printf("[+] %s base=0x%lx size=0x%lx\n",
           MODULE_NAME, (unsigned long)ue4.base, (unsigned long)ue4.size());

    // === Step 3: 找 shellcode RWX 区域 / Find shellcode ===
    auto scRegions = FindShellcodeRegions(pid);
    if (!scRegions.empty()) {
        printf("[+] Shellcode RWX: base=0x%lx size=%zuKB\n",
               (unsigned long)scRegions[0].base, scRegions[0].size / 1024);
    } else {
        printf("[!] 未找到 shellcode RWX 区域, 延迟页面映射会处理\n");
    }

    // === Step 4: 获取 TPIDR_EL0 / Get TPIDR_EL0 ===
    pid_t gameTid = ProcessMemory::findThreadByName(pid, "GameThread");
    uint64_t tpidr = 0;
    if (gameTid > 0) {
        printf("[+] GameThread TID: %d\n", (int)gameTid);
        tpidr = ProcessMemory::getTpidrEL0(gameTid);
        if (tpidr) printf("[+] TPIDR_EL0: 0x%lx\n", (unsigned long)tpidr);
        else       printf("[!] TPIDR_EL0 获取失败\n");
    } else {
        printf("[!] GameThread 未找到\n");
    }

    // === Step 5: 初始化模拟器 / Init emulator ===
    GameOffsets offsets = {};
    offsets.moduleBase    = ue4.base;
    offsets.shellcodeBase = scRegions.empty() ? 0 : scRegions[0].base;
    offsets.shellcodeSize = scRegions.empty() ? 0 : scRegions[0].size;

    if (!InitEmulatorARM64((int)pid, offsets)) {
        printf("[!] 模拟器初始化失败\n");
        return 1;
    }
    printf("[+] Unicorn 模拟器已初始化\n");

    if (tpidr) {
        SetTpidrEL0(tpidr);
        printf("[+] TPIDR_EL0 已设置\n");
    }

    // === Step 6: 解密测试 / Decrypt test ===
    // 解密函数绝对地址 = libUE4.so base + 0xD1FBB84
    // 签名: float sub_D1FBB84(uint64_t rootComponent)
    // 内部通过 LDR X16,=shellcode_addr; BR X16 跳转
    // Unicorn 延迟页面映射会自动加载 libUE4 和 shellcode 的页面
    uint64_t decryptAddr = ue4.base + DECRYPT_FUNC_OFF;
    printf("[+] 解密函数地址: 0x%lx (libUE4+0x%lx)\n",
           (unsigned long)decryptAddr, (unsigned long)DECRYPT_FUNC_OFF);

    // 验证解密函数入口字节 / Verify decrypt function entry
    uint32_t entryInsn[2] = {};
    ProcessMemory pmem;
    pmem.attach(pid);
    pmem.read(decryptAddr, entryInsn, 8);
    printf("[*] 入口指令: 0x%08X 0x%08X\n", entryInsn[0], entryInsn[1]);

    // 读取 shellcode 跳转目标 / Read shellcode jump target
    uint64_t scTarget = 0;
    pmem.read(decryptAddr + 8, &scTarget, 8);  // literal pool at +8
    printf("[*] Shellcode 目标: 0x%lx\n", (unsigned long)scTarget);

    // === 自动获取 Actor + RootComponent ===
    // 偏移来自绘制项目 drawing.h
    // Offsets from drawing project
    uint64_t GWorld = pmem.read<uint64_t>(ue4.base + 0x1a65ecc8);
    uint64_t UWorld = pmem.read<uint64_t>(GWorld + 0xF8);
    printf("[+] GWorld=0x%lx UWorld=0x%lx\n",
           (unsigned long)GWorld, (unsigned long)UWorld);

    // Controller → 自己 / Self
    uint64_t ctrl1 = pmem.read<uint64_t>(GWorld + 0x190);
    uint64_t ctrl2 = pmem.read<uint64_t>(ctrl1 + 0x38);
    uint64_t ctrl3 = pmem.read<uint64_t>(ctrl2 + 0x0);
    uint64_t Controller = pmem.read<uint64_t>(ctrl3 + 0x30);
    uint64_t Oneself = pmem.read<uint64_t>(Controller + 0x3A0);
    printf("[+] Controller=0x%lx Oneself=0x%lx\n",
           (unsigned long)Controller, (unsigned long)Oneself);

    // Actors 数组 / Actors array
    struct { uint64_t data; int32_t count; } Actors = {};
    pmem.read(UWorld + 0x1F0, &Actors, sizeof(Actors));
    printf("[+] Actors: data=0x%lx count=%d\n",
           (unsigned long)Actors.data, Actors.count);

    // 用 GName 类名过滤找玩家/人机角色
    // Filter by GName class: NC_BP_DFMCharacter_C / NC_BP_DFMCharacter_AI*
    uintptr_t Gname = ue4.base + 0x1A343A00;
    uint64_t testRootComp = 0;
    uint64_t testActorAddr = 0;
    int playerCount = 0;

    for (int i = 0; i < Actors.count && i < 500; i++) {
        uint64_t objAddr = pmem.read<uint64_t>(Actors.data + i * 8);
        if (objAddr == 0 || objAddr == Oneself) continue;
        if (objAddr < 0x1000000000ULL) continue;

        // 读取类名索引 (UObject + 0x1C)
        uint32_t nameIdx = pmem.read<uint32_t>(objAddr + 0x1C);
        std::string cls = GetClassName(pmem, Gname, nameIdx);

        // 调试: 打印前10个类名 / Debug: print first 10 class names
        if (playerCount < 10 && !cls.empty()) {
            printf("  [dbg] Actor[%d] 0x%lx cls=\"%s\"\n",
                   i, (unsigned long)objAddr, cls.c_str());
        }

        // 过滤: 玩家 NC_BP_DFMCharacter_C 或 AI NC_BP_DFMCharacter_AI*
        bool isPlayer = (cls == "NC_BP_DFMCharacter_C" ||
                         cls == "NC_BP_DFMCharacter_TutorialPlayerAi_C");
        bool isAI = (cls.find("NC_BP_DFMCharacter_AI") == 0 ||
                     cls.find("NC_BP_DFMAICharacter") == 0);
        // 也匹配包含 Character 的
        bool isCharacter = (cls.find("Character") != std::string::npos);
        if (!isPlayer && !isAI && !isCharacter) continue;

        // 玩家角色用 +0x3E0 双重指针读 RootComponent
        // Player characters use +0x3E0 double-pointer for RootComponent
        uint64_t rc = pmem.read<uint64_t>(objAddr + 0x3E0);
        uint64_t rcPtr = pmem.read<uint64_t>(rc);
        if (rc == 0 || rc < 0x1000000000ULL || rcPtr == 0) {
            // fallback 到 +0x180
            rc = pmem.read<uint64_t>(objAddr + 0x180);
        }
        if (rc == 0 || rc < 0x1000000000ULL) continue;

        playerCount++;

        // 读取加密状态和坐标
        uint8_t hdr[16] = {};
        pmem.read(rc + 0x168, hdr, 16);
        uint16_t encIdx = *(uint16_t*)(hdr + 0x0C);
        int8_t bEnc = *(int8_t*)(hdr + 0x0E);
        float xyz220[3] = {};
        pmem.read(rc + 0x220, xyz220, 12);

        const char* typeStr = isPlayer ? "玩家" : "AI";
        printf("  [%d] %s %s RC=0x%lx idx=0x%04X enc=%d xyz=(%.0f,%.0f,%.0f)\n",
               playerCount, typeStr, cls.c_str(), (unsigned long)rc,
               encIdx, (int)bEnc, xyz220[0], xyz220[1], xyz220[2]);

        // 优先选真正的玩家/AI角色作为测试目标
        if (testRootComp == 0 && (isPlayer || isAI)) {
            testRootComp = rc;
            testActorAddr = objAddr;
        }
    }

    printf("[+] 找到 %d 个角色\n", playerCount);

    // 读取自己的 TeamID 和 CampId 用于区分敌我
    // Read self TeamID/CampId for friend/foe filtering
    uint64_t selfTeamComp = pmem.read<uint64_t>(Oneself + 0x1090);
    int32_t selfTeamID = pmem.read<int32_t>(selfTeamComp + 0x108);
    int32_t selfCampId = pmem.read<int32_t>(selfTeamComp + 0x10C);
    printf("[+] 自己 TeamID=%d CampId=%d\n", selfTeamID, selfCampId);

    // === 自己 + 队友的坐标 (未加密, 做参考) ===
    printf("\n[*] === 参考坐标 (未加密) ===\n");
    // 自己
    {
        uint64_t selfRc = pmem.read<uint64_t>(Oneself + 0x3E0);
        if (selfRc == 0 || selfRc < 0x1000000000ULL)
            selfRc = pmem.read<uint64_t>(Oneself + 0x180);
        float selfPos[3] = {};
        pmem.read(selfRc + 0x168, selfPos, 12);
        float selfPos220[3] = {};
        pmem.read(selfRc + 0x220, selfPos220, 12);
        printf("  [自己] +168: X=%.1f Y=%.1f Z=%.1f\n", selfPos[0], selfPos[1], selfPos[2]);
        printf("         +220: X=%.1f Y=%.1f Z=%.1f\n", selfPos220[0], selfPos220[1], selfPos220[2]);
    }
    // 相机坐标 (ViewInfo)
    {
        uint64_t camMgr = pmem.read<uint64_t>(Controller + 0x408);
        if (camMgr > 0x1000000000ULL) {
            float camPos[3] = {};
            pmem.read(camMgr + 0x3540, camPos, 12);  // ViewInfo.Location
            printf("  [相机] X=%.1f Y=%.1f Z=%.1f\n", camPos[0], camPos[1], camPos[2]);
        }
    }
    // 遍历找队友
    for (int i = 0; i < Actors.count && i < 500; i++) {
        uint64_t objAddr = pmem.read<uint64_t>(Actors.data + i * 8);
        if (objAddr == 0 || objAddr == Oneself || objAddr < 0x1000000000ULL) continue;
        uint32_t ni = pmem.read<uint32_t>(objAddr + 0x1C);
        std::string cn = GetClassName(pmem, Gname, ni);
        if (cn != "NC_BP_DFMCharacter_C") continue;
        uint64_t tc = pmem.read<uint64_t>(objAddr + 0x1090);
        int32_t tid = (tc > 0x1000000000ULL) ? pmem.read<int32_t>(tc + 0x108) : -1;
        if (tid != selfTeamID || tid == 0) continue;
        // 是队友
        uint64_t rc = pmem.read<uint64_t>(objAddr + 0x3E0);
        if (rc == 0 || rc < 0x1000000000ULL) rc = pmem.read<uint64_t>(objAddr + 0x180);
        if (rc == 0) continue;
        float tp[3] = {}, tp2[3] = {};
        pmem.read(rc + 0x168, tp, 12);
        pmem.read(rc + 0x220, tp2, 12);
        // 名字
        uint64_t ps = pmem.read<uint64_t>(objAddr + 0x390);
        char tn[64] = "?";
        if (ps > 0x1000000000ULL) {
            uint64_t np = pmem.read<uint64_t>(ps + 0x470);
            if (np > 0x1000000000ULL) {
                uint16_t b16[16] = {};
                pmem.read(np, b16, sizeof(b16));
                char* p = tn;
                for (int k=0; k<16 && b16[k] && p<tn+60; k++) {
                    if (b16[k]<=0x7F) *p++=(char)b16[k];
                    else if (b16[k]<=0x7FF) { *p++=(char)((b16[k]>>6)|0xC0); *p++=(char)((b16[k]&0x3F)|0x80); }
                    else { *p++=(char)((b16[k]>>12)|0xE0); *p++=(char)(((b16[k]>>6)&0x3F)|0x80); *p++=(char)((b16[k]&0x3F)|0x80); }
                }
                *p=0;
            }
        }
        printf("  [队友] [%s] Team=%d +168: X=%.1f Y=%.1f Z=%.1f  +220: X=%.1f Y=%.1f Z=%.1f\n",
               tn, tid, tp[0], tp[1], tp[2], tp2[0], tp2[1], tp2[2]);
    }

    // === 帧循环解密测试 (10帧, 每帧间隔500ms) ===
    printf("\n[*] === 帧循环解密测试 (10帧) ===\n");

    // 先收集敌方玩家列表 (只收集一次)
    struct EnemyInfo { uint64_t actor; uint64_t rc; char name[64]; };
    std::vector<EnemyInfo> enemies;

    for (int i = 0; i < Actors.count && i < 500; i++) {
        uint64_t objAddr = pmem.read<uint64_t>(Actors.data + i * 8);
        if (objAddr == 0 || objAddr == Oneself || objAddr < 0x1000000000ULL) continue;
        uint32_t ni = pmem.read<uint32_t>(objAddr + 0x1C);
        std::string cn = GetClassName(pmem, Gname, ni);
        if (cn != "NC_BP_DFMCharacter_C") continue;
        uint64_t tc = pmem.read<uint64_t>(objAddr + 0x1090);
        int32_t tid = (tc > 0x1000000000ULL) ? pmem.read<int32_t>(tc + 0x108) : -1;
        if (tid == selfTeamID && tid != 0) continue; // 跳过队友
        uint64_t rc = pmem.read<uint64_t>(objAddr + 0x3E0);
        if (rc == 0 || rc < 0x1000000000ULL) rc = pmem.read<uint64_t>(objAddr + 0x180);
        if (rc == 0 || rc < 0x1000000000ULL) continue;
        EnemyInfo e; e.actor = objAddr; e.rc = rc;
        // 读名字
        uint64_t ps = pmem.read<uint64_t>(objAddr + 0x390);
        strcpy(e.name, "?");
        if (ps > 0x1000000000ULL) {
            uint64_t np = pmem.read<uint64_t>(ps + 0x470);
            if (np > 0x1000000000ULL) {
                uint16_t b16[16]={}; pmem.read(np,b16,sizeof(b16));
                char*p=e.name;
                for(int k=0;k<16&&b16[k]&&p<e.name+60;k++){
                    if(b16[k]<=0x7F)*p++=(char)b16[k];
                    else if(b16[k]<=0x7FF){*p++=(char)((b16[k]>>6)|0xC0);*p++=(char)((b16[k]&0x3F)|0x80);}
                    else{*p++=(char)((b16[k]>>12)|0xE0);*p++=(char)(((b16[k]>>6)&0x3F)|0x80);*p++=(char)((b16[k]&0x3F)|0x80);}
                }*p=0;
            }
        }
        enemies.push_back(e);
    }
    printf("[+] 找到 %zu 个敌方玩家\n\n", enemies.size());

    // 帧循环
    for (int frame = 0; frame < 10; frame++) {
        printf("--- 帧 %d ---\n", frame);

        // 自己坐标 (每帧刷新)
        uint64_t selfRc = pmem.read<uint64_t>(Oneself + 0x3E0);
        if (selfRc == 0 || selfRc < 0x1000000000ULL)
            selfRc = pmem.read<uint64_t>(Oneself + 0x180);
        float sp[3]={}; pmem.read(selfRc + 0x168, sp, 12);
        printf("  自己: X=%.0f Y=%.0f Z=%.0f\n", sp[0], sp[1], sp[2]);

        // 每个敌人解密
        for (auto& e : enemies) {
            // 重新读 RC (可能变化)
            uint64_t rc = pmem.read<uint64_t>(e.actor + 0x3E0);
            if (rc == 0 || rc < 0x1000000000ULL) rc = e.rc;

            InvalidateDataPages(rc, 0x400);
            CallARM64(decryptAddr, 1, (uint64_t)rc);

            float dx=0,dy=0,dz=0;
            uc_reg_read(GetEmulatorUc(), UC_ARM64_REG_S0, &dx);
            uc_reg_read(GetEmulatorUc(), UC_ARM64_REG_S1, &dy);
            uc_reg_read(GetEmulatorUc(), UC_ARM64_REG_S2, &dz);

            printf("  [%s] 解密: X=%.0f Y=%.0f Z=%.0f\n", e.name, dx, dy, dz);
        }
        printf("\n");
        usleep(500000); // 500ms
    }

    CleanupEmulator();
    printf("[+] Done.\n");
    return 0;
}
