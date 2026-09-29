# ACE Shellcode 模拟执行工作流程
# ACE Shellcode Emulation Call Workflow

**作者 / Author**: @Kernel_Hack  https://github.com/libtersafe

---

## 总览 / Overview

```
┌─────────────────────────────────────────────────────────────┐
│  1. 找游戏进程 PID         (扫描 /proc/*/cmdline)            │
│  2. 找 libUE4.so 基址      (解析 /proc/pid/maps)            │
│  3. 找 GameThread TID      (扫描 /proc/pid/task/*/comm)     │
│  4. 获取 TPIDR_EL0         (ptrace PTRACE_GETREGSET)        │
│  5. 初始化 Unicorn 模拟器   (uc_ctl CPU model, 栈, 钩子, stub)│
│  6. 预映射 shellcode + ELF 符号解析 (函数边界定位)            │
│  7. 遍历 Actors 找敌方玩家  (GWorld→UWorld→Actors, GName)    │
│  8. 对每个敌人 call 解密     (hash_direct_start→hash_end)    │
│  9. 从 component+0x168 读取解密坐标 X/Y/Z                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 1: 找游戏进程 PID

```cpp
// 扫描 /proc/*/cmdline 匹配包名
pid_t pid = FindPid("com.tencent.tmgp.dfm");
// 实现: main.cpp FindPid()
// 方式: opendir("/proc") + fopen("cmdline") + strstr
```

---

## Step 2: 找 libUE4.so 基址

```cpp
// 解析 /proc/pid/maps
ModuleInfo ue4 = FindModule(pid, "libUE4.so");
// ue4.base = 0x7875349000 (示例)
// ue4.size = 0x1c483000
// 实现: libc_stub.h FindModule()
```

---

## Step 3-4: 找 GameThread + 获取 TPIDR_EL0

```cpp
// 扫描 /proc/pid/task/*/comm 找 "GameThread"
pid_t gameTid = ProcessMemory::findThreadByName(pid, "GameThread");

// ptrace 读取 TPIDR_EL0
uint64_t tpidr = ProcessMemory::getTpidrEL0(gameTid);
// tpidr = 0x78b95dfa80 (示例)
```

---

## Step 5: 初始化 Unicorn 模拟器

```cpp
GameOffsets offsets = {};
offsets.moduleBase = ue4.base;
InitEmulatorARM64(pid, offsets);
SetTpidrEL0(tpidr);
```

**初始化内容：**
- Unicorn ARM64 引擎 (`UC_ARCH_ARM64, UC_MODE_ARM`)
- `uc_ctl` 设置 CPU model (`UC_CPU_ARM64_MAX`) → 自动启用 NEON/FP
  - fallback: `CPACR_EL1.FPEN = 0b11`
- 256KB 栈 (`0x7000000000`)
- 返回桩 (`0x7100000000`: NOP + BRK #0)
- TLS 区域 (`0x7300000000`)
- 密文缓冲区 (`0x7200000000`)
- 3 个 Unicorn 钩子:
  - **Unmapped hook**: 延迟页面映射 (MTE tag 感知)
  - **Interrupt hook**: BRK 间接跳转处理
  - **Code hook**: MRS TPIDR_EL0 拦截 + trace
- 33 个 libc 函数 stub (pthread_*, fopen, ioctl, sysconf...)
- 预映射 shellcode (~940KB 整块写入 Unicorn)
- 解析 shellcode ELF 符号表 → 定位函数边界:
  - `hash_direct_start` → 解密函数 begin 地址
  - `hash_end` → 解密函数 until 地址
  - `entry`, `ring_calc_start`, `all_params_exec_end` 等

---

## Step 6: 遍历 Actors 找敌方玩家

```cpp
// 偏移来自绘制项目 drawing.h
uint64_t GWorld = read(libUE4 + 0x1a65ecc8);
uint64_t UWorld = read(GWorld + 0xF8);
uint64_t Controller = read(read(read(read(GWorld + 0x190) + 0x38) + 0x0) + 0x30);
uint64_t Oneself = read(Controller + 0x3A0);

// Actors 数组
struct { uint64_t data; int32_t count; } Actors;
read(UWorld + 0x1F0, &Actors, sizeof(Actors));

// GName 类名解析
uintptr_t Gname = libUE4 + 0x1A343A00;

for (int i = 0; i < Actors.count; i++) {
    uint64_t objAddr = read(Actors.data + i * 8);
    
    // 读类名索引并解密
    uint32_t nameIdx = read<uint32_t>(objAddr + 0x1C);
    std::string cls = GetClassName(Gname, nameIdx);
    // 名字解密: switch(len%9) 计算 key, XOR 每个字节
    
    // 过滤: 只要敌方玩家
    if (cls != "NC_BP_DFMCharacter_C") continue;
    if (objAddr == Oneself) continue;
    
    // 读 TeamID 判断敌我
    uint64_t teamComp = read(objAddr + 0x1090);
    int32_t teamID = read<int32_t>(teamComp + 0x108);
    if (teamID == selfTeamID) continue; // 跳过队友
    
    // 读 RootComponent (双重指针)
    uint64_t rootComp = read(objAddr + 0x3E0);
    // fallback: read(objAddr + 0x180)
}
```

**关键类名：**
| 类名 | 类型 |
|------|------|
| `NC_BP_DFMCharacter_C` | 玩家角色 |
| `NC_BP_DFMCharacter_AI_DT_C` | AI 普通兵 |
| `NC_BP_DFMCharacter_AI_DT_RPG_C` | AI RPG兵 |
| `NC_BP_DFMAICharacter_ShielderLight_C` | AI 盾兵 |
| `NC_BP_DFMAICharacter_HeavyMachineGun_C` | AI 重机枪 |

---

## Step 7-8: Call 解密函数

### 函数定位 (ELF 符号解析)

shellcode 本身是 ELF64 格式，包含符号表。初始化时通过双路径解析:
- **Path 1**: Section Headers → `.symtab` + `.strtab`
- **Path 2**: Program Headers → `PT_DYNAMIC` → `DT_SYMTAB` / `DT_STRTAB`

解析到的关键符号:
```
hash_direct_start  → 解密函数入口 (begin)
hash_end           → 解密函数边界 (until)
entry              → shellcode 总入口
ring_calc_start    → 环计算入口
all_params_exec_end → 全参数执行终点
```

### 原始代码 (hook前)
```asm
0xD1FBB98: LDR S0, [X0, #0x168]   ; 读 X 坐标
0xD1FBB9C: LDR S1, [X0, #0x16C]   ; 读 Y 坐标
0xD1FBBA0: LDR S2, [X0, #0x170]   ; 读 Z 坐标
0xD1FBBA4: RET
```

### Hook 后 (ACE shellcode)
```asm
0xD1FBB84: LDR X16, =0xb400007a0d5a14c8  ; shellcode 地址 (带 MTE tag)
0xD1FBB88: BR  X16                         ; 跳转到 shellcode
0xD1FBB8C: .quad 0xb400007a0d5a14c8        ; literal pool
```

### 调用方式 (PoP 风格)
```cpp
// 符号驱动: 直接调用 shellcode 内部函数, 精确 begin/until
uint64_t beginAddr = syms.hashDirectStart;   // ELF 符号解析得到
uint64_t untilAddr = syms.hashEnd;           // ELF 符号解析得到

// X0 = RootComponent, X1 = 加密数据区
// LR = hash_end (函数 RET 跳到 until → uc_emu_start 自动停止)
CallShellcodeFunc(beginAddr, untilAddr, rootComp, encAddr);

// 解密结果由 shellcode 直接写回 component 内存
// 从 component+0x168 读取解密后的坐标
Vector3 pos = RdVal<Vector3>(rootComp + 0x168);
```

**Fallback** (符号解析失败时):
```cpp
beginAddr = shellcodeBase + scDecryptFuncOff;  // 硬编码偏移
untilAddr = RET_STUB_ADDR;                     // 返回桩
```

### 执行流程
```
DecryptPosition(rootComp)
  │
  ├─ 读取 FEncHandler → 判断是否加密
  ├─ 未加密 → 直接返回 component+0x168 明文坐标
  │
  ├─ 已加密:
  │   ├─ beginAddr = hash_direct_start  (ELF 符号)
  │   ├─ untilAddr = hash_end           (ELF 符号)
  │   │
  │   ├─ CallShellcodeFunc(begin, until, rootComp, encAddr)
  │   │   ├─ ResetForCall()             // 清零寄存器, 设置 SP
  │   │   ├─ X0 = rootComp              // 组件指针
  │   │   ├─ X1 = encAddr               // 加密数据区
  │   │   ├─ LR = hash_end              // 到达即停止
  │   │   │
  │   │   ├─ uc_emu_start(begin=hash_direct_start,
  │   │   │               until=hash_end,
  │   │   │               timeout=500ms, count=0)
  │   │   │   │
  │   │   │   ├─ shellcode 已预映射 (init 时整块加载)
  │   │   │   ├─ [PAGE READ] 游戏对象数据页  // 延迟映射
  │   │   │   ├─ OLLVM CFF 调度器循环
  │   │   │   ├─ BRK → OnInterrupt 间接跳转解析
  │   │   │   ├─ 解密 → 写回 component+0x168
  │   │   │   └─ PC 到达 hash_end → 自动停止
  │   │   │
  │   │   └─ 返回
  │   │
  │   ├─ pos = read(component + 0x168)  // 读取解密坐标
  │   ├─ 异常检测 + 重试 (最多 20 次)
  │   └─ 返回 Vector3{X, Y, Z}
```

---

## Step 9: 结果

### 数据对比
```
                    内存 +0x168 (加密前)    解密后 +0x168         说明
自己 (未加密):   X=-28103 Z=924           -                     真实坐标
相机 (ViewInfo): X=-28076 Z=970           -                     与自己接近 ✓

敌人 (加密):     X=-26559 Z=-407          X=-86009 Z=231        内存是假坐标
                                                                shellcode 解密后写回
```

### 关键发现
- **加密前 +0x168** 存的是 ACE **加密后的假坐标**
- shellcode 解密后将 **真实坐标写回 component 内存**，从 +0x168 读取即可
- `bEncrypted` 标志位 (`+0x174`) 标记加密状态
- 加密坐标特征: Z 值为负数 (如 -407), 而真实 Z 应为正数 (如 231)
- 自己和队友的坐标不被加密, 只有敌方玩家被加密

---

## MTE Tag 处理

Android 12+ 使用 Memory Tagging Extension (MTE), 指针高字节含 tag:
```
shellcode 地址: 0xB400007a0d5a14c8
                ^^
                MTE tag = 0xB4

真实虚拟地址:   0x00007a0d5a14c8
```

在 `OnUnmapped` 延迟映射钩子中:
```cpp
uint64_t realPage = addr & 0x00FFFFFFFFFFFFFFULL;  // 去掉 MTE tag
ReadPageCached(realPage, buf);                       // 用真实地址读游戏内存
uc_mem_map(uc, page, ...);                          // 映射到带 tag 地址
```

---

## 每次 Call 前的页面清理

**关键**: 每次解密不同的 RootComponent 前必须清除 Unicorn 中的旧数据页映射,
否则上一次 call 的组件数据会污染当前 call。

shellcode 代码页在 init 时预映射，不参与清理:

```cpp
// InvalidateDataPages: 只清除指定范围的数据页, 跳过 shellcode 页
void InvalidateDataPages(uint64_t addr, size_t size) {
    for (每个覆盖的页面 p) {
        if (p 在 shellcode 范围内) continue;  // shellcode 页保持常驻
        uc_mem_unmap(uc, p, PAGE_SIZE);
        cache.erase(p);
    }
}

// InvalidatePageCache: 清除所有数据页, 保留 shellcode 页
void InvalidatePageCache() {
    for (auto it = cache.begin(); it != cache.end(); ) {
        if (shellcodeMapped && addr 在 shellcode 范围内) { ++it; continue; }
        uc_mem_unmap(uc, addr, PAGE_SIZE);
        it = cache.erase(it);
    }
}

// 使用:
for (每个敌人) {
    InvalidatePageCache();       // 清除旧数据页 (shellcode 保留)
    DecryptPosition(rootComp);   // 符号驱动的解密调用
}
```

---

## 安全性

- ✅ **完全只读** — 不写入游戏进程内存
- ✅ `process_vm_readv` — 只读 syscall
- ✅ `/proc/pid/mem` — `O_RDONLY` 模式打开
- ✅ Unicorn 写入 — 只在模拟器虚拟内存中, 不回传到游戏
- ⚠️ **不能** 使用 `process_vm_writev` 或写 `/proc/pid/mem`
- ⚠️ shellcode 的 STR 指令只写入 Unicorn 内存, 游戏进程不受影响

---

## 33 个 libc Stub

shellcode 调用的 libc 函数全部被 stub:

| 函数 | 返回值 | 原因 |
|------|:---:|------|
| `pthread_mutex_lock/unlock/init/destroy` | 0 | 避免死锁 |
| `pthread_key_create/delete/get/setspecific` | 0 | TLS 模拟 |
| `fopen/fclose/fgets` | NULL | 跳过文件检查 |
| `sysconf` | 0x1000 | 返回页面大小 |
| `syscall/getpid/gettid` | 0/1 | 假进程信息 |
| `ioctl` | 0 | 跳过 GPU anti-debug |
| `munmap/mprotect/mincore` | 0/-1 | 内存管理 |
| `usleep/unsetenv/wmemset` | 0 | 无操作 |

---

## 当前状态

| 项目 | 状态 |
|------|:---:|
| 自动找 PID | ✅ |
| 自动找 libUE4.so | ✅ |
| 自动找 GameThread | ✅ |
| TPIDR_EL0 获取 | ✅ |
| Unicorn 初始化 | ✅ |
| MTE tag 处理 | ✅ |
| libc stub (33个) | ✅ |
| GName 类名解密 | ✅ |
| Actor 遍历 + 敌我识别 | ✅ |
| 玩家名字读取 (UTF16→UTF8) | ✅ |
| shellcode 模拟执行 | ✅ |
| S0/S1/S2 坐标读取 | ✅ |
| 页面缓存清理 | ✅ |
| **解密精度验证** | ⚠️ 偏差较大, 待调试 |
