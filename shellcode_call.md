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
│  5. 初始化 Unicorn 模拟器   (ARM64, 栈, 钩子, libc stub)     │
│  6. 遍历 Actors 找敌方玩家  (GWorld→UWorld→Actors, GName)    │
│  7. 对每个敌人 call 解密函数 (libUE4+0xD1FBB84 → shellcode)  │
│  8. 读取 S0/S1/S2 寄存器    (真实解密坐标 X/Y/Z)             │
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
- 启用 NEON/FP (`CPACR_EL1.FPEN = 0b11`)
- 256KB 栈 (`0x7000000000`)
- 返回桩 (`0x7100000000`: NOP + BRK #0)
- TLS 区域 (`0x7300000000`)
- 密文缓冲区 (`0x7200000000`)
- 3 个 Unicorn 钩子:
  - **Unmapped hook**: 延迟页面映射 (MTE tag 感知)
  - **Interrupt hook**: BRK 间接跳转处理
  - **Code hook**: MRS TPIDR_EL0 拦截 + trace
- 33 个 libc 函数 stub (pthread_*, fopen, ioctl, sysconf...)

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

## Step 7: Call 解密函数

### 函数地址
```
libUE4.so + 0xD1FBB84
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

### 调用方式
```cpp
// X0 = RootComponent 指针
// LR = RET_STUB_ADDR (返回时停止模拟)
uint64_t ret = CallARM64(libUE4 + 0xD1FBB84, 1, rootComp);

// 读取解密后的坐标 (S0/S1/S2 = X/Y/Z)
float x, y, z;
uc_reg_read(uc, UC_ARM64_REG_S0, &x);  // 真实 X
uc_reg_read(uc, UC_ARM64_REG_S1, &y);  // 真实 Y
uc_reg_read(uc, UC_ARM64_REG_S2, &z);  // 真实 Z
```

### 执行流程
```
CallARM64(libUE4+0xD1FBB84, rootComp)
  │
  ├─ ResetForCall()           // 清零 X0-X28, 设置 SP, 清栈
  ├─ X0 = rootComp            // 设置参数
  ├─ LR = RET_STUB_ADDR       // 设置返回地址
  │
  ├─ uc_emu_start(PC=0xD1FBB84)
  │   │
  │   ├─ [PAGE FETCH] libUE4 页面   // 延迟映射 libUE4 代码页
  │   ├─ LDR X16, [PC+8]           // 加载 shellcode 地址
  │   ├─ BR X16                     // 跳转到 shellcode
  │   │
  │   ├─ [PAGE FETCH] shellcode 页面 // MTE tag 0xB4 → 去掉高字节
  │   │   // StripMteTag: 0xb400007a0d5a1000 → 0x7a0d5a1000
  │   │   // 从游戏进程读取真实 shellcode 代码
  │   │
  │   ├─ OLLVM CFF 调度器循环        // ~200条指令
  │   │   ├─ [PAGE READ] 游戏对象数据页  // 读取 RootComponent 数据
  │   │   ├─ [PAGE READ] vtable 页       // 读取函数指针表
  │   │   ├─ [PAGE READ] shellcode 数据页 // 读取加密参数
  │   │   ├─ BL 子函数                    // 调用内部解密子函数
  │   │   └─ 判断加密状态 → 解密 or 直接返回
  │   │
  │   ├─ 设置 S0=X, S1=Y, S2=Z     // 解密结果写入浮点寄存器
  │   ├─ RET → PC=RET_STUB_ADDR    // 返回到桩地址
  │   └─ BRK #0 → uc_emu_stop()    // 模拟停止
  │
  └─ uc_reg_read(S0/S1/S2)         // 读取解密坐标
```

---

## Step 8: 结果

### 数据对比
```
                    内存 +0x168      解密 S0/S1/S2       说明
自己 (未加密):   X=-28103 Z=924    -                    真实坐标
相机 (ViewInfo): X=-28076 Z=970    -                    与自己接近 ✓

敌人 (加密):     X=-26559 Z=-407   X=-86009 Z=231       内存是假坐标
                                                        S寄存器是真实坐标
```

### 关键发现
- **内存 +0x168 和 +0x220** 存的是 ACE **加密后的假坐标**
- **S0/S1/S2 寄存器** 返回的是 **真实解密坐标**
- `bEncrypted` 标志位 (`+0x174`) 始终为 0 — ACE 不使用这个标志
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

**关键**: 每次解密不同的 RootComponent 前必须清除 Unicorn 中的旧页面映射,
否则上一次 call 的组件数据会污染当前 call:

```cpp
void InvalidatePageCache() {
    for (auto& [addr, _] : cache) {
        uc_mem_unmap(uc, addr, PAGE_SIZE);  // 卸载 Unicorn 中的旧映射
    }
    cache.clear();
}

// 使用:
for (每个敌人) {
    InvalidatePageCache();  // 清除旧数据
    CallARM64(decryptAddr, 1, rootComp);
    // 读 S0/S1/S2
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
