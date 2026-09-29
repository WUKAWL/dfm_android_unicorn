# @Kernel_Hack — ACE 反作弊坐标解密 (Android ARM64)

**中文** | **[English](README_EN.md)**

**作者 / Author**: [@Kernel_Hack](https://github.com/libtersafe)
**协议 / License**: GPL v2 (与 Unicorn Engine 一致 / same as Unicorn Engine)

---

## 简介 / Introduction

通过 Unicorn Engine 模拟执行 ACE (安全组件) shellcode，解密游戏中被加密的玩家坐标。
纯用户态实现，所有底层操作通过 Linux syscall 完成，无需内核模块。

Decrypts player coordinates encrypted by ACE (Anti-Cheat Expert) shellcode
using Unicorn Engine emulation. Pure userspace implementation via Linux syscalls,
no kernel module required.

## 目录结构 / Project Structure

```
android_unicorn/
├── jni/
│   ├── sjz_dec_arm64.h        # 解密 API / Decrypt API
│   ├── sjz_dec_arm64.cpp      # Unicorn 模拟核心 / Emulation core
│   ├── memory_helper.h        # 进程内存读取+TLS / Memory read + TLS
│   ├── libc_stub.h            # 33个 libc 函数 stub / 33 libc stubs
│   ├── auto_finder_arm64.h/cpp # ARM64 地址扫描 / Address finder
│   ├── main.cpp               # 全自动入口 / Auto-discovery entry
│   ├── Android.mk             # NDK 构建规则 / Build rules
│   ├── Application.mk         # arm64-v8a, C++17
│   ├── include/unicorn/       # Unicorn Engine headers
│   └── libs/arm64-v8a/        # Unicorn static lib (.a)
├── README.md                  # 中文文档
└── README_EN.md               # English documentation
```

---

## 编译 / Build

**前提 / Prerequisites**: Android NDK r26d+

```bash
# 编译 / Build
ndk-build -j8 -B NDK_PROJECT_PATH=. NDK_APPLICATION_MK=jni/Application.mk

# 或使用 Windows 批处理 / Or use batch script
build.bat
```

**产物 / Output**:
- `libs/arm64-v8a/sjz_decrypt_arm64` — 可执行文件 / Executable
- `libs/arm64-v8a/libsjz_decrypt.so` — 共享库 / Shared library

---

## 运行 / Usage

```bash
adb push libs/arm64-v8a/sjz_decrypt_arm64 /data/local/tmp/
adb shell chmod +x /data/local/tmp/sjz_decrypt_arm64
adb shell su -c /data/local/tmp/sjz_decrypt_arm64
```

程序会自动完成以下步骤 / The program auto-discovers:
1. 扫描 `/proc/*/cmdline` 找到游戏 PID / Find game PID
2. 解析 `/proc/pid/maps` 找到 libUE4.so / Find libUE4.so
3. 扫描匿名 RWX 区域找到 ACE shellcode / Find ACE shellcode
4. 通过 `/proc/pid/task/*/comm` 找到 GameThread / Find GameThread
5. 通过 `ptrace` 获取 TPIDR_EL0 / Get TPIDR_EL0
6. 初始化 Unicorn 模拟器 / Initialize emulator
7. 调用解密 / Call decrypt

---

## 加密算法与模拟思路 / Encryption Algorithm & Emulation Approach

### ACE 加密机制 / ACE Encryption Mechanism

ACE (Anti-Cheat Expert) 通过以下方式加密玩家坐标:

1. **Hook libUE4.so**: ACE 在 `USceneComponent::SetRelativeLocation` 等函数处安装 hook
2. **BR X16 跳转**: hook 代码通过 `LDR X16, =shellcode_addr; BR X16` 跳入 shellcode
3. **Shellcode 加密**: 940KB 的 shellcode blob (mmap RWX) 包含 43 个 OLLVM CFF 混淆函数
4. **加密数据写入**: 加密后的坐标写入 `component + 0x210` 区域
5. **原始坐标被替换**: `component + 0x168` 的 FEncVector 包含加密标志

ACE encrypts player coordinates by:
1. Hooking `USceneComponent::SetRelativeLocation` in libUE4.so
2. Redirecting via `BR X16` to a 940KB RWX shellcode blob
3. The shellcode (43 OLLVM CFF-obfuscated functions) encrypts coordinates
4. Encrypted data written to `component + 0x210`
5. `FEncHandler` at `component + 0x174` marks encryption status

### 数据结构 / Data Structures

```cpp
// 来自 SDK dump v1.201.37110.44 / From SDK dump
struct FEncVector {          // size = 0x10
    float X, Y, Z;          // 0x00 - 明文坐标 / plain coords
    FEncHandler Handler;     // 0x0C - 加密控制器 / encryption handler
};

struct FEncHandler {         // size = 0x04
    uint16_t Index;          // 0x00 - 加密槽索引 / slot index
    int8_t   bEncrypted;     // 0x02 - 1=已加密 / 1=encrypted
    // bit0: bDynamic, bit1: bShareKey, bit2: bBitwiseCopyable
};

// USceneComponent 关键偏移 / Key offsets:
// 0x0168: FEncVector RelativeLocation
// 0x0174: FEncHandler (= RelativeLocation + 0x0C)
// 0x0210: ACE 加密数据区 / ACE encrypted data area
// AActor:
// 0x0180: USceneComponent* RootComponent
```

### Unicorn 模拟流程 / Emulation Flow

```
┌──────────────────────────────────────────────────┐
│  1. 从目标进程读取 shellcode (~940KB RWX 区域)      │
│     Read shellcode from target process memory      │
│                                                    │
│  2. 整块映射 shellcode 到 Unicorn + 解析 ELF 符号     │
│     Pre-map shellcode + resolve ELF symbols         │
│     (hash_direct_start / hash_end 等函数边界)        │
│                                                    │
│  3. 映射 libc.so 并安装 33 个函数 stub               │
│     Map libc.so and install 33 function stubs       │
│     (pthread_*, fopen, ioctl, sysconf...)           │
│                                                    │
│  4. 读取组件 FEncHandler 判断是否加密                 │
│     Read FEncHandler to check if encrypted          │
│                                                    │
│  5. 设置 ARM64 寄存器:                               │
│     X0 = component 指针                              │
│     X1 = 加密数据区地址                               │
│     LR = hash_end (到达即停止)                        │
│                                                    │
│  6. uc_emu_start(hash_direct_start, hash_end,       │
│                  timeout=500ms, count=0)             │
│     begin/until 精确范围 + timeout 兜底               │
│     (延迟页面映射处理所有内存访问)                      │
│                                                    │
│  7. 从 component + 0x168 读取解密后的坐标              │
│     Read decrypted Vector3 from component + 0x168   │
└──────────────────────────────────────────────────┘
```

### Shellcode 关键函数 / Key Shellcode Functions

| 偏移 / Offset | 用途 / Purpose | 栈帧 / Stack |
|:---:|------|:---:|
| `0x9E000` | 主解密函数 / Main decrypt | 0x290 |
| `0x50000` | 查找/解析函数 / Find/resolve | 0x200 |
| `0x510A0` | MurmurHash3 查找 / Hash lookup | 0x220 |

### libc 函数 Stub 列表 / Stubbed libc Functions

| 类别 / Category | 函数 / Functions | Stub 返回值 |
|------|------|:---:|
| 同步 / Sync | `pthread_mutex_*`, `pthread_once`, `__cxa_guard_*` | 0 |
| TLS | `pthread_key_create/delete/get/setspecific` | 0 |
| 文件 / File | `fopen`, `fclose`, `fgets`, `remove` | NULL/0 |
| 系统 / System | `sysconf` | 0x1000 |
| 系统 / System | `syscall`, `getpid`, `gettid`, `usleep` | 0/1 |
| 内存 / Memory | `munmap`, `mprotect`, `mincore` | 0/-1 |
| 设备 / Device | `ioctl` (GPU anti-debug) | 0 |
| 其他 / Other | `unsetenv`, `wmemset` | 0/NOP |

---

## 底层操作 / Low-Level Operations

所有操作通过 Linux syscall 实现，无需内核模块 / All via syscalls, no kernel needed:

| 操作 / Operation | 方式 / Method |
|------|------|
| 读取进程内存 | `syscall(__NR_process_vm_readv)` + `/proc/pid/mem` |
| 解析 maps | `fopen("/proc/pid/maps")` |
| 找 PID | `opendir("/proc")` + `cmdline` |
| 找 GameThread | `/proc/pid/task/*/comm` |
| 获取 TPIDR_EL0 | `ptrace(PTRACE_GETREGSET, NT_ARM_TLS)` |

---

## 许可证 / License

本项目采用 **GNU General Public License v2 (GPLv2)** 开源协议，与 Unicorn Engine 保持一致。

This project is licensed under the **GNU General Public License v2 (GPLv2)**, consistent with Unicorn Engine.

完整协议文本见: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html

---

## 免责声明 / Disclaimer

本项目仅供安全研究和学习用途。作者不对任何滥用行为负责。
使用本软件即表示您同意以下条款:

1. 本软件仅用于合法的安全研究、逆向工程学习和教育目的
2. 禁止将本软件用于任何违反法律法规的活动
3. 禁止将本软件用于破坏游戏公平性或损害其他玩家利益的行为
4. 作者不对因使用本软件造成的任何直接或间接损失承担责任
5. 使用者需自行承担使用本软件的一切风险和法律责任

---

## 致谢 / Credits

- **[@Kernel_Hack](https://github.com/libtersafe)** — 作者 / Author
- **Unicorn Engine** (GPLv2) — CPU 模拟框架 / CPU emulation framework
- **Capstone** — 反汇编引擎 / Disassembly engine (用于分析 / for analysis)
