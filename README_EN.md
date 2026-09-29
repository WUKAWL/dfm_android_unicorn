# @Kernel_Hack — ACE Anti-Cheat Coordinate Decryption (Android ARM64)

**[中文](README.md)** | **English**

**Author**: [@Kernel_Hack](https://github.com/libtersafe)
**License**: GPL v2 (same as Unicorn Engine)

---

## Introduction

Decrypts player coordinates encrypted by ACE (Anti-Cheat Expert) shellcode using Unicorn Engine emulation. Pure userspace implementation via Linux syscalls, no kernel module required.

## Project Structure

```
android_unicorn/
├── jni/
│   ├── sjz_dec_arm64.h/cpp    # Decrypt API + Unicorn emulation core
│   ├── memory_helper.h        # Process memory read + TLS via ptrace
│   ├── libc_stub.h            # 33 libc function stubs for shellcode
│   ├── auto_finder_arm64.h/cpp # ARM64 address pattern scanner
│   ├── main.cpp               # Auto-discovery entry point (zero args)
│   ├── Android.mk / Application.mk  # NDK build config
│   ├── include/unicorn/       # Unicorn Engine headers
│   └── libs/arm64-v8a/        # Unicorn static lib (.a)
├── README.md                  # 中文文档
└── README_EN.md               # English documentation
```

---

## Build

**Prerequisites**: Android NDK r26d+

```bash
ndk-build -j8 -B NDK_PROJECT_PATH=. NDK_APPLICATION_MK=jni/Application.mk
```

**Output**:
- `libs/arm64-v8a/sjz_decrypt_arm64` — Standalone executable
- `libs/arm64-v8a/libsjz_decrypt.so` — Shared library for integration

---

## Usage

```bash
adb push libs/arm64-v8a/sjz_decrypt_arm64 /data/local/tmp/
adb shell chmod +x /data/local/tmp/sjz_decrypt_arm64
adb shell su -c /data/local/tmp/sjz_decrypt_arm64
```

The program automatically:
1. Scans `/proc/*/cmdline` to find the game PID
2. Parses `/proc/pid/maps` to find libUE4.so base
3. Scans anonymous RWX regions to find ACE shellcode (~940KB)
4. Finds GameThread via `/proc/pid/task/*/comm`
5. Gets TPIDR_EL0 via `ptrace(PTRACE_GETREGSET, NT_ARM_TLS)`
6. Initializes Unicorn emulator with shellcode mapping
7. Ready to decrypt coordinates

---

## Encryption Algorithm & Emulation Approach

### ACE Encryption Mechanism

ACE (Anti-Cheat Expert) encrypts player coordinates through:

1. **Hook libUE4.so**: ACE installs hooks at `USceneComponent::SetRelativeLocation`
2. **BR X16 redirect**: Hook code uses `LDR X16, =shellcode_addr; BR X16` to jump into shellcode
3. **Shellcode encryption**: A 940KB RWX shellcode blob with 43 OLLVM CFF-obfuscated functions
4. **Encrypted data write**: Encrypted coordinates written to `component + 0x210`
5. **Flag marking**: `FEncHandler` at `component + 0x174` marks encryption status

### Data Structures (from SDK dump v1.201.37110.44)

```cpp
struct FEncVector {          // size = 0x10
    float X, Y, Z;          // 0x00 - plain coordinates
    FEncHandler Handler;     // 0x0C - encryption handler
};

struct FEncHandler {         // size = 0x04
    uint16_t Index;          // 0x00 - encryption slot index
    int8_t   bEncrypted;     // 0x02 - 1 = encrypted
    // bit0: bDynamic, bit1: bShareKey, bit2: bBitwiseCopyable
};

// USceneComponent key offsets:
// 0x0168: FEncVector RelativeLocation
// 0x0174: FEncHandler (= RelativeLocation + 0x0C)
// 0x0210: ACE encrypted data area
// AActor:
// 0x0180: USceneComponent* RootComponent
```

### Emulation Flow

```
1. Read shellcode (~940KB RWX region) from target process
2. Pre-map entire shellcode into Unicorn + resolve ELF symbols
   (hash_direct_start / hash_end for function boundaries)
3. Map libc.so and install 33 function stubs
   (pthread_*, fopen, ioctl, sysconf, etc.)
4. Read FEncHandler to check if encrypted
5. Set ARM64 registers:
   X0 = component pointer
   X1 = encrypted data area address
   LR = hash_end (stops when reached)
6. uc_emu_start(begin=hash_direct_start, until=hash_end,
   timeout=500ms, count=0)
   Precise range execution with timeout fallback
   (lazy page mapping handles all memory access)
7. Read decrypted Vector3 from component + 0x168
```

### Key Shellcode Functions

| Offset | Purpose | Stack Frame |
|:---:|------|:---:|
| `0x9E000` | Main decrypt function | 0x290 |
| `0x50000` | Find/resolve function | 0x200 |
| `0x510A0` | MurmurHash3 lookup | 0x220 |

### Stubbed libc Functions (33 total)

| Category | Functions | Return |
|------|------|:---:|
| Sync | `pthread_mutex_*`, `pthread_once`, `__cxa_guard_*` | 0 |
| TLS | `pthread_key_create/delete/get/setspecific` | 0 |
| File I/O | `fopen`, `fclose`, `fgets`, `remove` | NULL/0 |
| System | `sysconf` | 0x1000 |
| System | `syscall`, `getpid`, `gettid`, `usleep` | 0/1 |
| Memory | `munmap`, `mprotect`, `mincore` | 0/-1 |
| Device | `ioctl` (GPU anti-debug) | 0 |
| Other | `unsetenv`, `wmemset` | 0/NOP |

---

## Low-Level Operations

All operations via Linux syscalls, no kernel module needed:

| Operation | Method |
|------|------|
| Read process memory | `syscall(__NR_process_vm_readv)` + `/proc/pid/mem` |
| Parse maps | `fopen("/proc/pid/maps")` |
| Find PID | `opendir("/proc")` + `cmdline` |
| Find GameThread | `/proc/pid/task/*/comm` |
| Get TPIDR_EL0 | `ptrace(PTRACE_GETREGSET, NT_ARM_TLS)` |

---

## License

This project is licensed under the **GNU General Public License v2 (GPLv2)**, consistent with Unicorn Engine.

Full license text: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html

---

## Disclaimer

This project is for security research and educational purposes only. The author is not responsible for any misuse. By using this software, you agree to:

1. Use only for legitimate security research, reverse engineering study, and education
2. Not use for any activities that violate applicable laws or regulations
3. Not use to undermine game fairness or harm other players
4. The author bears no liability for any direct or indirect damages
5. You assume all risks and legal responsibilities from using this software

---

## Credits

- **[@Kernel_Hack](https://github.com/libtersafe)** — Author
- **Unicorn Engine** (GPLv2) — CPU emulation framework
- **Capstone** — Disassembly engine (for analysis)
