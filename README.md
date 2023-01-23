# MWCC on Linux

This project converts several Windows-only Metrowerks CodeWarrior tools into static Linux executables.

### Requirements

- 32-bit x86 GCC toolchain with musl libc
  - Bundled via Git LFS at `./i686-linux-musl-native.tgz`
  - Via [musl.cc](https://more.musl.cc/11/i686-linux-musl/i686-linux-musl-native.tgz)
- Recent version of Go (for `pe2elf.go`)
  - Go 1.16 and above is known to work
  - No external dependencies :)

### Status

This integration is about 30% done.
- [x] PE to ELF conversion
- [x] ELF relocations
- [x] Scaffold for compatibility module containing Windows library calls
- [x] Demo 
- [ ] PE symbol maps
- [x] Runtime environment for entering Windows `main()`
- [x] Implement console logging
- [ ] Implement file I/O
- ...

### Support Matrix

File I/O not yet implemented, so no compiler conversion is functional yet.

Checking if the `-help` page works is useful for checking runtime compatibility.

| Target | Tool        | Version         | Runtime Built       | `-help`    |
|--------|-------------|-----------------|---------------------|------------|
| EPPC   | `mwasmeppc` | 2.3.2 build 106 | 2000-06-02 15:30:53 | ☠️ SIGSEGV |
| EPPC   | `mwldeppc`  | 2.3.3 build 126 | 2000-03-21 19:00:24 | ❌ assert   |
| EPPC   | `mwldeppc`  | 2.3.3 build 137 | 2001-02-07 12:15:53 | ❌ assert   |
| EPPC   | `mwcceppc`  | 2.3.3 build 144 | 2000-04-13 14:30:41 | ❌ assert   |
| EPPC   | `mwcceppc`  | 2.3.3 build 159 | 2001-02-07 12:08:38 | ❌ assert   |
| EPPC   | `mwcceppc`  | 2.3.3 build 163 | 2001-04-23 10:58:30 | ❌ assert   |
| EPPC   | `mwldeppc`  | 2.4.1 build 47  | 2001-06-12 11:53:24 | ?          |
| EPPC   | `mwcceppc`  | 2.4.2 build 81  | 2002-05-07 23:39:33 | ?          |
| EPPC   | `mwldeppc`  | 2.4.2 build 81  | 2002-05-07 23:43:34 | ?          |
| EPPC   | `mwcceppc`  | 2.4.2 build 92  | 2002-09-16 15:14:48 | ✅          |
| EPPC   | `mwldeppc`  | 2.4.7 build 92  | 2002-09-16 15:15:26 | ?          |
| EPPC   | `mwcceppc`  | 2.4.7 build 102 | 2002-11-07 12:45:57 | ✅          |
| EPPC   | `mwcceppc`  | 2.4.7 build 105 | 2003-02-20 14:21:02 | ✅          |
| EPPC   | `mwcceppc`  | 2.4.7 build 107 | 2003-07-14 14:19:11 | ?          |
| EPPC   | `mwldeppc`  | 2.4.7 build 107 | 2003-07-14 14:20:31 | ?          |
| EPPC   | `mwcceppc`  | 2.4.7 build 108 | 2004-07-22 17:19:15 | ?          |
| EPPC   | `mwldeppc`  | 3.0.4           | 2004-08-13 10:40:59 | ?          |
| EPPC   | `mwasmeppc` | 4.0 build 50315 | 2005-03-15 23:48:10 | ?          |
| EPPC   | `mwldeppc`  | 4.1 build 51213 | 2005-12-13 17:41:17 | ?          |
| EPPC   | `mwcceppc`  | 4.1 build 60126 | 2006-01-26 08:43:54 | ?          |
| EPPC   | `mwcceppc`  | 4.1 build 60831 | 2006-08-31 18:18:06 | ?          |
| EPPC   | `mwasmeppc` | 4.2 build 142   | 2008-08-26 02:27:18 | ☠️ SIGSEGV |
| EPPC   | `mwcceppc`  | 4.2 build 142   | 2008-08-26 02:32:39 | ✅          |
| EPPC   | `mwldeppc`  | 4.2 build 142   | 2008-08-26 02:33:56 | ✅          |
| EPPC   | `mwasmeppc` | 4.2 build 60320 | 2006-03-20 23:12:52 | ?          |
| EPPC   | `mwldeppc`  | 4.2 build 60320 | 2006-03-20 23:19:16 | ?          |
| EPPC   | `mwasmeppc` | 4.3 build 151   | 2009-04-02 14:58:50 | ☠️ SIGILL  |
| EPPC   | `mwcceppc`  | 4.3 build 151   | 2009-04-02 15:04:17 | ✅          |
| EPPC   | `mwldeppc`  | 4.3 build 151   | 2009-04-02 15:05:36 | ✅          |
| EPPC   | `mwasmeppc` | 4.3 build 172   | 2010-04-23 11:35:15 | ☠️ SIGSEGV |
| EPPC   | `mwcceppc`  | 4.3 build 172   | 2010-04-23 11:38:37 | ✅          |
| EPPC   | `mwldeppc`  | 4.3 build 172   | 2010-04-23 11:39:30 | ✅          |
| EPPC   | `mwasmeppc` | 4.3 build 213   | 2011-09-05 12:57:32 | ☠️ SIGSEGV |
| EPPC   | `mwcceppc`  | 4.3 build 213   | 2011-09-05 13:01:10 | ✅          |
| EPPC   | `mwldeppc`  | 4.3 build 213   | 2011-09-05 13:02:03 | ✅          |

**Demo**

This demo requires `mwcceppc.exe` version `4199_60831`.

```
$ make
go build -o out/pe2elf pe2elf.go
./out/pe2elf -i mwcceppc.exe -o out/generated.o
./i686-linux-musl-native/bin/gcc -static -no-pie -c -o out/compat.o compat.c
./i686-linux-musl-native/bin/gcc -static -no-pie -o out/mwcceppc.elf out/generated.o out/compat.o
```

```
$ ./out/mwcceppc.elf
__builtin_return_address() = 0x828cea6
__pe_text_start       = 0x804820f
__pe_data_start       = 0x82a7024
__pe_data_idata_start = 0x830d424
KERNEL32_EnterCriticalSection(0x8344af4)
KERNEL32_GlobalAlloc(0, 65544)
KERNEL32_LeaveCriticalSection(0x8344af4)
It works!
```

In the above snipppet, the following happens:
- Standard GNU/Linux program initialization with musl libc (crt, main)
- `main` prints the addresses of various PE sections in memory
- `main` invokes function at PE vaddr 0x4031b0, entering Win32 land
  (I have no idea what this function is supposed to do)
- `0x4031b0` does a bunch of `KERNEL32` function calls
- `0x4031b0` returns to main
- No crashes, so no memory was grossly violated!

### Internals

The CodeWarrior tools we have access to are fairly basic 32-bit Windows NT PE files.

### pe2elf

The `pe2elf.go` script extracts sections, relocations, and imports from a PE file, and generates a relocatable ELF object.
The Go programming language was chosen because its standard library happens to have great support for both file formats.

For an explanation of the tool's internals, refer to code comments.

### Toolchain

We then use an i686-linux-gnu musl GCC toolchain to compile a compatibility module (similar to winelib) and link everything together into a static executable.
The resulting executable is non-relocatable.

### ELF layout

**Sections**

Copying sections is straightforward.

Typically, binaries contain the following sections.

| PE       | ELF           | Purpose                 |
|----------|---------------|-------------------------|
| `.text`  | `.text`       | Executable i686 code    |
| `.data`  | `.data`       | Read-write data         |
| `.rdata` | `.rodata`     | Read-only data          |
| `.idata` | `.data.idata` | PE Import Address Table |
| `.bss`   | `.bss`        | Zero-initialized data   |
| `.reloc` | `.rel.*`      | Relocation Tables       |

**Imports**

The absolute virtual addresses of imported functions are written into the Import Address Table located in section `.idata`.

This can be trivially modelled in ELF by emitting `R_386_32` relocations against undefined symbols.

**Code Relocations**

Code relocations are technically optional if the ELF linker can ensure that none of the PE sections get shifted.

In practice however, creating executable ELFs with custom segments at specific addresses
with any modern compiler or libc requires a massive linker script and several sleepless nights of staring at radare2.
Yes, I'm sure some fancy tool out there can do it, but who's going to maintain that?

It ended up being easier just implementing a PE reloc table walk and generating a `R_386_32` relocs.
For now, the program generates a large amount of global symbols for this (one for each reloc target).
In the future, this can be improved by only using symbols that point to the beginning to a section and fixup via implicit addend.

### Runtime and ABI

**Intro**

Obviously, we are not done with just converting a PE file to an ELF.
You can try running it, but your program is going to segfault about 4 instructions in when it tries to read from the `fs` segment.

The code, still believing it is running under Windows, will try to access the
Thread Information Block (TIB) to get some basic data about the process environment.

On Linux, process initialization works completely differently and there is no TIB.

This is just one of the many runtime differences that will have to be taken care of.
Figurately, machine code is about doing arithmetic while confidently jumping across a mine field while blindfolded.
This is fine when you've memorized the safe paths. But Linux is a different mine field and you still think you're running under Windows.

Modifying the source machine code is not time-effective.
Thus, our strategy is to strategically relocate mines to vaguely resemble a Windows environment.
We don't aim to fully reimplement a Windows runtime (Wine already exists), but just enough to get a program running fairly reliably.

**Patching**

The aforementioned `fs` register issue is nontrivial.

IA-32 does not allow writing to the segment register in an unprivileged context.
Running code with kernel privileges is obviously not an option either.

The fix involves slightly modifying machine code in the `pe2elf` conversion.

We can just patch instructions using `fs:[0]` to `ds:[0]` and then emit a relocation to patch up the offset to `ds:[__pe__tib]`.

On the machine code level, this involves replacing the `0x64` instruction prefix (setting the segment to `fs`) with `0x90` (the nop instruction).

For example

```
64 a1 00000000   mov eax, dword [fs:0x0]
```

becomes

```
90               nop
a1 00000000      mov eax, dword [ds:0x0]
```

Note that `pe2elf` implements this patching feature in a brittle/hacky way.

- The TIB is thread-local, but this new data structure is now shared across threads.
  This breaks any multi-threaded applications.
- No disassemblers used, just binary search replace.
- Only the first few kBs of `.text` are covered by patching to avoid false positives.

**Runtime**

WIP

**System**

One aspect of the environment which cannot easily be changed is machine code that directly interfaces with the kernel, i.e. syscalls.
Luckily, Windows applications rarely use interrupt/syscall instructions directly.
Instead, everything goes through dynamically linked libraries like `KERNEL32.dll`.

We can "simply" mock those library calls and overwrite the corresponding Import Address Table entries.

**ABI**

ABI broadly refers to the assumptions that code makes when interfacing with subroutines and data in memory.

This area has been standardized somewhat:
Function calling conventions used in Windows such as *stdcall*, *cdecl* are supported by GCC on GNU/Linux.

Mixing Win32 and SysV-ABI C code works fine for basic operations like function calls (e.g. no severe stack layout errors).

Unwinding and backtracing is obviously undefined behavior though:

Any unwinding code in Win32 will choke on SysV stack frames at the top,
Inversely, the `compat.c` DLL functions will fail to unwind Win32 stack frames.
The latter can probably be fixed though by modifying libunwind.s

### Background

CodeWarrior is set of tools for compiling C/C++ code for PowerPC.

We use these tools to reverse engineer various GameCube-era games.
We do this to preserve games from when we were younger for future generations,
as the underlying hardware is slowly dying out.

For example, a number of "decompile" projects are painstakingly reconstructing
the source code of various GameCube/Wii games, that when compiled with specific CodeWarrior versions
result in byte-to-byte identical machine code as the original game.

Through the course of various company acquisitions,
the original source code of the CodeWarrior PowerPC-EABI tools is believed to be lost.

What we have is a small handful of Windows-only binaries.
Running those under Wine works, but creating native executables makes things easier.

This method also allows arbitrarily modding those tools to work around bugs,
or sometimes even adding back patched compiler bugs.

Then, there's also the method itself.
Running Windows programs *natively* under Linux, isn't that nice?

---------------------------------------------------------------------

*2023 by Richard Patel*
