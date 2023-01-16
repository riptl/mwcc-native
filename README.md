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
- [ ] Runtime environment for entering Windows `main()`
- [ ] Implement console logging
- [ ] Implement file I/O
- ...

**Demo**

This demo requires `mwcceppc.exe` version `4199_60831`.

```
$ make
go build -o out/pe2elf pe2elf.go
./out/pe2elf -i mwcceppc.exe -o out/generated.o 2>/dev/null >/dev/null
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
