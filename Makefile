# Remove Make builtin junk
MAKEFLAGS+=--no-builtin-rules
.SUFFIXES:=

# Input EXE files
EXE=./exe

# Folder to place intermediate and target results in
OUT=./out

# GNU/Linux i686 toolchain with static libc support
TOOLCHAIN=./i686-linux-musl-native

# Compiler tools
OBJCOPY=$(TOOLCHAIN)/bin/objcopy
CC=$(TOOLCHAIN)/bin/gcc

# Script tools
GO=go
PE2ELF=$(OUT)/pe2elf

# Use flags
CFLAGS=-Werror=all

# Derive ELF target names from EXE names
ALL_EXES:=$(shell find -L exe -name '*.exe')
ALL_ELFS:=$(patsubst exe/%.exe,$(OUT)/%.elf,$(ALL_EXES))

ifeq ($(words $(ALL_EXES)),0)
$(warning No .exe files found in ./exe)
endif

.PHONY: all
all: $(ALL_ELFS)

$(OUT)/%.elf: $(OUT)/%.gen.bin.o $(OUT)/%.gen.str.o $(OUT)/%.gen.compat.o | $(OUT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -static -no-pie -o $@ $^

$(OUT)/%.gen.str.o: $(OUT)/%.gen.str.c | $(OUT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -static -no-pie -c -o $@ $<

$(OUT)/%.gen.bin.o: $(EXE)/%.exe $(PE2ELF) | $(OUT)
	@mkdir -p $(patsubst %.gen.bin.o,%,$@)
	$(PE2ELF) -i $< -o $@ -out-cstr $(patsubst %.bin.o,%.str.c,$@) -out-config $(patsubst %.gen.bin.o,%.gen.config.h,$@)

$(patsubst %.elf,%.gen.str.c,$(ALL_ELFS)): %.gen.str.c: %.gen.bin.o
$(patsubst %.elf,%.gen.config.h,$(ALL_ELFS)): %.gen.config.h: %.gen.bin.o

$(OUT)/%.gen.compat.o: compat.c compat.h $(OUT)/%.gen.config.h | $(OUT)
	$(CC) $(CFLAGS) -static -no-pie -c -include $(patsubst %.gen.compat.o,%.gen.config.h,$@) -o $@ $<

$(OUT)/pe2elf: $(shell find pe2elf -name '*.go') pe2elf/ordinals.csv | $(OUT)
	cd pe2elf && $(GO) build -o $(shell realpath $(OUT))/pe2elf -buildvcs=false .

$(OUT):
	mkdir -p "$(OUT)"

.PHONY: clean
clean:
	@if test -d "$(OUT)"; then find "$(OUT)" \( -name "*.elf" -o -name "*.o" -o -name "pe2elf" \) -print -delete; fi
	@if test -d "$(OUT)"; then find "$(OUT)" && find "$(OUT)" -type d -empty -print -delete; fi
