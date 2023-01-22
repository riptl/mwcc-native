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
CFLAGS=

# Derive ELF target names from EXE names
ALL_EXES:=$(shell find exe -name '*.exe')
ALL_ELFS:=$(patsubst exe/%.exe,$(OUT)/%.elf,$(ALL_EXES))

ifeq ($(words $(ALL_EXES)),0)
$(warning No .exe files found in ./exe)
endif

.PHONY: all
all: $(ALL_ELFS)

$(OUT)/%.elf: $(OUT)/%.gen.bin.o $(OUT)/%.gen.str.o $(OUT)/compat.o | $(OUT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -static -no-pie -o $@ $^

$(OUT)/%.gen.str.o: $(OUT)/%.gen.str.c | $(OUT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -static -no-pie -c -o $@ $<

$(OUT)/%.gen.bin.o $(OUT)/%.gen.str.c: $(EXE)/%.exe $(PE2ELF) | $(OUT)
	@mkdir -p $(dir $@)
	$(PE2ELF) -i $< -o $(patsubst %.str.c,%.bin.o,$@) -out-cstr $(patsubst %.bin.o,%.str.c,$@) 

$(OUT)/compat.o: compat.c compat.h | $(OUT)
	$(CC) $(CFLAGS) -static -no-pie -c -o $@ $<

$(OUT)/pe2elf: $(shell find pe2elf -name '*.go') pe2elf/ordinals.csv | $(OUT)
	cd pe2elf && $(GO) build -o $(shell realpath $(OUT))/pe2elf -buildvcs=false .

$(OUT):
	mkdir -p $(OUT)

.PHONY: clean
clean:
	find $(OUT) \( -name "*.gen.*" -o -name "*.elf" \) -print -delete
