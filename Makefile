TOOLCHAIN=./i686-linux-musl-native
OBJCOPY=$(TOOLCHAIN)/bin/objcopy
CC=$(TOOLCHAIN)/bin/gcc
CFLAGS=
OUT=./out
GO=go

$(OUT)/mwcceppc.elf: $(OUT)/generated.o $(OUT)/compat.o $(OUT)/genstr.o $(OUT)/main.o
	$(CC) $(CFLAGS) -static -no-pie -o $@ $^

$(OUT):
	mkdir -p $(OUT)

$(OUT)/main.o: main.c compat.h
	$(CC) $(CFLAGS) -static -no-pie -c -o $@ $<

$(OUT)/compat.o: compat.c compat.h
	$(CC) $(CFLAGS) -static -no-pie -c -o $@ $<

$(OUT)/genstr.o: $(OUT)/genstr.c
	$(CC) $(CFLAGS) -static -no-pie -c -o $@ $<

$(OUT)/generated.o $(OUT)/genstr.c: $(OUT)/pe2elf $(OUT) mwcceppc.exe mwcceppc_syms.txt
	$(OUT)/pe2elf -i mwcceppc.exe -o $(OUT)/generated.o -out-cstr $(OUT)/genstr.c -symbols mwcceppc_syms.txt -v=1

$(OUT)/pe2elf: $(wildcard pe2elf/*.go pe2elf/winres/*.go) pe2elf/ordinals.csv $(OUT)
	touch $@ && cd pe2elf && $(GO) build -o $(shell realpath $@) -buildvcs=false .

.PHONY: clean
clean:
	rm -rf $(OUT)
	mkdir -p $(OUT)
