TOOLCHAIN=./i686-linux-musl-native
OBJCOPY=$(TOOLCHAIN)/bin/objcopy
CC=$(TOOLCHAIN)/bin/gcc

out/mwcceppc.elf: out/compat.o out/generated.o
	$(CC) -static -no-pie -o $@ $^

out/compat.o: compat.c
	$(CC) -static -no-pie -c -o $@ $^

out/generated.o: out/pe2elf mwcceppc.exe
	./out/pe2elf -i mwcceppc.exe -o out/generated.o

out/pe2elf: pe2elf.go
	go build -o $@ $<

.PHONY: clean
clean:
	rm -rf out
	mkdir -p out
