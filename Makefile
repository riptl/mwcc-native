OBJCOPY=/usr/local/opt/llvm/bin/llvm-objcopy
LD=/usr/local/opt/llvm/bin/ld.lld
CC=/usr/local/opt/llvm/bin/clang

out/mwcceppc.elf: mwcceppc.ld_broken out/generated.o out/compat.o out/i686-linux-musl-native
	$(LD) -static --no-pie -z execstack --build-id -T mwcceppc.ld -o $@ --verbose

out/compat.o: compat.c
	$(CC) -static -c -target i386-linux-gnu -o $@ $<

out/generated.o: out/pe2elf mwcceppc.exe
	./out/pe2elf -in mwcceppc.exe -out out/generated.o

out/pe2elf: pe2elf.go
	go build -o $@ $<

out/i686-linux-musl-native: out/i686-linux-musl-native.tgz
	tar -xf out/i686-linux-musl-native.tgz -C out

out/i686-linux-musl-native.tgz:
	curl -o $@ https://musl.cc/i686-linux-musl-native.tgz

.PHONY: clean
clean:
	rm -rf out
