package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {
	inPath := flag.String("in", "", "Input file")
	outPath := flag.String("out", "out.elf", "Output file")
	flag.Parse()

	log.Default().SetFlags(0)

	peFile, err := pe.Open(*inPath)
	if err != nil {
		log.Fatal(err)
	}
	defer peFile.Close()

	outFile, err := os.Create(*outPath)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	peOpt := peFile.OptionalHeader.(*pe.OptionalHeader32)
	baseVaddr := peOpt.ImageBase
	log.Printf("Base vaddr:   %#x", baseVaddr)

	entryVaddr := baseVaddr + peOpt.AddressOfEntryPoint
	log.Printf("Entry vaddr:  %#x", entryVaddr)

	var writer elfWriter
	if err := writer.init(outFile); err != nil {
		log.Fatal(err)
	}
	writer.hdr.Entry = entryVaddr

	peText := peFile.Section(".text")
	rawText := peText.Open()
	log.Printf("Text vaddr:   %#x", baseVaddr+peText.VirtualAddress)
	if err := writer.writeText(rawText, peText.VirtualAddress); err != nil {
		log.Fatal(err)
	}

	peRodata := peFile.Section(".rdata")
	rawRodata := peRodata.Open()
	log.Printf("Rodata vaddr: %#x", baseVaddr+peRodata.VirtualAddress)
	if err := writer.writeRodata(rawRodata, peRodata.VirtualAddress); err != nil {
		log.Fatal(err)
	}

	peData := peFile.Section(".data")
	rawData := peData.Open()
	log.Printf("Data vaddr:   %#x", baseVaddr+peData.VirtualAddress)
	if err := writer.writeData(rawData, peData.VirtualAddress); err != nil {
		log.Fatal(err)
	}

	peIdata := peFile.Section(".idata")
	rawIdata := peIdata.Open()
	log.Printf("Idata vaddr:  %#x", baseVaddr+peIdata.VirtualAddress)
	if err := writer.writeIdata(rawIdata, peIdata.VirtualAddress); err != nil {
		log.Fatal(err)
	}

	peBss := peFile.Section(".bss")
	log.Printf("Bss vaddr:    %#x", baseVaddr+peBss.VirtualAddress)
	writer.addBss(peBss.VirtualSize, peBss.VirtualAddress)

	//peRelocs := peFile.Section(".reloc")
	//readRelocs(peRelocs)

	idd := peOpt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	var ds *pe.Section
	ds = nil
	for _, s := range peFile.Sections {
		if s.VirtualAddress <= idd.VirtualAddress && idd.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			ds = s
			break
		}
	}
	if ds == nil {
		log.Fatal("could not find section containing import directory table")
	}
	d, err := ds.Data()
	if err != nil {
		log.Fatal(err)
	}
	d = d[idd.VirtualAddress-ds.VirtualAddress:]

	// start decoding the import directory
	var imps []imp
	var ida []pe.ImportDirectory
	for len(d) >= 20 {
		var dt pe.ImportDirectory
		dt.OriginalFirstThunk = binary.LittleEndian.Uint32(d[0:4])
		dt.TimeDateStamp = binary.LittleEndian.Uint32(d[4:8])
		dt.ForwarderChain = binary.LittleEndian.Uint32(d[8:12])
		dt.Name = binary.LittleEndian.Uint32(d[12:16])
		dt.FirstThunk = binary.LittleEndian.Uint32(d[16:20])
		d = d[20:]
		if dt.OriginalFirstThunk == 0 {
			break
		}
		ida = append(ida, dt)
	}
	names, _ := ds.Data()
	dlls := make([]string, len(ida))
	for i, dt := range ida {
		dlls[i], _ = getString(names, int(dt.Name-ds.VirtualAddress))
		d, _ = ds.Data()
		// seek to OriginalFirstThunk
		d = d[dt.OriginalFirstThunk-ds.VirtualAddress:]
		targetAddr := baseVaddr + dt.FirstThunk
		for len(d) > 0 {
			va := binary.LittleEndian.Uint32(d[0:4])
			d = d[4:]
			if va == 0 {
				break
			}
			fn, _ := getString(names, int(va-ds.VirtualAddress+2))
			if fn == "" {
				fn = fmt.Sprintf("%x", targetAddr)
			}
			imp_ := imp{
				name:  strings.TrimSuffix(dlls[i], ".dll") + "_" + fn,
				vaddr: targetAddr,
			}
			imps = append(imps, imp_)
			log.Printf("Import at %#x %s!%s as %s", targetAddr, dlls[i], fn, imp_.name)
			targetAddr += 4
		}
	}

	if err := writer.writeIdataRelocs(imps, peIdata, baseVaddr); err != nil {
		log.Fatal(err)
	}

	if err := writer.writeImportedSyms(imps); err != nil {
		log.Fatal(err)
	}

	if err := writer.finish(); err != nil {
		log.Fatal(err)
	}
}

type imp struct {
	name  string
	vaddr uint32
}

func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}
	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}

func readRelocs(s *pe.Section) {
	rd := s.Open()
	for {
		var hdr struct {
			PageRVA   uint32
			BlockSize uint32
		}
		if err := binary.Read(rd, binary.LittleEndian, &hdr); err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		if hdr.PageRVA == 0 {
			break
		}
		log.Printf("Reloc block: %#x", hdr.PageRVA)
		for i := uint32(0); i < hdr.BlockSize-8; i += 2 {
			var reloc uint16
			if err := binary.Read(rd, binary.LittleEndian, &reloc); err != nil {
				log.Fatal(err)
			}
			if reloc == 0 {
				break
			}
			relocType := reloc >> 12
			relocOffset := reloc & 0xfff
			if relocType != 3 {
				log.Printf("unsupported reloc type: " + strconv.Itoa(int(relocType)))
				continue
			}
			log.Printf("Reloc (%d): %#x", relocType, relocOffset)
		}
	}
}

type elfWriter struct {
	hdr      elf.Header32
	wr       io.ReadWriteSeeker
	sections []elf.Section32

	shstrtab bytes.Buffer
	strtab   bytes.Buffer
}

func (e *elfWriter) pos() uint32 {
	x, err := e.wr.Seek(0, io.SeekCurrent)
	if err != nil {
		panic(err)
	}
	return uint32(x)
}

func (e *elfWriter) align(n uint32) error {
	pos := e.pos()
	if pos%n != 0 {
		_, err := e.wr.Seek(int64(n-(pos%n)), io.SeekCurrent)
		return err
	}
	return nil
}

func (e *elfWriter) init(wr io.ReadWriteSeeker) error {
	e.wr = wr
	e.strtab.WriteByte(0)
	e.shstrtab.WriteByte(0)
	e.hdr = elf.Header32{
		Ident: [elf.EI_NIDENT]byte{
			elf.ELFMAG[0], elf.ELFMAG[1], elf.ELFMAG[2], elf.ELFMAG[3],
			byte(elf.ELFCLASS32),
			byte(elf.ELFDATA2LSB),
			byte(elf.EV_CURRENT),
			0, // ELFOSABI_SYSV
		},
		Type:    uint16(elf.ET_REL),
		Machine: uint16(elf.EM_386),
		Version: uint32(elf.EV_CURRENT),
		Ehsize:  uint16(binary.Size(e.hdr)),
	}
	e.sections = []elf.Section32{{}}
	return binary.Write(wr, binary.LittleEndian, &e.hdr)
}

func (e *elfWriter) writeText(rd io.Reader, vaddr uint32) error {
	return e.copySection(rd, ".text", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC) | uint32(elf.SHF_EXECINSTR),
		Addr:  vaddr,
	})
}

func (e *elfWriter) writeRodata(rd io.Reader, vaddr uint32) error {
	return e.copySection(rd, ".rodata", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC),
		Addr:  vaddr,
	})
}

func (e *elfWriter) writeData(rd io.Reader, vaddr uint32) error {
	return e.copySection(rd, ".data", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC) | uint32(elf.SHF_WRITE),
		Addr:  vaddr,
	})
}

func (e *elfWriter) writeIdata(rd io.Reader, vaddr uint32) error {
	return e.copySection(rd, ".idata", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC),
		Addr:  vaddr,
	})
}

func (e *elfWriter) addBss(size uint32, vaddr uint32) {
	e.sections = append(e.sections, elf.Section32{
		Name:  e.addShstr(".bss"),
		Type:  uint32(elf.SHT_NOBITS),
		Flags: uint32(elf.SHF_ALLOC) | uint32(elf.SHF_WRITE),
		Size:  size,
		Addr:  vaddr,
	})
}

func (e *elfWriter) copySection(rd io.Reader, name string, sec elf.Section32) error {
	if err := e.align(0x100); err != nil {
		return err
	}

	atStart := e.pos()
	n, err := io.Copy(e.wr, rd)
	if err != nil {
		return err
	}
	atEnd := atStart + uint32(n)

	sec.Name = e.addShstr(name)
	sec.Off = atStart
	sec.Size = atEnd - atStart
	sec.Addralign = 1
	e.sections = append(e.sections, sec)

	return nil
}

// addShstr adds a string to the section header string table.
func (e *elfWriter) addShstr(s string) uint32 {
	addr := uint32(e.shstrtab.Len())
	e.shstrtab.WriteString(s)
	e.shstrtab.WriteByte(0)
	return addr
}

// addStr adds a string to the string table.
func (e *elfWriter) addStr(s string) uint32 {
	addr := uint32(e.strtab.Len())
	e.strtab.WriteString(s)
	e.strtab.WriteByte(0)
	return addr
}

// writeShstrtab writes the .shstrtab section (section header string table).
func (e *elfWriter) writeShstrtab() error {
	e.hdr.Shstrndx = uint16(len(e.sections))
	selfName := e.addShstr(".shstrtab")

	atStart := e.pos()
	if _, err := io.Copy(e.wr, &e.shstrtab); err != nil {
		return err
	}
	e.shstrtab.Reset()
	atEnd := e.pos()

	sec := elf.Section32{
		Name: selfName,
		Type: uint32(elf.SHT_STRTAB),
		Off:  atStart,
		Size: atEnd - atStart,
	}
	e.sections = append(e.sections, sec)

	return nil
}

// writeStrtab writes the .strtab section (string table).
func (e *elfWriter) writeStrtab() error {
	atStart := e.pos()
	if _, err := io.Copy(e.wr, &e.strtab); err != nil {
		return err
	}
	e.strtab.Reset()
	atEnd := e.pos()

	sec := elf.Section32{
		Name: e.addShstr(".strtab"),
		Type: uint32(elf.SHT_STRTAB),
		Off:  atStart,
		Size: atEnd - atStart,
	}
	e.sections = append(e.sections, sec)

	return nil
}

// writeShtab writes the section header table.
func (e *elfWriter) writeShtab() error {
	atStart := e.pos()
	buf := bufio.NewWriter(e.wr)
	for _, sec := range e.sections {
		if err := binary.Write(buf, binary.LittleEndian, &sec); err != nil {
			return err
		}
	}
	if err := buf.Flush(); err != nil {
		return err
	}

	e.hdr.Shoff = atStart
	e.hdr.Shentsize = uint16(binary.Size(elf.Section32{}))
	e.hdr.Shnum = uint16(len(e.sections))
	return nil
}

func (e *elfWriter) writeIdataRelocs(imps []imp, idata *pe.Section, baseVaddr uint32) error {
	atStart := e.pos()
	buf := bufio.NewWriter(e.wr)
	sectionVA := baseVaddr + idata.VirtualAddress
	for i, imp := range imps {
		// Ensure import target is within idata
		impRVA := imp.vaddr - baseVaddr
		if impRVA < idata.VirtualAddress || impRVA >= idata.VirtualAddress+idata.VirtualSize {
			continue
		}

		// Write relocation
		rel := elf.Rel32{
			Off:  imp.vaddr - sectionVA,
			Info: elf.R_INFO32(uint32(i), uint32(elf.R_386_32)),
		}
		if err := binary.Write(buf, binary.LittleEndian, &rel); err != nil {
			return err
		}
	}
	if err := buf.Flush(); err != nil {
		return err
	}
	atEnd := e.pos()

	// Write section header
	e.sections = append(e.sections, elf.Section32{
		Name:    e.addShstr(".rel.idata"),
		Type:    uint32(elf.SHT_REL),
		Off:     atStart,
		Size:    atEnd - atStart,
		Link:    uint32(len(e.sections) + 1), // .symtab
		Info:    uint32(len(e.sections) - 2), // .idata
		Entsize: uint32(binary.Size(elf.Rel32{})),
	})
	return nil
}

func (e *elfWriter) writeImportedSyms(imps []imp) error {
	atStart := e.pos()
	buf := bufio.NewWriter(e.wr)
	if err := binary.Write(buf, binary.LittleEndian, &elf.Sym32{}); err != nil {
		return err
	}
	for _, imp := range imps {
		sym := elf.Sym32{
			Name:  e.addStr(imp.name),
			Info:  elf.ST_INFO(elf.STB_GLOBAL, elf.STT_NOTYPE),
			Other: uint8(elf.STV_DEFAULT),
			Shndx: uint16(elf.SHN_UNDEF),
		}
		if err := binary.Write(buf, binary.LittleEndian, &sym); err != nil {
			return err
		}
	}
	if err := buf.Flush(); err != nil {
		return err
	}
	atEnd := e.pos()

	sec := elf.Section32{
		Name:    e.addShstr(".symtab"),
		Type:    uint32(elf.SHT_SYMTAB),
		Off:     atStart,
		Size:    atEnd - atStart,
		Entsize: uint32(binary.Size(elf.Sym32{})),
		Link:    uint32(len(e.sections) + 1), // .strtab follows symtab
		Info:    1,
	}
	e.sections = append(e.sections, sec)

	return nil
}

func (e *elfWriter) finish() error {
	if err := e.writeStrtab(); err != nil {
		return err
	}
	if err := e.writeShstrtab(); err != nil {
		return err
	}
	if err := e.writeShtab(); err != nil {
		return err
	}
	if _, err := e.wr.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return binary.Write(e.wr, binary.LittleEndian, e.hdr)
}
