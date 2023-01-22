package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/pe"
	_ "embed"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"text/template"
	"unicode/utf16"

	"github.com/terorie/mwcc-native/pe2elf/winres"
)

var verbose uint

var discardLogger = log.New(io.Discard, "", 0)

func logger(level uint) *log.Logger {
	if level <= verbose {
		return log.Default()
	} else {
		return discardLogger
	}
}

const tibSize = 0xf78
const tibVaddr = 0x10000000

//go:embed ordinals.csv
var knownOrdinalsCSV []byte

var knownOrdinals map[string]map[uint16]string

func init() {
	if err := initOrdinals(); err != nil {
		panic("invalid ordinals.csv, please recompile pe2elf: " + err.Error())
	}
}

func initOrdinals() error {
	knownOrdinals = make(map[string]map[uint16]string)
	rd := csv.NewReader(bytes.NewReader(knownOrdinalsCSV))
	_, _ = rd.Read()
	for {
		record, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		dll, ordinalStr, name := record[0], record[1], record[2]
		ordinal64, err := strconv.ParseUint(ordinalStr, 10, 16)
		if err != nil {
			return err
		}
		if ordinal64 > math.MaxUint16 {
			return fmt.Errorf("ordinal number too large (%d)", ordinal64)
		}
		lut := knownOrdinals[dll]
		if lut == nil {
			lut = make(map[uint16]string)
			knownOrdinals[dll] = lut
		}
		lut[uint16(ordinal64)] = name
	}
	return nil
}

func main() {
	inPath := flag.String("i", "", "PE input file")
	outPath := flag.String("o", "out.elf", "ELF output file")
	outCstrPath := flag.String("out-cstr", "genstr.c", "Resource strings output file")
	flag.UintVar(&verbose, "v", 0, "Verbosity (0=no 1=lil 2=much)")
	symbolsPath := flag.String("symbols", "", "Path to symbols list")
	flag.Parse()

	log.Default().SetFlags(0)

	var symbols []sym
	if *symbolsPath != "" {
		var err error
		symbols, err = getSymbols(*symbolsPath)
		if err != nil {
			log.Fatal("Invalid symbols file: ", symbols)
		}
	}

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

	outCstrFile, err := os.Create(*outCstrPath)
	if err != nil {
		log.Fatal(err)
	}
	defer outCstrFile.Close()

	peOpt := peFile.OptionalHeader.(*pe.OptionalHeader32)
	baseVaddr := peOpt.ImageBase
	logger(1).Printf("Base vaddr:   %#x", baseVaddr)

	entryVaddr := baseVaddr + peOpt.AddressOfEntryPoint
	logger(1).Printf("Entry vaddr:  %#x", entryVaddr)

	var writer elfWriter
	if err := writer.init(outFile); err != nil {
		log.Fatal(err)
	}
	writer.hdr.Entry = entryVaddr

	var strs []string
	peRes := peFile.Section(".rsrc")
	if peRes != nil {
		var res winres.ResourceSet
		rawRsrc, err := peRes.Data()
		if err != nil {
			log.Fatal("Failed to read .rsrc: ", err)
		}
		if err := res.Read(rawRsrc, peRes.VirtualAddress, winres.ID(0)); err != nil {
			log.Fatal("Failed to parse .rsrc: ", err)
		}

		escape := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
		var strID uint
		res.WalkType(winres.RT_STRING, func(resID winres.Identifier, langID uint16, data []byte) bool {
			bundleID := uint(resID.(winres.ID))
			_ = bundleID
			rd := bytes.NewReader(data)
			for i := uint(0); rd.Len() > 0 && i < 16; i++ {
				var sz uint16
				_ = binary.Read(rd, binary.LittleEndian, &sz)
				if sz == 0 {
					continue
				}
				points := make([]uint16, sz)
				_ = binary.Read(rd, binary.LittleEndian, &points)
				runes := utf16.Decode(points)
				str := string(runes)
				//strID := (bundleID * 16) + i
				strID++

				if verbose >= 2 {
					fmt.Printf(".rsrc str (%d): %s", strID, str)
				}

				if uint(len(strs)) <= strID {
					strs = append(strs, make([]string, strID-uint(len(strs))+1)...)
				}
				strs[strID] = escape.Replace(str)
			}
			return true
		})
	}

	cstrTmpl := `/* Generated file */
	int const __pe_str_cnt = {{ . | len }};
	
	char const * const __pe_strs[] = {
	{{- range $i, $x := . }}
	  /*{{ $i | printf "% 4d" }} */ "{{- . -}}",
	{{- end }}
	""
	};`

	tmpl, err := template.New("").Parse(cstrTmpl)
	if err != nil {
		log.Fatal("Invalid template: ", err)
	}
	tmpl.Execute(outCstrFile, strs)

	peText := peFile.Section(".text")
	rawText := peText.Open()
	logger(1).Printf("Text vaddr:   %#x", baseVaddr+peText.VirtualAddress)
	if err = writer.copySection(rawText, ".text", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC | elf.SHF_EXECINSTR),
		Addr:  baseVaddr + peText.VirtualAddress,
	}); err != nil {
		log.Fatal(err)
	}

	peExc := peFile.Section(".exc")
	rawExc := peExc.Open()
	logger(1).Printf("Exc vaddr:    %#x", baseVaddr+peExc.VirtualAddress)
	if err = writer.copySection(rawExc, ".rodata.exc", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC),
		Addr:  baseVaddr + peExc.VirtualAddress,
	}); err != nil {
		log.Fatal("copySection(.rodata.exc):", err)
	}

	peRodata := peFile.Section(".rdata")
	rawRodata := peRodata.Open()
	logger(1).Printf("Rodata vaddr: %#x", baseVaddr+peRodata.VirtualAddress)
	if err = writer.copySection(rawRodata, ".rodata", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC),
		Addr:  baseVaddr + peRodata.VirtualAddress,
	}); err != nil {
		log.Fatal("copySection(.rodata):", err)
	}

	peData := peFile.Section(".data")
	rawData := peData.Open()
	logger(1).Printf("Data vaddr:   %#x", baseVaddr+peData.VirtualAddress)
	if err = writer.copySection(rawData, ".data", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC | elf.SHF_WRITE),
		Addr:  baseVaddr + peData.VirtualAddress,
	}); err != nil {
		log.Fatal("copySection(.data):", err)
	}

	peCRT := peFile.Section(".CRT")
	rawCRT := peCRT.Open()
	logger(1).Printf("CRT vaddr:    %#x", baseVaddr+peCRT.VirtualAddress)
	if err = writer.copySection(rawCRT, ".data.CRT", elf.Section32{
		Type:  uint32(elf.SHT_PROGBITS),
		Flags: uint32(elf.SHF_ALLOC | elf.SHF_WRITE),
		Addr:  baseVaddr + peCRT.VirtualAddress,
	}); err != nil {
		log.Fatal("copySection(.data.CRT):", err)
	}

	peIdata := peFile.Section(".idata")
	logger(1).Printf("Idata vaddr:  %#x", baseVaddr+peIdata.VirtualAddress)
	// Instead of copying .idata, we zero it out completely.
	// ELF relocs will fill it in, but we don't want any implicit addends.
	// TODO This zero filling could be a bit more graceful
	if err = writer.copySection(
		bytes.NewReader(make([]byte, peIdata.VirtualSize)),
		".data.idata", elf.Section32{
			Type:  uint32(elf.SHT_PROGBITS),
			Flags: uint32(elf.SHF_ALLOC | elf.SHF_WRITE),
			Addr:  baseVaddr + peIdata.VirtualAddress,
		}); err != nil {
		log.Fatal("copySection(.data.idata):", err)
	}

	idataNdx := len(writer.sections) - 1
	if err = writer.addImports(peFile, peOpt, idataNdx); err != nil {
		log.Fatal("addImports:", err)
	}

	writer.addImplicitSyms()

	writer.addUserSyms(symbols)

	peBss := peFile.Section(".bss")
	logger(1).Printf("Bss vaddr:    %#x", baseVaddr+peBss.VirtualAddress)
	writer.addBss(peBss.VirtualSize, baseVaddr+peBss.VirtualAddress, ".bss")

	writer.addBss(tibSize, tibVaddr, ".bss.tib")

	if err := writer.patchMovFs(len(writer.sections)-1 /*bss.tib*/, 1 /*text*/); err != nil {
		log.Fatal("patchMovFs:", err)
	}

	peRelocs := peFile.Section(".reloc")
	writer.addRelocs(peRelocs, baseVaddr)

	if err := writer.finish(); err != nil {
		log.Fatal("finish:", err)
	}
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

type symkey struct {
	shndx uint32
	value uint32
}

type elfWriter struct {
	hdr      elf.Header32
	wr       *os.File
	sections []elf.Section32
	symtab   []elf.Sym32
	symmap   map[symkey]int      // (shndx, vaddr) -> index in symtab
	relocs   map[int][]elf.Rel32 // section index -> relocs

	shstrtab bytes.Buffer
	strtab   bytes.Buffer
}

func (e *elfWriter) init(wr *os.File) error {
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
	e.symtab = []elf.Sym32{{}}
	e.symmap = make(map[symkey]int)
	e.relocs = make(map[int][]elf.Rel32)
	return binary.Write(wr, binary.LittleEndian, &e.hdr)
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

func (e *elfWriter) addBss(size uint32, vaddr uint32, name string) {
	e.sections = append(e.sections, elf.Section32{
		Name:  e.addShstr(name),
		Type:  uint32(elf.SHT_NOBITS),
		Flags: uint32(elf.SHF_ALLOC) | uint32(elf.SHF_WRITE),
		Size:  size,
		Addr:  vaddr,
	})
}

// patchMovFs patches a bunch of instructions reading from `fs:[0]`.
//
// Very crappy poopy code, but good enough for mwcceppc.exe.
func (e *elfWriter) patchMovFs(tibShndx, textShndx int) error {
	// Create symbol for TIB
	symIdx := e.addSym(elf.Sym32{
		Value: 0,
		Info:  elf.ST_INFO(elf.STB_GLOBAL, elf.STT_NOTYPE),
		Shndx: uint16(tibShndx),
		Other: uint8(elf.STV_DEFAULT),
		Size:  0,
	}, "__pe_tib")

	// All refs to fs are usually in the first 2KiB.
	buf := make([]byte, 2048)

	// Read original bytes
	shOff := int64(e.sections[textShndx].Off)
	_, rdErr := io.ReadFull(io.NewSectionReader(e.wr, shOff, int64(len(buf))), buf)
	if rdErr != nil {
		return fmt.Errorf("failed to read .text to be patched: %w", rdErr)
	}

	// Old:      mov eax, dword [fs:0x0]
	// New: nop; mov eax, dword [ds:__pe_tib+0x0]
	e.patchTib(
		buf, textShndx, 0, uint32(symIdx),
		[]byte{0x64, 0xa1, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x90, 0xa1, 0x00, 0x00, 0x00, 0x00},
		2,
	)

	// Old:      mov esi, dword [fs:0x0]
	// New: nop; mov esi, dword [ds:__pe_tib+0x0]
	e.patchTib(
		buf, textShndx, 0, uint32(symIdx),
		[]byte{0x64, 0x8b, 0x35, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x90, 0x8b, 0x35, 0x00, 0x00, 0x00, 0x00},
		3,
	)

	// Old:      mov dword [fs:0x0],          ebx
	// New: nop; mov dword [ds:__pe_tib+0x0], ebx
	e.patchTib(
		buf, textShndx, 0, uint32(symIdx),
		[]byte{0x64, 0x89, 0x1d, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x90, 0x89, 0x1d, 0x00, 0x00, 0x00, 0x00},
		3,
	)

	// Old:      mov dword [fs:0x0],          esp
	// New: nop; mov dword [ds:__pe_tib+0x0], esp
	e.patchTib(
		buf, textShndx, 0, uint32(symIdx),
		[]byte{0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x90, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00},
		3,
	)

	// Old:      push dword [fs:0x0]
	// New: nop; push dword [ds:__pe_tib+0x0]
	e.patchTib(
		buf, textShndx, 0, uint32(symIdx),
		[]byte{0x64, 0xff, 0x35, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x90, 0xff, 0x35, 0x00, 0x00, 0x00, 0x00},
		3,
	)

	// Old:      pop dword [fs:0x0]
	// New: nop; pop dword [ds:__pe_tib+0x0]
	e.patchTib(
		buf, textShndx, 0, uint32(symIdx),
		[]byte{0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x90, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00},
		3,
	)

	// Write patched bytes
	_, wrErr := e.wr.WriteAt(buf, shOff)
	return wrErr
}

func (e *elfWriter) patchTib(
	buf []byte, // section content
	shndx int, // reloc site section inde
	shOffset uint32, // offset within section
	symNdx uint32, // index of symbol in symtab
	oldBuf []byte, newBuf []byte, // replacement
	relOffset uint16, // reloc offset witin replacement
) {
	if len(oldBuf) != len(newBuf) {
		panic("patchBin: len(oldBuf) != len(newBuf)")
	}
	sectionName, _ := getString(e.shstrtab.Bytes(), int(e.sections[shndx].Name))
	for len(buf) > 0 {
		idx := bytes.Index(buf, oldBuf)
		if idx < 0 {
			break
		}
		copy(buf[idx:], newBuf)
		buf = buf[idx+len(newBuf):]
		shOffset += uint32(idx)
		e.relocs[shndx] = append(e.relocs[shndx], elf.Rel32{
			Off:  shOffset + uint32(relOffset),
			Info: elf.R_INFO32(uint32(symNdx), uint32(elf.R_386_32)),
		})
		if verbose >= 1 {
			log.Printf("TIB patch %s:%#04x+%d (%x => %x)", sectionName, shOffset, relOffset, oldBuf, newBuf)
		}
		shOffset += uint32(len(newBuf))
	}
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

// addSym adds a symbol to the symbol table.
func (e *elfWriter) addSym(sym elf.Sym32, name string) int {
	key := symkey{
		shndx: uint32(sym.Shndx),
		value: sym.Value,
	}
	if symndx, ok := e.symmap[key]; ok {
		return symndx
	}
	if name != "" {
		sym.Name = e.addStr(name)
	}
	ndx := len(e.symtab)
	e.symtab = append(e.symtab, sym)
	e.symmap[key] = ndx
	return ndx
}

// addRelocs parses PE relocations and emits ELF relocations.
//
// All of this only covers relocations of absolute 32-bit virtual addresses, i.e. R_386_32.
//
// Some terminology:
// - Site: the address that needs to be patched
// - Target: the (virtual) address of the symbol that the site refers to
//
// In PE, this works by simply having the site refer to the target virtual address.
// The relocation table contains a list of these sites.
// Because the site already contains the target address, no further info is required in the reloc itself.
//
// ELF is a bit more flexible, however.
// Patching works by creating a symbol that points at or before the target,
// and then having the reloc associate a site with that symbol.
// An addend, which is sourced from the original site or `r_addend`,
// is added to the symbol's address to get the final target address.
//
// We don't have any actual symbols, so we use the start of the target's as the symbol,
// and store the offset between the target and the symbol in the addend field.
func (e *elfWriter) addRelocs(s *pe.Section, baseVaddr uint32) {
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
			log.Fatal("failed to read reloc block header:", err)
		}
		if hdr.PageRVA == 0 {
			break
		}
		pageVA := baseVaddr + hdr.PageRVA
		//log.Printf("Reloc block: %#x", hdr.PageRVA)
		for i := uint32(0); i < hdr.BlockSize-8; i += 2 {
			var reloc uint16
			if err := binary.Read(rd, binary.LittleEndian, &reloc); err != nil {
				log.Fatal("failed to read reloc:", err)
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
			siteVaddr := pageVA + uint32(relocOffset)

			// Detect section of reloc site
			siteShndx := -1
			for i, s := range e.sections {
				if s.Addr <= siteVaddr && siteVaddr < s.Addr+s.Size {
					siteShndx = i
					break
				}
			}
			if siteShndx < 0 {
				log.Printf("Reloc site of any ELF section (type=%d, vaddr=%#x)", relocType, siteVaddr)
				continue
			}

			// Read original target address
			sitePaddr := e.sections[siteShndx].Off + siteVaddr - e.sections[siteShndx].Addr
			var origAddrBuf [4]byte
			if _, err := e.wr.ReadAt(origAddrBuf[:], int64(sitePaddr)); err != nil {
				log.Fatalf("failed to read reloc at paddr=%#x vaddr=%#x shndx=%d: %v", sitePaddr, siteVaddr, siteShndx, err)
			}
			targetVaddr := binary.LittleEndian.Uint32(origAddrBuf[:])

			// Patch site to zero
			// TODO: We could simplify this by writing a section offset,
			//       and using a symbol that points to the section start.
			if _, err := e.wr.WriteAt([]byte{0, 0, 0, 0}, int64(sitePaddr)); err != nil {
				log.Fatal(err)
			}

			// Detect section of reloc target
			targetShndx := -1
			for i, s := range e.sections {
				if s.Addr <= targetVaddr && targetVaddr < s.Addr+s.Size {
					targetShndx = i
					break
				}
			}
			if targetShndx < 0 {
				log.Printf("Reloc target outside of any ELF section (type=%d, vaddr=%#x)", relocType, targetVaddr)
				continue
			}

			// Create symbol for target
			targetShName, _ := getString(e.shstrtab.Bytes(), int(e.sections[targetShndx].Name))
			targetSymIdx := e.addSym(elf.Sym32{
				Value: targetVaddr - e.sections[targetShndx].Addr,
				Info:  elf.ST_INFO(elf.STB_GLOBAL, elf.STT_NOTYPE),
				Shndx: uint16(targetShndx),
				Other: uint8(elf.STV_DEFAULT),
				Size:  0,
			}, fmt.Sprintf("__pe_unk_%x", targetVaddr))

			// Create relocation entry
			rel := elf.Rel32{
				Off:  siteVaddr - e.sections[siteShndx].Addr,
				Info: elf.R_INFO32(uint32(targetSymIdx), uint32(elf.R_386_32)),
			}
			e.relocs[siteShndx] = append(e.relocs[siteShndx], rel)

			if verbose >= 2 {
				siteShName, _ := getString(e.shstrtab.Bytes(), int(e.sections[siteShndx].Name))
				log.Printf("Reloc type=%d %#x (%s+%#x) -> %#x (%s+%#x)",
					relocType,
					siteVaddr, siteShName, siteVaddr-e.sections[siteShndx].Addr,
					targetVaddr, targetShName, targetVaddr-e.sections[targetShndx].Addr,
				)
			}
		}
	}
}

func (e *elfWriter) addImplicitSyms() {
	for i, s := range e.sections[1:] {
		shName, _ := getString(e.shstrtab.Bytes(), int(s.Name))
		symName := "__pe" + strings.ReplaceAll(shName, ".", "_") + "_start"
		e.addSym(elf.Sym32{
			Value: 0,
			Info:  elf.ST_INFO(elf.STB_GLOBAL, elf.STT_NOTYPE),
			Shndx: uint16(i + 1),
			Other: uint8(elf.STV_DEFAULT),
			Size:  0,
		}, symName)
		if verbose >= 1 {
			log.Printf("Adding implicit sym %s (shndx=%d value=0)", symName, i)
		}
	}
}

func (e *elfWriter) addUserSyms(symbols []sym) {
	for _, sym := range symbols {
		shNdx := -1
		var shOffset uint32
		for i, sec := range e.sections {
			if sec.Addr <= sym.addr && sym.addr < sec.Addr+sec.Size {
				shNdx = i
				shOffset = sym.addr - sec.Addr
			}
		}
		if shNdx < 0 {
			continue
		}
		e.addSym(elf.Sym32{
			Value: shOffset,
			Info:  elf.ST_INFO(elf.STB_GLOBAL, elf.STT_NOTYPE),
			Shndx: uint16(shNdx),
			Other: uint8(elf.STV_DEFAULT),
			Size:  0,
		}, sym.name)
		if verbose >= 1 {
			log.Printf("Adding user sym %s (shndx=%d value=%d)", sym.name, shNdx, shOffset)
		}
	}
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

func (e *elfWriter) addImports(peFile *pe.File, peOpt *pe.OptionalHeader32, idataNdx int) error {
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
		return fmt.Errorf("could not find section containing import directory table")
	}
	d, err := ds.Data()
	if err != nil {
		return err
	}
	d = d[idd.VirtualAddress-ds.VirtualAddress:]

	// start decoding the import directory
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
		dll, ok := getString(names, int(dt.Name-ds.VirtualAddress))
		if !ok {
			log.Printf("Import directory %d missing name (name=%d)", i, dt.Name)
			continue
		}
		dll = strings.TrimSuffix(strings.TrimSuffix(dll, ".DLL"), ".dll")
		dlls[i] = dll
		d, _ = ds.Data()
		// seek to OriginalFirstThunk
		d = d[dt.OriginalFirstThunk-ds.VirtualAddress:]
		targetAddr := peOpt.ImageBase + dt.FirstThunk
		j := -1
		for len(d) > 0 {
			j++
			va := binary.LittleEndian.Uint32(d[0:4])
			d = d[4:]
			if va == 0 {
				break
			}

			var fn string
			isOrdinal := (va & 0x8000_0000) != 0
			if isOrdinal {
				ordinal := uint16(va & 0xFFFF)
				if dllTab := knownOrdinals[dll]; dllTab != nil {
					fn = dllTab[ordinal]
				}
				if fn == "" {
					log.Printf("Import %s ord %d missing known ordinal name", dll, ordinal)
					fn = fmt.Sprintf("ord_%d", ordinal)
				}
			} else {
				fn, ok = getString(names, int(va-ds.VirtualAddress+2))
				if !ok {
					log.Printf("Import %s/%d missing literal name (va=%#x ds_va=%#x)", dll, j, va, ds.VirtualAddress)
					fn = fmt.Sprintf("%x", targetAddr)
				}
			}

			// Declare new undefined symbol
			symName := dll + "_" + fn
			symIdx := e.addSym(elf.Sym32{
				Value: va,
				Info:  elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC),
				Other: uint8(elf.STV_DEFAULT),
				Shndx: uint16(elf.SHN_UNDEF),
			}, symName)

			// Emit relocation to symbol
			e.relocs[idataNdx] = append(e.relocs[idataNdx], elf.Rel32{
				Off:  targetAddr - e.sections[idataNdx].Addr,
				Info: elf.R_INFO32(uint32(symIdx), uint32(elf.R_386_32)),
			})

			if verbose >= 1 {
				log.Printf("Import at %#x %s!%s as %s", targetAddr, dlls[i], fn, symName)
			}
			targetAddr += 4
		}
	}

	return nil
}

func (e *elfWriter) writeReltabs() error {
	// Count number of reloc sections
	nReltabs := 0
	for i := 0; i < len(e.sections); i++ {
		if len(e.relocs[i]) > 0 {
			nReltabs++
		}
	}

	// Write reloc sections
	buf := bufio.NewWriter(e.wr)
	for i := 0; i < len(e.sections); i++ {
		if len(e.relocs[i]) == 0 {
			continue
		}
		nReltabs--
		atStart := e.pos()
		if err := binary.Write(buf, binary.LittleEndian, e.relocs[i]); err != nil {
			return err
		}
		if err := buf.Flush(); err != nil {
			return err
		}
		atEnd := e.pos()

		// Get target section name
		name, _ := getString(e.shstrtab.Bytes(), int(e.sections[i].Name))
		if name == "" {
			panic("cannot find section name")
		}

		sec := elf.Section32{
			Name:    e.addShstr(".rel" + name),
			Type:    uint32(elf.SHT_REL),
			Off:     atStart,
			Size:    atEnd - atStart,
			Link:    uint32(len(e.sections) + nReltabs + 1), // .symtab follows last reloc section
			Info:    uint32(i),
			Entsize: uint32(binary.Size(elf.Rel32{})),
		}
		e.sections = append(e.sections, sec)
	}

	return nil
}

func (e *elfWriter) writeSymtab() error {
	atStart := e.pos()
	buf := bufio.NewWriter(e.wr)
	binary.Write(buf, binary.LittleEndian, e.symtab)
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
	if err := e.writeReltabs(); err != nil {
		return err
	}
	if err := e.writeSymtab(); err != nil {
		return err
	}
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

type sym struct {
	addr uint32
	name string
}

func getSymbols(symbolsPath string) ([]sym, error) {
	f, err := os.Open(symbolsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var syms []sym
	scn := bufio.NewScanner(f)
	for i := 1; scn.Scan(); i++ {
		line := strings.TrimSpace(scn.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			return syms, fmt.Errorf("line %d: invalid entry", i)
		}
		addr, err := strconv.ParseUint(parts[0], 0, 32)
		if err != nil {
			return syms, fmt.Errorf("line %d: invalid address: %w", i, err)
		}
		syms = append(syms, sym{
			addr: uint32(addr),
			name: parts[1],
		})
	}
	return syms, scn.Err()
}
