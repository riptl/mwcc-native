package winres

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"unicode/utf16"
)

const (
	// Visual C++ pads resource data to 8 bytes.
	// 4 bytes is a minimum.
	dataAlignment = 8
)

// state is a temporary state used during the execution of ResourceSet.write()
type state struct {
	offset      int          // offset to write in the next directory entry
	relocAddr   []int        // addresses to add to the relocation table (addresses of the data entries)
	nameOffset  map[Name]int // offset of every name in the names string table
	namesData   []uint16     // final data for the names string table
	orderedKeys []Identifier // ordered keys for ResourceSet.types
	namesCount  int          // number of keys of type Name in ResourceSet.types
}

// order orders identifiers in the whole resource set.
func (rs *ResourceSet) order(s *state) {
	s.orderedKeys = make([]Identifier, 0, len(rs.types))
	for ident, te := range rs.types {
		s.orderedKeys = append(s.orderedKeys, ident)
		te.order()
	}

	// Names in case sensitive ascending order, then IDs in ascending order
	sort.Slice(s.orderedKeys, func(i, j int) bool {
		return s.orderedKeys[i].lessThan(s.orderedKeys[j])
	})

	// Count Names by searching the first ID
	s.namesCount = sort.Search(len(s.orderedKeys), func(i int) bool {
		_, ok := s.orderedKeys[i].(ID)
		return ok
	})
}

// prepare calculates the names index offset and content, as this has to be known before writing the resource directory.
// It also freezes the order of identifiers in the directory, so that subsequent write functions can rely on it.
func (rs *ResourceSet) prepare() *state {
	var (
		nameSet     = make(map[Name]struct{})
		typeNameSet = make(map[Name]struct{})
		s           = &state{
			nameOffset: make(map[Name]int),
		}
	)

	rs.order(s)

	for ident, te := range rs.types {
		if name, ok := ident.(Name); ok {
			typeNameSet[name] = struct{}{}
			nameSet[name] = struct{}{}
		}
		for _, name := range te.orderedKeys[:te.namesCount] {
			nameSet[name.(Name)] = struct{}{}
		}
	}

	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, string(n))
	}
	sort.Strings(names)

	offset := rs.dirSize()
	for _, n := range names {
		s.nameOffset[Name(n)] = offset
		u := utf16.Encode([]rune(n))
		s.namesData = append(s.namesData, uint16(len(u)))
		s.namesData = append(s.namesData, u...)
		offset += (len(u) + 1) * 2
	}

	// Names must be padded to align the resource data.
	sz := len(s.namesData) * 2
	s.namesData = append(s.namesData, make([]uint16, (alignData(sz)-sz)/2)...)
	return s
}

// fullSize returns the full size of the rsrc section's content: the directory, the names, and the actual data.
func (rs *ResourceSet) fullSize() int {
	s := rs.prepare()
	sz := rs.dirSize() + len(s.namesData)*2
	for _, te := range rs.types {
		for _, re := range te.resources {
			for _, de := range re.data {
				sz += de.paddedDataSize()
			}
		}
	}
	return sz
}

// dirSize returns the size of the rsrc section's directory.
func (rs *ResourceSet) dirSize() int {
	sz := sizeOfDirTable + len(rs.types)*sizeOfDirEntry
	for _, te := range rs.types {
		sz += te.size()
		for _, re := range te.resources {
			sz += re.size() + len(re.data)*sizeOfDataEntry
		}
	}
	return sz
}

// numDataEntries returns the number of resource data entries to be written into the rsrc section.
func (rs *ResourceSet) numDataEntries() int {
	var n int
	for _, te := range rs.types {
		for _, re := range te.resources {
			n += len(re.data)
		}
	}
	return n
}

type typeEntry struct {
	resources   map[Identifier]*resourceEntry
	orderedKeys []Identifier
	namesCount  int
}

// size returns the size of the entry's directory table
func (te *typeEntry) size() int {
	return sizeOfDirTable + len(te.resources)*sizeOfDirEntry
}

// order orders ids and names following the specification, and saves them in orderedKeys.
// It calls resourceEntry.order() too, for each resource entry it owns.
func (te *typeEntry) order() {
	if te.orderedKeys != nil {
		return
	}

	te.orderedKeys = make([]Identifier, 0, len(te.resources))
	for ident, re := range te.resources {
		te.orderedKeys = append(te.orderedKeys, ident)

		// Order LCIDs in every resource
		re.order()
	}

	// Names in case sensitive ascending order, then IDs in ascending order
	sort.Slice(te.orderedKeys, func(i, j int) bool {
		return te.orderedKeys[i].lessThan(te.orderedKeys[j])
	})

	// Count Names by searching the first ID
	te.namesCount = sort.Search(len(te.orderedKeys), func(i int) bool {
		_, ok := te.orderedKeys[i].(ID)
		return ok
	})
}

type resourceEntry struct {
	data        map[ID]*dataEntry
	orderedKeys []ID
}

// size returns the size of the entry's directory table
func (re *resourceEntry) size() int {
	return sizeOfDirTable + len(re.data)*sizeOfDirEntry
}

// order orders LCIDs and saves them in orderedKeys.
func (re *resourceEntry) order() {
	if re.orderedKeys != nil {
		return
	}

	re.orderedKeys = make([]ID, 0, len(re.data))
	for id := range re.data {
		re.orderedKeys = append(re.orderedKeys, id)
	}

	// LCIDs in ascending order
	sort.Slice(re.orderedKeys, func(i, j int) bool {
		return re.orderedKeys[i].lessThan(re.orderedKeys[j])
	})
}

type dataEntry struct {
	data []byte
}

func alignData(offset int) int {
	return (offset + dataAlignment - 1) &^ (dataAlignment - 1)
}

// paddedDataSize returns the room taken by data, including some padding at the end.
func (de *dataEntry) paddedDataSize() int {
	return alignData(len(de.data))
}

// Binary format of the directory :

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
// https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)#pe-file-resources

type resourceDirectoryTable struct {
	Characteristics     uint32
	TimeDateStamp       uint32
	MajorVersion        uint16
	MinorVersion        uint16
	NumberOfNameEntries uint16
	NumberOfIDEntries   uint16
}

const sizeOfDirTable = 16

type resourceDirectoryIDEntry struct {
	ID     uint32
	Offset uint32
}

const sizeOfDirEntry = 8

const subdirectoryOffset = 0x80000000
const nameOffset = 0x80000000

type resourceDataEntry struct {
	DataRVA  uint32
	Size     uint32
	Codepage uint32
	Reserved uint32
}

const sizeOfDataEntry = 16

// Reading functions:

func (rs *ResourceSet) Read(section []byte, baseAddress uint32, typeID Identifier) error {
	r := bytes.NewReader(section)
	return dirEntry{}.walk(r, func(typeEntry dirEntry) error {
		if typeID != ID(0) &&
			typeEntry.ident != typeID &&
			(typeEntry.ident != RT_ICON || typeID != RT_GROUP_ICON) &&
			(typeEntry.ident != RT_CURSOR || typeID != RT_GROUP_CURSOR) {
			return nil
		}
		return typeEntry.walk(r, func(resourceEntry dirEntry) error {
			resourceEntry.leaf = true
			return resourceEntry.walk(r, func(langEntry dirEntry) error {
				data, err := langEntry.readData(r, baseAddress)
				if err != nil {
					return err
				}
				return rs.Set(typeEntry.ident, resourceEntry.ident, uint16(langEntry.ident.(ID)), data)
			})
		})
	})
}

type dirEntry struct {
	path   string
	ident  Identifier
	offset int64
	leaf   bool
}

func (de dirEntry) walk(section *bytes.Reader, fn func(dirEntry) error) error {
	entries, err := de.readDirTable(section)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		err = fn(entry)
		if err != nil {
			return err
		}
	}
	return nil
}

func (de dirEntry) readData(section *bytes.Reader, baseAddress uint32) ([]byte, error) {
	section.Seek(de.offset, io.SeekStart)

	entry := resourceDataEntry{}
	err := binaryRead(section, &entry)
	if err != nil {
		return nil, err
	}

	offset := int64(entry.DataRVA) - int64(baseAddress)
	if offset < 0 || offset+int64(entry.Size) > section.Size() {
		return nil, errors.New(errDataEntryOutOfBounds)
	}

	data := make([]byte, entry.Size)
	section.Seek(offset, io.SeekStart)
	section.Read(data)

	return data, nil
}

func (de dirEntry) readDirTable(section *bytes.Reader) ([]dirEntry, error) {
	section.Seek(de.offset, io.SeekStart)

	table := resourceDirectoryTable{}
	err := binaryRead(section, &table)
	if err != nil {
		return nil, err
	}

	dir := make([]resourceDirectoryIDEntry, table.NumberOfNameEntries+table.NumberOfIDEntries)
	err = binaryRead(section, &dir)
	if err != nil {
		return nil, err
	}

	entries := make([]dirEntry, len(dir))
	for i := range dir {
		if de.leaf != (dir[i].Offset&subdirectoryOffset == 0) {
			return nil, errors.New(errInvalidResDir)
		}
		if de.leaf && dir[i].ID&nameOffset != 0 {
			return nil, errors.New(errInvalidResDir)
		}
		entries[i].offset = int64(dir[i].Offset &^ subdirectoryOffset)
		if dir[i].ID&nameOffset == 0 {
			entries[i].ident = ID(dir[i].ID)
		} else {
			entries[i].ident, err = readName(section, dir[i].ID&^nameOffset)
			if err != nil {
				return nil, err
			}
		}
	}

	return entries, nil
}

func readName(section *bytes.Reader, offset uint32) (Name, error) {
	section.Seek(int64(offset), io.SeekStart)

	var length uint16
	err := binaryRead(section, &length)
	if err != nil {
		return "", err
	}

	b := make([]uint16, length)
	err = binaryRead(section, b)
	if err != nil {
		return "", err
	}

	return Name(utf16.Decode(b)), nil
}
