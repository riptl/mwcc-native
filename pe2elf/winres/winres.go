package winres

// Standard type IDs from  https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types
const (
	RT_CURSOR       ID = 1
	RT_BITMAP       ID = 2
	RT_ICON         ID = 3
	RT_MENU         ID = 4
	RT_DIALOG       ID = 5
	RT_STRING       ID = 6
	RT_FONTDIR      ID = 7
	RT_FONT         ID = 8
	RT_ACCELERATOR  ID = 9
	RT_RCDATA       ID = 10
	RT_MESSAGETABLE ID = 11
	RT_GROUP_CURSOR ID = 12
	RT_GROUP_ICON   ID = 14
	RT_VERSION      ID = 16
	RT_PLUGPLAY     ID = 19
	RT_VXD          ID = 20
	RT_ANICURSOR    ID = 21
	RT_ANIICON      ID = 22
	RT_HTML         ID = 23
	RT_MANIFEST     ID = 24
)

const (
	LCIDNeutral = 0
	LCIDDefault = 0x409 // en-US is default
)

// Arch defines the target architecture.
// Its value can be used as a target suffix too:
// "rsrc_windows_"+string(arch)+".syso"
type Arch string

const (
	ArchI386  Arch = "386"
	ArchAMD64 Arch = "amd64"
	ArchARM   Arch = "arm"
	ArchARM64 Arch = "arm64"
)

// ResourceSet is the main object in the package.
//
// Create an empty ResourceSet and call Set methods to add resources, then WriteObject to produce a COFF object file.
type ResourceSet struct {
	types        map[Identifier]*typeEntry
	lastIconID   uint16
	lastCursorID uint16
}

// Set adds or replaces a resource.
//
// typeID is the resource type's identifier.
// It can be either a standard type number (RT_ICON, RT_VERSION, ...) or any type name.
//
// resID is the resource's unique identifier for a given type.
// It can either be an ID starting from 1, or a Name.
//
// A resource ID can have different data depending on the user's locale.
// In this case Set can be called several times with the same resID but a different language ID.
//
// langID can be 0 (neutral), or one of those LCID:
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid
//
// Warning: the ResourceSet takes ownership of the data parameter.
// The caller should not write into it anymore after calling this method.
func (rs *ResourceSet) Set(typeID, resID Identifier, langID uint16, data []byte) error {
	if err := checkIdentifier(resID); err != nil {
		return err
	}
	if err := checkIdentifier(typeID); err != nil {
		return err
	}

	rs.set(typeID, resID, langID, data)

	return nil
}

// Count returns the number of resources in the set.
func (rs *ResourceSet) Count() int {
	return rs.numDataEntries()
}

// Walk walks through the resources in same order as they will be written.
//
// It takes a callback function that takes same parameters as Set and returns a bool that should be true to continue, false to stop.
//
// If you modify the set during a call to Walk, behaviour is undefined.
func (rs *ResourceSet) Walk(f func(typeID, resID Identifier, langID uint16, data []byte) bool) {
	s := &state{}
	rs.order(s)
	for _, tk := range s.orderedKeys {
		te := rs.types[tk]
		for _, rk := range te.orderedKeys {
			re := te.resources[rk]
			for _, dk := range re.orderedKeys {
				if !f(tk, rk, uint16(dk), re.data[dk].data) {
					return
				}
			}
		}
	}
}

// WalkType walks through the resources or a certain type, in same order as they will be written.
//
// It takes a callback function that takes same parameters as Set and returns a bool that should be true to continue, false to stop.
//
// If you modify the set during a call to Walk, behaviour is undefined.
func (rs *ResourceSet) WalkType(typeID Identifier, f func(resID Identifier, langID uint16, data []byte) bool) {
	te := rs.types[typeID]
	if te == nil {
		return
	}
	te.order()
	for _, rk := range te.orderedKeys {
		re := te.resources[rk]
		for _, dk := range re.orderedKeys {
			if !f(rk, uint16(dk), re.data[dk].data) {
				return
			}
		}
	}
}

// Get returns resource data.
//
// Returns nil if the resource was not found.
func (rs *ResourceSet) Get(typeID, resID Identifier, langID uint16) []byte {
	te := rs.types[typeID]
	if te == nil {
		return nil
	}

	re := te.resources[resID]
	if re == nil {
		return nil
	}

	de := re.data[ID(langID)]
	if de == nil {
		return nil
	}

	return de.data
}

// set is the only function that may create/modify entries in the ResourceSet
func (rs *ResourceSet) set(typeID Identifier, resID Identifier, langID uint16, data []byte) {
	if rs.types == nil {
		rs.types = make(map[Identifier]*typeEntry)
	}

	if data == nil {
		// Like UpdateResource, delete resources by passing nil
		rs.delete(typeID, resID, langID)
		return
	}

	te := rs.types[typeID]
	if te == nil {
		te = &typeEntry{
			resources: make(map[Identifier]*resourceEntry),
		}
		rs.types[typeID] = te
	}

	re := te.resources[resID]
	if re == nil {
		te.orderedKeys = nil
		re = &resourceEntry{
			data: make(map[ID]*dataEntry),
		}
		te.resources[resID] = re
	}

	if typeID == RT_ICON {
		if id, ok := resID.(ID); ok && rs.lastIconID < uint16(id) {
			rs.lastIconID = uint16(id)
		}
	} else if typeID == RT_CURSOR {
		if id, ok := resID.(ID); ok && rs.lastCursorID < uint16(id) {
			rs.lastCursorID = uint16(id)
		}
	}

	de := re.data[ID(langID)]
	if de == nil {
		re.orderedKeys = nil
		de = &dataEntry{}
		re.data[ID(langID)] = de
	}

	de.data = data
}

func (rs *ResourceSet) delete(typeID Identifier, resID Identifier, langID uint16) {
	te := rs.types[typeID]
	if te == nil {
		return
	}

	re := te.resources[resID]
	if re == nil {
		return
	}

	delete(re.data, ID(langID))
	re.orderedKeys = nil

	if len(re.data) > 0 {
		return
	}

	delete(te.resources, resID)
	te.orderedKeys = nil

	if len(te.resources) > 0 {
		return
	}

	delete(rs.types, typeID)
}

// firstLang finds the first language ID of a resource.
//
// When an icon image has several languages, Windows takes the first one
// in the resource directory, even if it's not the same as the group's language,
// or the user's language.
//
// UpdateResource sorts resources just like winres does, so we may assume
// the first language in the file should be the lowest LCID.
func (rs *ResourceSet) firstLang(typeID, resID Identifier) uint16 {
	te := rs.types[typeID]
	if te == nil {
		return 0
	}

	re := te.resources[resID]
	if re == nil {
		return 0
	}

	if len(re.data) == 0 {
		return 0
	}

	re.order()

	return uint16(re.orderedKeys[0])
}
