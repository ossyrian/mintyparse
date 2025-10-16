package wztypes

// WzFile represents a parsed WZ file
type WzFile struct {
	Name        string
	Version     int
	Directories []*WzDirectory
}

// ExtractSprites extracts all sprites from the WZ file to the given directory
func (f *WzFile) ExtractSprites(dir string) (int, error) {
	// TODO: Implement sprite extraction
	return 0, nil
}

// WzDirectory represents a directory in a WZ file
type WzDirectory struct {
	Name   string
	Images []*WzImage
}

// WzImage represents an image container in a WZ file
type WzImage struct {
	Name       string
	Properties []WzProperty
}

// WzProperty is an interface for all WZ property types
type WzProperty interface {
	GetName() string
	GetType() WzPropertyType
	GetValue() interface{}
}

// WzPropertyType represents the type of a WZ property
type WzPropertyType int

const (
	PropertyNull WzPropertyType = iota
	PropertyShort
	PropertyInt
	PropertyLong
	PropertyFloat
	PropertyDouble
	PropertyString
	PropertyVector
	PropertyCanvas
	PropertyConvex
	PropertySound
	PropertyUOL
	PropertySub
)

func (t WzPropertyType) String() string {
	switch t {
	case PropertyNull:
		return "Null"
	case PropertyShort:
		return "Short"
	case PropertyInt:
		return "Int"
	case PropertyLong:
		return "Long"
	case PropertyFloat:
		return "Float"
	case PropertyDouble:
		return "Double"
	case PropertyString:
		return "String"
	case PropertyVector:
		return "Vector"
	case PropertyCanvas:
		return "Canvas"
	case PropertyConvex:
		return "Convex"
	case PropertySound:
		return "Sound"
	case PropertyUOL:
		return "UOL"
	case PropertySub:
		return "Sub"
	default:
		return "Unknown"
	}
}

// Concrete property types

type WzNullProperty struct {
	Name string
}

func (p *WzNullProperty) GetName() string         { return p.Name }
func (p *WzNullProperty) GetType() WzPropertyType { return PropertyNull }
func (p *WzNullProperty) GetValue() interface{}   { return nil }

type WzShortProperty struct {
	Name  string
	Value int16
}

func (p *WzShortProperty) GetName() string         { return p.Name }
func (p *WzShortProperty) GetType() WzPropertyType { return PropertyShort }
func (p *WzShortProperty) GetValue() interface{}   { return p.Value }

type WzIntProperty struct {
	Name  string
	Value int32
}

func (p *WzIntProperty) GetName() string         { return p.Name }
func (p *WzIntProperty) GetType() WzPropertyType { return PropertyInt }
func (p *WzIntProperty) GetValue() interface{}   { return p.Value }

type WzLongProperty struct {
	Name  string
	Value int64
}

func (p *WzLongProperty) GetName() string         { return p.Name }
func (p *WzLongProperty) GetType() WzPropertyType { return PropertyLong }
func (p *WzLongProperty) GetValue() interface{}   { return p.Value }

type WzFloatProperty struct {
	Name  string
	Value float32
}

func (p *WzFloatProperty) GetName() string         { return p.Name }
func (p *WzFloatProperty) GetType() WzPropertyType { return PropertyFloat }
func (p *WzFloatProperty) GetValue() interface{}   { return p.Value }

type WzDoubleProperty struct {
	Name  string
	Value float64
}

func (p *WzDoubleProperty) GetName() string         { return p.Name }
func (p *WzDoubleProperty) GetType() WzPropertyType { return PropertyDouble }
func (p *WzDoubleProperty) GetValue() interface{}   { return p.Value }

type WzStringProperty struct {
	Name  string
	Value string
}

func (p *WzStringProperty) GetName() string         { return p.Name }
func (p *WzStringProperty) GetType() WzPropertyType { return PropertyString }
func (p *WzStringProperty) GetValue() interface{}   { return p.Value }

type WzVectorProperty struct {
	Name string
	X    int32
	Y    int32
}

func (p *WzVectorProperty) GetName() string         { return p.Name }
func (p *WzVectorProperty) GetType() WzPropertyType { return PropertyVector }
func (p *WzVectorProperty) GetValue() interface{}   { return map[string]int32{"x": p.X, "y": p.Y} }

type WzCanvasProperty struct {
	Name       string
	Width      int32
	Height     int32
	Format     int32
	PngData    []byte
	Properties []WzProperty
}

func (p *WzCanvasProperty) GetName() string         { return p.Name }
func (p *WzCanvasProperty) GetType() WzPropertyType { return PropertyCanvas }
func (p *WzCanvasProperty) GetValue() interface{}   { return p.PngData }

type WzSubProperty struct {
	Name       string
	Properties []WzProperty
}

func (p *WzSubProperty) GetName() string         { return p.Name }
func (p *WzSubProperty) GetType() WzPropertyType { return PropertySub }
func (p *WzSubProperty) GetValue() interface{}   { return p.Properties }

type WzUOLProperty struct {
	Name string
	Link string
}

func (p *WzUOLProperty) GetName() string         { return p.Name }
func (p *WzUOLProperty) GetType() WzPropertyType { return PropertyUOL }
func (p *WzUOLProperty) GetValue() interface{}   { return p.Link }

type WzSoundProperty struct {
	Name     string
	Duration int32
	Data     []byte
}

func (p *WzSoundProperty) GetName() string         { return p.Name }
func (p *WzSoundProperty) GetType() WzPropertyType { return PropertySound }
func (p *WzSoundProperty) GetValue() interface{}   { return p.Data }

// WzPngFormat represents PNG compression formats
type WzPngFormat int

const (
	PngFormat1    WzPngFormat = 0x1   // BGRA4444
	PngFormat2    WzPngFormat = 0x2   // BGRA32
	PngFormat3    WzPngFormat = 0x3   // DXT3
	PngFormat257  WzPngFormat = 0x101 // ARGB1555
	PngFormat513  WzPngFormat = 0x201 // RGB565
	PngFormat517  WzPngFormat = 0x205 // RGB565 variant
	PngFormat1026 WzPngFormat = 0x402 // DXT3 variant
	PngFormat2050 WzPngFormat = 0x802 // DXT5
)

func (f WzPngFormat) String() string {
	switch f {
	case PngFormat1:
		return "BGRA4444"
	case PngFormat2:
		return "BGRA32"
	case PngFormat3:
		return "DXT3"
	case PngFormat257:
		return "ARGB1555"
	case PngFormat513:
		return "RGB565"
	case PngFormat517:
		return "RGB565_Variant"
	case PngFormat1026:
		return "DXT3_Variant"
	case PngFormat2050:
		return "DXT5"
	default:
		return "Unknown"
	}
}
