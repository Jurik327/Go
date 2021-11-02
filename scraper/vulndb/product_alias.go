package vulndb

import (
	"encoding/xml"
	"os"
)

// xmlProductAliases represents aliases of vendor/product combinations for reference to the same product.
type xmlProductAliases struct {
	Products []xmlProductAliasEntry `xml:"product"`
}

type xmlProductAliasEntry struct {
	Vendor  string            `xml:"vendor,attr"`
	Product string            `xml:"product,attr"`
	Aliases []xmlProductAlias `xml:"alias"`
}

type xmlProductAlias struct {
	Vendor  string `xml:"vendor,attr"`
	Product string `xml:"product,attr"`
}

// loadProductAliases loads the product aliases from XML file and returns as xmlProductAliases.
func loadProductAliases(inputPath string) (*xmlProductAliases, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}

	var aliases xmlProductAliases

	decoder := xml.NewDecoder(f)
	err = decoder.Decode(&aliases)
	if err != nil {
		return nil, err
	}

	return &aliases, err
}
