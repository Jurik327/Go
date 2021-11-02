package vulndb

import (
	"encoding/xml"
	"os"
)

// xmlVendorAliases represents vendor aliases from XML file.
type xmlVendorAliases struct {
	Aliases []xmlVendorAlias `xml:"vendor-alias"`
}

type xmlVendorAlias struct {
	ForName string `xml:"for,attr"`
	Alias   string `xml:",chardata"`
}

// loadVendorAliases loads the vendor aliases from XML file and returns as xmlVendorAliases.
func loadVendorAliases(inputPath string) (*xmlVendorAliases, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}

	var aliases xmlVendorAliases

	decoder := xml.NewDecoder(f)
	err = decoder.Decode(&aliases)
	if err != nil {
		return nil, err
	}

	return &aliases, err
}
