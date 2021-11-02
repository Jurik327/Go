package vulndb

import (
	"encoding/xml"
	"os"
)

// xmlProductIgnoreList represents product vendor/product ignore list from XML file.
type xmlProductIgnoreList struct {
	Items []xmlProductIgnoreItem `xml:"ignore"`
}

type xmlProductIgnoreItem struct {
	VendorName  string `xml:"vendor,attr"`
	ProductGlob string `xml:"product,attr"`
}

// loadProductIgnoreList loads the product ignore items from XML file and returns as xmlProductIgnoreList.
func loadProductIgnoreList(inputPath string) (*xmlProductIgnoreList, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}

	var ignoreList xmlProductIgnoreList

	decoder := xml.NewDecoder(f)
	err = decoder.Decode(&ignoreList)
	if err != nil {
		return nil, err
	}

	return &ignoreList, err
}
