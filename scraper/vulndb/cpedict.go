package vulndb

import (
	"compress/gzip"
	"encoding/xml"
	"os"
)

// xmlCPEDict represents content of the official CPE dictionary xml file.
type xmlCPEDict struct {
	Items []xmlCPEItem `xml:"cpe-item"`
}

type xmlCPEItem struct {
	Name       string  `xml:"name,attr"`
	Deprecated *string `xml:"deprecated,attr"`
	Title      string  `xml:"title"`
	CPE23      CPE23   `xml:"cpe23-item"`
}

// CPE23 represents <cpe23-item> xml item.
type CPE23 struct {
	Name string `xml:"name,attr"`
}

// loadCPEDict loads the CPE dictionary from xml file and returns as CPEDict.
func loadCPEDict(inputPath string) (*xmlCPEDict, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	var cpeDict xmlCPEDict

	decoder := xml.NewDecoder(gzReader)
	err = decoder.Decode(&cpeDict)
	if err != nil {
		return nil, err
	}

	return &cpeDict, err
}
