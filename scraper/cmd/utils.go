package cmd

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"nanscraper/pkg/models/msrcapi"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func fatalf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}

// downloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory.
func downloadFile(filepath string, url string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		//log.Debugf("Response: %v", resp.StatusCode)
		return errors.New("status != 200")
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func bunzip2File(dstPath, srcPath string) error {
	srcf, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcf.Close()

	dstf, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstf.Close()

	bzip2Reader := bzip2.NewReader(srcf)
	_, err = io.Copy(dstf, bzip2Reader)
	return err
}

// filesize returns file size of input file by path.
func filesize(inputPath string) (int64, error) {
	fi, err := os.Stat(inputPath)
	if err != nil {
		return 0, err
	}

	size := fi.Size()
	return size, nil
}

// sha256GZippedFile returns sha256 hash of contents of GZipped input file.
func sha256GZippedFile(inputPath string) (hash string, err error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return hash, err
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return hash, err
	}

	h := sha256.New()
	if _, err := io.Copy(h, gzReader); err != nil {
		return hash, err
	}

	hash = fmt.Sprintf("%X", h.Sum(nil))
	return hash, nil
}

// nvdCVEMeta represents metadata for NVD CVE xml files.
type nvdCVEMeta struct {
	Size   int64
	GSSize int64
	SHA256 string
}

// loadNVDCVEMeta loads metadata information for NVD CVE xml file from a meta file.
func loadNVDCVEMeta(inputPath string) (nvdCVEMeta, error) {
	meta := nvdCVEMeta{}

	f, err := os.Open(inputPath)
	if err != nil {
		return meta, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}

		switch parts[0] {
		case "size":
			size, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return meta, err
			}
			meta.Size = size
		case "gzSize":
			gzSize, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return meta, err
			}
			meta.GSSize = gzSize
		case "sha256":
			meta.SHA256 = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return meta, err
	}

	return meta, nil
}

// Check if XML is valid.  Returns an error if invalid.
func IsValidXMLFile(filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Basic generic xml schema.
	var xmlSchema []struct {
		XMLName xml.Name
		Items   []struct {
			XMLName    xml.Name
			Attributes []xml.Attr `xml:",any,attr"`
		} `xml:",any"`
		Attributes []xml.Attr `xml:",any,attr"`
	}

	return xml.Unmarshal(data, &xmlSchema)
}

// Check if XML is valid.  Returns an error if invalid.
func IsValidPlatformXMLFile(filePath string) (map[string][]string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Basic generic xml schema.
	var xmlSchema struct {
		XMLName xml.Name
		Product []struct {
			XMLName  xml.Name
			ID       string   `xml:"id,attr"`
			Product  string   `xml:"product,attr"`
			Platfrom []string `xml:",any"`
		} `xml:",any"`
	}
	if err := xml.Unmarshal(data, &xmlSchema); err != nil {
		return nil, err
	}
	mp := make(map[string][]string)
	for _, p := range xmlSchema.Product {
		mp[p.ID] = p.Platfrom
		mp[p.Product] = p.Platfrom
	}
	return mp, nil
}

// Check if JSON is valid.  Returns an error if invalid.
func IsValidJSONFile(filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	sceham := msrcapi.Result{}
	return json.Unmarshal(data, &sceham)
}
