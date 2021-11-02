package vulndb

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/parnurzeal/gorequest"

	"net/url"
	"strings"
)

type CPEParts struct {
	CPEVersion int // 22 for CPE2.2, 23 for CPE 2.3.

	Systype   string
	Vendor    string
	Product   string
	Version   string
	Patch     string
	Edition   string
	Language  string
	SWEdition string
	TargetSW  string
	TargetHW  string
	Other     string
}

// ParseCPE parses CPE strings of format 2.2 and 2.3 into CPEParts.
// Format 2.2: "cpe:/a:vendor:product:version:update:edition:language"
// Format 2.3: "cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other"
func ParseCPE(cpe string) (CPEParts, error) {
	var cpeParts CPEParts

	parts, err := tokenizeString(cpe, ':', '\\')
	if err != nil {
		return cpeParts, err
	}
	if len(parts) < 4 {
		return cpeParts, errors.New("invalid length")
	}

	if parts[1] == "2.3" {
		return parseCPE23(cpe)
	}

	cpeParts.CPEVersion = 22 // CPE 2.2.
	switch parts[1] {
	case "/a":
		cpeParts.Systype = "a"
	case "/o":
		cpeParts.Systype = "o"
	case "/h":
		cpeParts.Systype = "h"
	default:
		return cpeParts, errors.New("invalid type")
	}
	cpeParts.Vendor = cpeDecode(parts[2])
	cpeParts.Product = cpeDecode(parts[3])

	if len(parts) > 4 {
		cpeParts.Version = cpeDecode(parts[4])
	}
	if len(parts) > 5 {
		cpeParts.Patch = cpeDecode(parts[5])
	}
	if len(parts) > 6 {
		cpeParts.Edition = cpeDecode(parts[6])
	}
	if len(parts) > 7 {
		cpeParts.Language = cpeDecode(parts[7])
	}

	return cpeParts, nil
}

// parseCPE23 parses CPE 2.3 string.
func parseCPE23(cpe23str string) (CPEParts, error) {
	var cpeParts CPEParts

	parts, err := tokenizeString(cpe23str, ':', '\\')
	if err != nil {
		return cpeParts, err
	}
	if len(parts) != 13 {
		log.Debugf("Broken CPE23 - skipping (got %d)", len(parts))
		log.Debugf("Broken CPE23: '%s'", cpe23str)
		return cpeParts, errors.New("invalid cpe23")
	}
	if parts[0] != "cpe" && parts[1] != "2.3" {
		log.Debugf("Invalid CPE2.3: '%s'", cpe23str)
		return cpeParts, errors.New("invalid cpe23")
	}

	cpeParts.CPEVersion = 23 // CPE 2.3.
	cpeParts.Systype = parts[2]
	cpeParts.Vendor = cpeDecode(parts[3])
	cpeParts.Product = cpeDecode(parts[4])
	cpeParts.Version = cpeDecode(parts[5])
	cpeParts.Patch = cpeDecode(parts[6])
	cpeParts.Edition = cpeDecode(parts[7])
	cpeParts.Language = cpeDecode(parts[8])
	cpeParts.SWEdition = cpeDecode(parts[9])
	cpeParts.TargetSW = cpeDecode(parts[10])
	cpeParts.TargetHW = cpeDecode(parts[11])
	cpeParts.Other = cpeDecode(parts[12])

	return cpeParts, nil
}

// cpeDecode decodes percentage encoded values.
func cpeDecode(cpe string) string {
	if len(cpe) == 0 {
		return ""
	}

	// Special cases for handling escaped symbols "\(" and "\)" removing the slash.
	cpe = strings.Replace(cpe, `%5c%28`, `%28`, -1)
	cpe = strings.Replace(cpe, `%5c%29`, `%29`, -1)
	cpe = strings.Replace(cpe, `\(`, `(`, -1)
	cpe = strings.Replace(cpe, `\)`, `)`, -1)
	s, _ := url.PathUnescape(cpe)
	return s
}

// tokenizeString splits a string at each non-escaped occurrence of a separator character.
func tokenizeString(s string, sep, escape rune) (tokens []string, err error) {
	var runes []rune
	inEscape := false
	for _, r := range s {
		switch {
		case inEscape:
			inEscape = false
			fallthrough
		default:
			runes = append(runes, r)
		case r == escape:
			inEscape = true
		case r == sep:
			tokens = append(tokens, string(runes))
			runes = runes[:0]
		}
	}
	tokens = append(tokens, string(runes))
	if inEscape {
		err = errors.New("invalid terminal escape")
	}
	return tokens, err
}

// FetchURL returns HTTP response body with retry
func FetchURL(url, apikey string, retry int) (res []byte, err error) {
	for i := 0; i <= retry; i++ {
		if i > 0 {
			wait := math.Pow(float64(i), 2) + float64(RandInt()%10)
			log.Debugf("retry after %f seconds\n", wait)
			time.Sleep(time.Duration(time.Duration(wait) * time.Second))
		}
		res, err = fetchURL(url, apikey)
		if err == nil {
			return res, nil
		}
	}
	return nil, err
}

func fetchURL(url, apikey string) ([]byte, error) {
	req := gorequest.New().Get(url)
	if apikey != "" {
		req.Header.Add("api-key", apikey)
	}
	resp, body, errs := req.Type("text").EndBytes()
	if len(errs) > 0 {
		return nil, errs[0]
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP error. status code: %d, url: %s", resp.StatusCode, url)
	}
	return body, nil
}

func RandInt() int {
	seed, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	return int(seed.Int64())
}
