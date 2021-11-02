package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"nanscraper/cvss"
)

const (
	appleCVEURL = `https://support.apple.com/en-us/HT201222`
	appleCVEURL2 = `https://support.apple.com/kb/HT212605`

)

type AppleAdvisory struct {
	AffectedProducts         []AppleAdvisoryAffectedProductItem `json:"affectedProducts"`
	CVENumber                string                             `json:"cveNumber"`
	CVETitle                 string                             `json:"cveTitle"`
	Description              string                             `json:"description"`
	ExploitabilityAssessment map[string]interface{}             `json:"exploitabilityAssessment"`
	Exploited                string                             `json:"exploited"`
	PubliclyDisclosed        string                             `json:"publiclyDisclosed"`
	PublishedDate            string                             `json:"publishedDate"`
	Vulnerability 			 string								`json:"vulnerability"`
	Revisions                []struct {
		Version string `json:"version"`
	} `json:"revisions"`
}

type appleCVSSItem struct {
	CVEID             string
	CVSS3VectorString string
}

type AppleAdvisoryAffectedProductItem struct {
	ArticleTitle1  string  `json:"articleTitle1"`
	BaseScore      float64 `json:"baseScore"`
	Impact         string  `json:"impact"`
	ImpactId       int     `json:"impactId"`
	Name           string  `json:"name"`
	Severity       string  `json:"severity"`
	SeverityId     int     `json:"severityId"`
	DownloadTitle  string  `json:"downloadTitle"`
	DownloadUrl    string  `json:"downloadUrl"`
	VectorString   string  `json:"vectorString"` // CVSS3.
	Supersedence   string  `json:"supersedence"`
}

func queryApple(cveID string) (*appleCVSSItem, error) {
	url := appleCVEURL + cveID

	fmt.Println(url)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var advisory AppleAdvisory
	err = json.Unmarshal(contents, &advisory)
	if err != nil {
		return nil, err
	}

	var score *cvss.CVSS3Vector
	for _, ap := range advisory.AffectedProducts {
		if len(ap.VectorString) == 0 {
			continue
		}
		cvssVector, err := cvss.Parse(ap.VectorString)
		if err != nil {
			fmt.Printf("Error parsing vector string: %v (%s)\n", err, ap.VectorString)
			return nil, err
		}
		cvss3 := cvssVector.ToCVSS3()
		if score == nil || cvss3.TemporalScore() > score.TemporalScore() {
			score = &cvss3
		}
	}

	item := appleCVSSItem{
		CVEID: advisory.CVENumber,
	}
	if score != nil {
		item.CVSS3VectorString = score.VectorString()
	}

	return &item, nil
}
