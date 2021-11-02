package vulndb

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"gopkg.in/cheggaaa/pb.v1"
)

const (
	urlFormat = "https://www.redhat.com/security/data/oval/v2/RHEL%s/rhel-%s.oval.xml.bz2"
	retry     = 5
)

var (
	releases = []string{"6", "7", "8"}
)

func processRedhatOvalData(sessionw *VulnDBSession) error {
	log.Debug("Fetching Red Hat OVAL data...")
	for _, release := range releases {
		if err := update(sessionw, release); err != nil {
			return err
		}
	}
	return nil
}

func update(sessionw *VulnDBSession, release string) error {
	var advisories []NVDCVEAdvisory
	if err := sessionw.Find(&advisories); err != nil {
		return err
	}
	advisoryIDs := map[string]int64{}
	for _, advisory := range advisories {
		advisoryIDs[advisory.CVEID] = advisory.Id
	}
	var platform platforms
	ok, err := sessionw.Where(`display_name = ?`, "Redhat Linux "+release).Get(&platform)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid Redhat release")
	}
	var platformVuln []platformVulnerabilities
	if err := sessionw.Find(&platformVuln); err != nil {
		return err
	}
	uniqueMapping := map[string]bool{}
	for _, p := range platformVuln {
		uniqueMapping[fmt.Sprintf("%v:%v", p.PlatformID, p.VulnerabilityId)] = true
	}
	url := fmt.Sprintf(urlFormat, release, release)
	res, err := FetchURL(url, "", retry)
	if err != nil {
		return err
	}
	bzr := bzip2.NewReader(bytes.NewBuffer(res))
	log.Debugf("Updating Red Hat %s OVAL data...\n", release)
	ovalroot := Root{}
	if err = xml.NewDecoder(bzr).Decode(&ovalroot); err != nil {
		return err
	}
	var count int64
	bar := pb.StartNew(len(ovalroot.Definitions.Definitions))
	for _, def := range ovalroot.Definitions.Definitions {
		for _, cve := range def.Advisory.Cves {
			advisoryID, has := advisoryIDs[cve.CveID]
			if has {
				key := fmt.Sprintf("%v:%v", platform.ID, advisoryID)
				if _, ok := uniqueMapping[key]; !ok {
					var platformVuln platformVulnerabilities
					platformVuln.PlatformID = platform.ID
					platformVuln.VulnerabilityId = advisoryID
					platformVuln.Source = SourceRedhatOVAL
					err = sessionw.Insert(&platformVuln)
					if err != nil {
						return err
					}
					uniqueMapping[key] = true
				}
				continue
			}
			count++
			var advisory NVDCVEAdvisory
			advisory.CVEID = cve.CveID
			advisory.Summary = def.Description
			timeLayout := "2006-01-02"
			pubDate, err := time.Parse(timeLayout, def.Advisory.Issued.Date)
			if err != nil {
				log.Errorf("ERROR: Unable to parse pub date: %v", err)
				continue
			}
			advisory.PublishedAt = pubDate.Unix()
			updateAt, err := time.Parse(timeLayout, def.Advisory.Updated.Date)
			if err != nil {
				log.Errorf("ERROR: Unable to parse pub date: %v", err)
				continue
			}
			advisory.LastModifiedAt = updateAt.Unix()
			advisory.CVSS3VectorString = &cve.Cvss3
			advisory.VendorRefUrl = &cve.Href
			err = sessionw.Insert(&advisory)
			if err != nil {
				return err
			}
			advisoryIDs[cve.CveID] = advisory.Id
			var platformVuln platformVulnerabilities
			platformVuln.PlatformID = platform.ID
			platformVuln.VulnerabilityId = advisory.Id
			platformVuln.Source = SourceRedhatOVAL
			err = sessionw.Insert(&platformVuln)
			if err != nil {
				return err
			}
			uniqueMapping[fmt.Sprintf("%v:%v", platform.ID, advisory.Id)] = true
		}
		bar.Increment()
	}
	log.Debugf("added %v advisories from Redhat %v oval", count, release)
	bar.Finish()
	return nil
}
