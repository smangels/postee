package actions

import (
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strconv"
)

type DefectDojoAction struct {
	apiKey           string
	apiUrl           string
	minimumSeverity  string
	ddActive         bool
	ddVerified       bool
	ddScanType       string
	ddProductName    string
	ddEngagementName string
	ddEngagementId   string
}

func scanTypeIsSupported(scanType string) bool {
	switch scanType {
	case "Trivy Operator Scan", "Nmap Scan":
		return true
	}
	return false
}

func apiUrlIsValid(apiUrl string) error {
	url, err := url.Parse(apiUrl)
	if url.Host == "" {
		myerror := fmt.Errorf("Received invalid URL (no hostname found)\"%s\"", apiUrl)
		return myerror
	}
	if err != nil {
		myerror := fmt.Errorf("Received invalid URL \"%s\"", apiUrl)
		return myerror
	}
	return nil
}

func apiKeyIsValid(apiKey string) error {
	var re = regexp.MustCompile(`(?m)[0-9a-f]{40}`)

	if re.Find([]byte(apiKey)) == nil {
		myerror := fmt.Errorf("Invalid length of DefectDojo API key, expected 40 chars, got %d chars", len(apiKey))
		return myerror
	}

	return nil

}

var supportedScanTypes = []string{
	"Trivy Operator Scan",
	"Nmap Scan",
}

const ddApiPath = "api/v2"

func (dd *DefectDojoAction) Init() error {
	log.Printf("Starting DefectDojo action %q... on URL %s", dd.ddProductName, dd.apiUrl)

	if !scanTypeIsSupported(dd.ddScanType) {
		myerror := fmt.Errorf("")
		return myerror
	}

	id, err := strconv.Atoi(dd.ddEngagementId)
	if err != nil {
		myerror := fmt.Errorf("failed to convert ddEngagementId %s", err)
		return myerror
	}

	if id <= 0 {
		myerror := fmt.Errorf("received invalid ID, should be > 0, received %d", id)
		return myerror
	}

	err = apiUrlIsValid(dd.apiUrl)
	if err != nil {
		return err
	}

	err = apiKeyIsValid(dd.apiKey)
	if err != nil {
		return err
	}

	// everything is fine
	return nil
}

func (dd *DefectDojoAction) GetName() string {
	return dd.ddProductName
}

func (dd DefectDojoAction) Send() error {
	log.Printf("DefectDojo action \"%s\", sent", dd.ddProductName)
	return nil
}

func (dd *DefectDojoAction) Terminate() error {
	log.Printf("DefectDojo action \"%s\" terminated", dd.ddProductName)
	return nil
}
