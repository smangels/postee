package actions

import (
	"fmt"
	"log"
	"strconv"
)

type DefectDojoAction struct {
	APIKey           string
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

var supportedScanTypes = []string{
	"Trivy Operator Scan",
	"Nmap Scan",
}

func (dd *DefectDojoAction) Init() error {
	log.Printf("Starting DefectDojo action %q...", dd.ddProductName)

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
	return nil
}

func (dd *DefectDojoAction) GetName() string {
	return dd.ddProductName
}
