/*
  This actions is supposed to import supported scan types (i.e. NMAP ports scan, TrivyOperator scans) into
  a so-called DefectDojo engagement. The idea here is to let a REGO filter to decide which environment it comes
  from and then address a certain Postee action that is unique for each engagement.
*/

package actions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type ddAction struct {
	name           string
	ddScanType     string
	ddEngagementId string
	expectError    bool
}

var getNameTCs = []ddAction{
	{"getName-1", "Nmap Scan", "8982391823", false},
	{"getName-2", "Trivy Operator Scan", "984989384", false},
}

var initTCs = []ddAction{
	{"init-1", "Nmap Scan", "897987987", false},
	{"init-2", "Unknown Scan Type", "897987987", true},
}

func TestDD_GetName(t *testing.T) {

	for _, test := range getNameTCs {
		dd := DefectDojoAction{ddProductName: test.name, ddScanType: test.ddScanType, ddEngagementId: test.ddEngagementId}
		if test.expectError {
			require.Error(t, dd.Init())
		} else {
			require.NoError(t, dd.Init())
			require.Equal(t, test.name, dd.GetName())
		}
	}
}

func Test_DD_Init(t *testing.T) {
	for _, test := range initTCs {
		dd := DefectDojoAction{
			ddProductName:  test.name,
			ddScanType:     test.ddScanType,
			ddEngagementId: test.ddEngagementId,
		}
		if test.expectError {
			require.Error(t, dd.Init())
		} else {
			require.NoError(t, dd.Init())
		}
	}
}

func Test_DD_Send(t *testing.T) {
	// test standard action function Send()
	dd := DefectDojoAction{
		ddProductName:  "checkSend",
		ddScanType:     "Nmap Scan",
		ddEngagementId: "46",
	}

	require.NoError(t, dd.Send())
}

func Test_DD_Terminate(t *testing.T) {
	// create an instance and terminate it
	dd := DefectDojoAction{
		ddProductName:  "checkTerminate",
		ddScanType:     "Nmap Scan",
		ddEngagementId: "23123123",
	}

	require.NoError(t, dd.Terminate())

}
