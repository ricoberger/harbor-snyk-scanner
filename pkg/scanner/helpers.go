package scanner

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/ricoberger/harbor-snyk-scanner/pkg/harbor"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/snyk"
)

type ScanRequestID struct {
	Timestamp int64           `json:"timestamp"`
	Location  string          `json:"location"`
	Artifact  harbor.Artifact `json:"artifact"`
}

func createScanRequestID(artifact harbor.Artifact, location string) (string, error) {
	data, err := json.Marshal(ScanRequestID{Timestamp: time.Now().Unix(), Location: location, Artifact: artifact})
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func getScanRequestID(id string) (*ScanRequestID, error) {
	data, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		return nil, err
	}

	var scanRequestID ScanRequestID
	err = json.Unmarshal(data, &scanRequestID)
	if err != nil {
		return nil, err
	}

	return &scanRequestID, nil
}

func createScanReportFromIssues(scanner harbor.Scanner, artifact harbor.Artifact, issues []snyk.Issue) harbor.ScanReport {
	var vulnerabilities []harbor.Vulnerability
	severity := "unknown"

	for _, issue := range issues {
		severity = getSeverity(severity, issue.IssueData.Severity)

		vulnerabilities = append(vulnerabilities, harbor.Vulnerability{
			ID:          issue.ID,
			Pkg:         issue.PkgName,
			Version:     strings.Join(issue.PkgVersions, ", "),
			FixVersion:  strings.Join(issue.FixInfo.FixedIn, ", "),
			Severity:    formatSeverity(issue.IssueData.Severity),
			Description: issue.IssueData.Description,
			Links:       []string{issue.IssueData.URL, issue.Links.Paths},
			PreferredCVSS: &harbor.CVSSDetails{
				ScoreV3:  &issue.IssueData.CvssScore,
				VectorV3: issue.IssueData.CVSSv3,
			},
			CweIDs:           issue.IssueData.Identifiers.Cwe,
			VendorAttributes: map[string]interface{}{},
		})
	}

	return harbor.ScanReport{
		GeneratedAt:     time.Now(),
		Scanner:         scanner,
		Artifact:        artifact,
		Severity:        formatSeverity(severity),
		Vulnerabilities: vulnerabilities,
	}
}

func getSeverity(currentSeverity, newSeverity string) string {
	if currentSeverity == "critical" {
		return currentSeverity
	}

	if currentSeverity == "high" {
		if newSeverity == "critical" {
			return newSeverity
		}

		return currentSeverity
	}

	if currentSeverity == "medium" {
		if newSeverity == "critical" || newSeverity == "high" {
			return newSeverity
		}

		return currentSeverity
	}

	if currentSeverity == "low" {
		if newSeverity == "critical" || newSeverity == "high" || newSeverity == "medium" {
			return newSeverity
		}

		return currentSeverity
	}

	return newSeverity
}

func formatSeverity(severity string) string {
	switch severity {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Unknown"
	}
}
