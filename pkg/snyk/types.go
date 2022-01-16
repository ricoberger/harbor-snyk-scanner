package snyk

import (
	"time"
)

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

type ImportJobResponse struct {
	ID      string    `json:"id"`
	Status  string    `json:"status"`
	Created time.Time `json:"created"`
	Logs    []struct {
		Name     string    `json:"name"`
		Created  time.Time `json:"created"`
		Status   string    `json:"status"`
		Projects []struct {
			TargetFile  string `json:"targetFile,omitempty"`
			Success     bool   `json:"success"`
			UserMessage string `json:"userMessage,omitempty"`
			ProjectURL  string `json:"projectUrl"`
			ProjectID   string `json:"projectId,omitempty"`
		} `json:"projects"`
	} `json:"logs"`
}

type IssuesResponse struct {
	Issues []Issue `json:"issues"`
}

type Issue struct {
	ID            string   `json:"id"`
	IssueType     string   `json:"issueType"`
	PkgName       string   `json:"pkgName"`
	PkgVersions   []string `json:"pkgVersions"`
	PriorityScore int      `json:"priorityScore"`
	Priority      struct {
		Score   int `json:"score"`
		Factors []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"factors"`
	} `json:"priority"`
	IssueData struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		URL         string `json:"url"`
		Description string `json:"description"`
		Identifiers struct {
			Cve []string `json:"CVE"`
			Cwe []string `json:"CWE"`
		} `json:"identifiers"`
		Credit          []string `json:"credit"`
		ExploitMaturity string   `json:"exploitMaturity"`
		Semver          struct {
			Vulnerable []string `json:"vulnerable"`
		} `json:"semver"`
		PublicationTime       time.Time     `json:"publicationTime"`
		DisclosureTime        time.Time     `json:"disclosureTime"`
		CVSSv3                string        `json:"CVSSv3"`
		CvssScore             float64       `json:"cvssScore"`
		Language              string        `json:"language"`
		Patches               []interface{} `json:"patches"`
		NearestFixedInVersion string        `json:"nearestFixedInVersion"`
		IsMaliciousPackage    bool          `json:"isMaliciousPackage"`
	} `json:"issueData"`
	IsPatched bool `json:"isPatched"`
	IsIgnored bool `json:"isIgnored"`
	FixInfo   struct {
		IsUpgradable          bool     `json:"isUpgradable"`
		IsPinnable            bool     `json:"isPinnable"`
		IsPatchable           bool     `json:"isPatchable"`
		IsFixable             bool     `json:"isFixable"`
		IsPartiallyFixable    bool     `json:"isPartiallyFixable"`
		NearestFixedInVersion string   `json:"nearestFixedInVersion"`
		FixedIn               []string `json:"fixedIn"`
	} `json:"fixInfo"`
	Links struct {
		Paths string `json:"paths"`
	} `json:"links"`
}
