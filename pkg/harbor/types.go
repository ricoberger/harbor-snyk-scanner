package harbor

import (
	"time"
)

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag"`
	MimeType   string `json:"mime_type,omitempty"`
}

type ScanRequest struct {
	Registry Registry `json:"registry"`
	Artifact Artifact `json:"artifact"`
}

type ScanResponse struct {
	ID string `json:"id"`
}

type ScanReport struct {
	GeneratedAt     time.Time       `json:"generated_at"`
	Artifact        Artifact        `json:"artifact"`
	Scanner         Scanner         `json:"scanner"`
	Severity        string          `json:"severity"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type CVSSDetails struct {
	ScoreV2  *float64 `json:"score_v2,omitempty"`
	ScoreV3  *float64 `json:"score_v3,omitempty"`
	VectorV2 string   `json:"vector_v2"`
	VectorV3 string   `json:"vector_v3"`
}

type Vulnerability struct {
	ID               string                 `json:"id"`
	Pkg              string                 `json:"package"`
	Version          string                 `json:"version"`
	FixVersion       string                 `json:"fix_version,omitempty"`
	Severity         string                 `json:"severity"`
	Description      string                 `json:"description"`
	Links            []string               `json:"links"`
	PreferredCVSS    *CVSSDetails           `json:"preferred_cvss,omitempty"`
	CweIDs           []string               `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]interface{} `json:"vendor_attributes,omitempty"`
}

type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	ConsumesMIMETypes []string `json:"consumes_mime_types"`
	ProducesMIMETypes []string `json:"produces_mime_types"`
}

type Error struct {
	Message string `json:"message"`
}
