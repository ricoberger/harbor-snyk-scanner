package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ricoberger/harbor-snyk-scanner/pkg/harbor"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/log"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/scanner/middleware/render"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/version"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

var (
	scannerData = harbor.Scanner{
		Name:    "Harbor Snyk Scanner",
		Vendor:  "Rico Berger",
		Version: version.Version,
	}
)

func (s *Server) acceptScanRequest(w http.ResponseWriter, r *http.Request) {
	var data harbor.ScanRequest

	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		log.Error(r.Context(), "Could not decode request body", zap.Error(err))
		render.JSON(w, r, http.StatusBadRequest, harbor.SCANNER_ADAPTER_ERROR, harbor.Error{
			Message: fmt.Sprintf("Could not decode request body: %#v", err),
		})
		return
	}

	if data.Artifact.Repository == "" {
		log.Error(r.Context(), "Repository field for artifact is missing in request data")
		render.JSON(w, r, http.StatusUnprocessableEntity, harbor.SCANNER_ADAPTER_ERROR, harbor.Error{
			Message: "Repository field for artifact is missing in request data",
		})
		return
	}

	if data.Artifact.Tag == "" {
		log.Error(r.Context(), "Tag field for artifact is missing in request data")
		render.JSON(w, r, http.StatusUnprocessableEntity, harbor.SCANNER_ADAPTER_ERROR, harbor.Error{
			Message: "Tag field for artifact is missing in request data",
		})
		return
	}

	// To import the image from Harbor into Snyk we just have to provide the repository and tag as image.
	image := fmt.Sprintf("%s:%s", data.Artifact.Repository, data.Artifact.Tag)

	location, err := s.snykClient.ImportProject(r.Context(), image)
	if err != nil {
		log.Error(r.Context(), "Could not import image into Snyk", zap.Error(err), zap.String("image", image))
		render.JSON(w, r, http.StatusInternalServerError, harbor.SCANNER_ADAPTER_ERROR, harbor.Error{
			Message: fmt.Sprintf("Could not import image into Snyk: %#v", err),
		})
		return
	}

	// To identify the image in Snyk we create a base64 encoded id with the artifact, the current timestamp and the
	// returned location from the Snyk API which can be used to check if the import is finished.
	// The current timestamp is needed, so that we can abort the getScanReport request, when the project was import x
	// hours ago and we still get not result from Snyk.
	scanRequestID, err := createScanRequestID(data.Artifact, location)
	if err != nil {
		log.Error(r.Context(), "Could not create scan request id", zap.Error(err), zap.Any("artifact", data.Artifact))
		render.JSON(w, r, http.StatusInternalServerError, harbor.SCANNER_ADAPTER_ERROR, harbor.Error{
			Message: fmt.Sprintf("Could not create scan request id: %#v", err),
		})
		return
	}

	render.JSON(w, r, http.StatusAccepted, harbor.SCANNER_ADAPTER_SCAN_RESPONSE, harbor.ScanResponse{
		ID: scanRequestID,
	})
}

func (s *Server) getScanReport(w http.ResponseWriter, r *http.Request) {
	scanRequestID := chi.URLParam(r, "scan_request_id")

	// The scan request id contains our base64 encoded data. So we have to decode the id to get the artifact and
	// timestamp.
	scanRequestIDData, err := getScanRequestID(scanRequestID)
	if err != nil {
		log.Error(r.Context(), "Invalid scan request id", zap.Error(err), zap.String("scanRequestID", scanRequestID), zap.Any("scanRequestIDData", scanRequestIDData))
		render.JSON(w, r, http.StatusBadRequest, "", harbor.Error{
			Message: fmt.Sprintf("Invalid scan request id: %#v", err),
		})
		return
	}

	scanRequestTime := time.Unix(scanRequestIDData.Timestamp, 0)
	if time.Now().After(scanRequestTime.Add(1 * time.Hour)) {
		log.Error(r.Context(), "Scan request time is older then an hour, do not retry anymore", zap.Time("now", time.Now()), zap.Time("scanRequestTime", scanRequestTime))
		render.JSON(w, r, http.StatusInternalServerError, harbor.SCANNER_ADAPTER_ERROR, harbor.Error{
			Message: "Scan request time is older then an hour, do not retry anymore",
		})
		return
	}

	// We try to get the aggregated issues from Snyk. When this returns an error why say Harbor that it should retry the
	// request after 5 minutes. We do not return an error, because the error would be returned after 1 hour when each
	// retry fails.
	// NOTE: Maybe we can built an exponential backoff to retry after 1 minute, 2 minutes, 4 minutes, ...
	image := fmt.Sprintf("%s:%s", scanRequestIDData.Artifact.Repository, scanRequestIDData.Artifact.Tag)

	issues, err := s.snykClient.GetAggregatedIssues(r.Context(), image, scanRequestIDData.Location)
	if err != nil {
		log.Error(r.Context(), "Could not get aggregated issues from Snyk", zap.Error(err), zap.String("image", image), zap.String("location", scanRequestIDData.Location))
		w.Header().Set("Refresh-After", "60")
		w.WriteHeader(http.StatusFound)
		return
	}

	scanReport := createScanReportFromIssues(scannerData, scanRequestIDData.Artifact, issues)
	render.JSON(w, r, http.StatusOK, harbor.SCANNER_ADAPTER_VULN_REPORT, scanReport)
}

func (s *Server) getMetadata(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, http.StatusOK, harbor.SCANNER_ADAPTER_METADATA, harbor.ScannerAdapterMetadata{
		Scanner: scannerData,
		Capabilities: []harbor.Capability{
			{
				ConsumesMIMETypes: []string{
					"application/vnd.oci.image.manifest.v1+json",
					"application/vnd.docker.distribution.manifest.v2+json",
				},
				ProducesMIMETypes: []string{
					"application/vnd.security.vulnerability.report; version=1.1",
				},
			},
		},
	})
}
