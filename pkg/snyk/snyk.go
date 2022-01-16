package snyk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	flag "github.com/spf13/pflag"
)

var (
	apiKey         string
	baseURL        string
	integrationID  string
	organisationID string
)

// init is used to define all flags, which are needed for the Snyk client. These are the base url of the Snyk API, an
// API key and the integration and organisation id.
func init() {
	defaultBaseURL := "https://snyk.io"
	if os.Getenv("SNYK_BASE_URL") != "" {
		defaultBaseURL = os.Getenv("SNYK_BASE_URL")
	}

	defaultAPIKey := ""
	if os.Getenv("SNYK_API_KEY") != "" {
		defaultAPIKey = os.Getenv("SNYK_API_KEY")
	}

	defaultIntegrationID := ""
	if os.Getenv("SNYK_INTEGRATION_ID") != "" {
		defaultIntegrationID = os.Getenv("SNYK_INTEGRATION_ID")
	}

	defaultOrganisationID := ""
	if os.Getenv("SNYK_ORGANISATION_ID") != "" {
		defaultOrganisationID = os.Getenv("SNYK_ORGANISATION_ID")
	}

	flag.StringVar(&apiKey, "snyk.api-key", defaultAPIKey, "The API key to access the Snyk API.")
	flag.StringVar(&baseURL, "snyk.base-url", defaultBaseURL, "The base url of the Snyk API.")
	flag.StringVar(&integrationID, "snyk.integration-id", defaultIntegrationID, "The id of the Snyk integration.")
	flag.StringVar(&organisationID, "snyk.organisation-id", defaultOrganisationID, "The id of the Snyk organisation.")
}

type Client interface {
	ImportProject(ctx context.Context, image string) (string, error)
	GetAggregatedIssues(ctx context.Context, image, location string) ([]Issue, error)
}

type client struct {
	apiKey         string
	baseURL        string
	integrationID  string
	organisationID string
	httpClient     *http.Client
}

func (c *client) getAggregatedIssues(ctx context.Context, project string) ([]Issue, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/org/%s/project/%s/aggregated-issues", c.baseURL, c.organisationID, project), bytes.NewBuffer([]byte("{\"includeDescription\": true, \"includeIntroducedThrough\": false, \"filters\": {\"severities\": [\"critical\", \"high\", \"medium\", \"low\"], \"exploitMaturity\": [\"mature\", \"proof-of-concept\", \"no-known-exploit\", \"no-data\"], \"types\": [\"vuln\"], \"ignored\": false, \"patched\": false, \"priority\": {\"score\": {\"min\": 0, \"max\": 1000}}}}")))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token: %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var issuesResponse IssuesResponse
		err = json.NewDecoder(resp.Body).Decode(&issuesResponse)
		if err != nil {
			return nil, err
		}

		return issuesResponse.Issues, nil
	}

	var res ErrorResponse

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("%s", res.Message)
}

func (c *client) ImportProject(ctx context.Context, image string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/org/%s/integrations/%s/import", c.baseURL, c.organisationID, c.integrationID), bytes.NewBuffer([]byte(fmt.Sprintf("{\"target\": {\"name\": \"%s\"}}", image))))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token: %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.Header.Get("location"), nil
	}

	var res ErrorResponse

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return "", err
	}

	return "", fmt.Errorf("%s", res.Message)
}

func (c *client) GetAggregatedIssues(ctx context.Context, image, location string) ([]Issue, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token: %s", c.apiKey))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var importJob ImportJobResponse

		err = json.NewDecoder(resp.Body).Decode(&importJob)
		if err != nil {
			return nil, err
		}

		if importJob.Status != "complete" {
			return nil, fmt.Errorf("import job is not completed yet")
		}

		var projectIDs []string
		for _, log := range importJob.Logs {
			if log.Name == image {
				for _, project := range log.Projects {
					if project.Success {
						projectIDs = append(projectIDs, project.ProjectID)
					}
				}
			}
		}

		var issues []Issue
		var issuesErr error

		var wg sync.WaitGroup
		wg.Add(len(projectIDs))

		for _, project := range projectIDs {
			go func(project string) {
				tmpIssues, err := c.getAggregatedIssues(ctx, project)
				if err != nil {
					issuesErr = err
				} else {
					issues = append(issues, tmpIssues...)
				}

				wg.Done()
			}(project)
		}

		wg.Wait()

		return issues, issuesErr
	}

	var res ErrorResponse

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("%s", res.Message)
}

func NewClient() Client {
	return &client{
		apiKey:         apiKey,
		baseURL:        baseURL,
		integrationID:  integrationID,
		organisationID: organisationID,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}
