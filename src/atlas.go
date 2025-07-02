package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/mongodb-forks/digest"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

const atlasAPIBaseURL = "https://cloud.mongodb.com"

type AtlasClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewAtlasClient(httpClient *http.Client) *AtlasClient {
	if httpClient == nil {
		// Always use a new http.Client to avoid sharing the default client's Transport (which may be nil)
		httpClient = &http.Client{}
	}
	return &AtlasClient{
		BaseURL:    atlasAPIBaseURL,
		HTTPClient: httpClient,
	}
}

func (c *AtlasClient) getAtlasClusterInfo(ctx context.Context, publicKey, privateKey, projectID, clusterName string) (*AtlasClusterInfo, error) {
	url := fmt.Sprintf("%s/api/atlas/v2/groups/%s/clusters/%s", c.BaseURL, projectID, clusterName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.atlas.2025-03-12+json")

	// Use Digest authentication
	digestTransport := &digest.Transport{
		Username: publicKey,
		Password: privateKey,
	}
	client := c.HTTPClient
	if client == http.DefaultClient {
		client = &http.Client{
			Transport: digestTransport,
			Timeout:   c.HTTPClient.Timeout,
		}
	} else {
		baseTransport := c.HTTPClient.Transport
		if baseTransport == nil {
			baseTransport = http.DefaultTransport
		}
		digestTransport.Transport = baseTransport
		client = &http.Client{
			Transport: digestTransport,
			Timeout:   c.HTTPClient.Timeout,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var info AtlasClusterInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &info, nil
}

func (c *AtlasClient) DownloadClusterLogs(ctx context.Context, publicKey, privateKey, projectID, clusterName string, startDate int, endDate int) ([]string, error) {
	fmt.Fprintln(os.Stdout, "Downloading Atlas cluster logs...")
	atlasClusterInfo, error := c.getAtlasClusterInfo(ctx, publicKey, privateKey, projectID, clusterName)
	if error != nil {
		return nil, fmt.Errorf("failed to get cluster info: %w", error)
	}
	hosts, err := GetHostsFromConnectionString(atlasClusterInfo.ConnectionStrings.Standard)
	if err != nil {
		return nil, fmt.Errorf("failed to get hosts from connection string: %w", err)
	}
	var logFiles []string
	for _, host := range hosts {
		fmt.Fprintf(os.Stdout, "Downloading logs for host %s...\n", host)
		logFile, err := c.downloadClusterLogsForHost(ctx, publicKey, privateKey, projectID, host, startDate, endDate)
		if err != nil {
			// If one host fails, we should clean up what we've downloaded so far
			_ = c.DeleteClusterLogs(ctx, logFiles)
			return nil, fmt.Errorf("failed to download logs for host %s: %w", host, err)
		}
		logFiles = append(logFiles, logFile)
	}
	return logFiles, nil
}

func (c *AtlasClient) DeleteClusterLogs(ctx context.Context, logFiles []string) error {
	var errs []string
	for _, logFile := range logFiles {
		if err := os.Remove(logFile); err != nil {
			// Log the error and continue, since we want to try deleting all files
			errStr := fmt.Sprintf("failed to delete log file %s: %v", logFile, err)
			fmt.Fprintln(os.Stderr, errStr)
			errs = append(errs, errStr)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("encountered errors during log cleanup:\n%s", strings.Join(errs, "\n"))
	}
	fmt.Fprintln(os.Stdout, "Cleaned up temporary files")
	return nil
}

func (c *AtlasClient) downloadClusterLogsForHost(ctx context.Context, publicKey, privateKey, projectID, host string, startDate int, endDate int) (string, error) {
	url := fmt.Sprintf(
		"%s/api/atlas/v2/groups/%s/clusters/%s/logs/mongodb.gz?endDate=%d&startDate=%d",
		c.BaseURL, projectID, host, endDate, startDate,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.atlas.2023-02-01+gzip")
	req.Header.Set("Content-Type", "application/gzip")

	digestTransport := &digest.Transport{
		Username: publicKey,
		Password: privateKey,
	}
	client := c.HTTPClient
	if client == http.DefaultClient {
		client = &http.Client{
			Transport: digestTransport,
			Timeout:   c.HTTPClient.Timeout,
		}
	} else {
		baseTransport := c.HTTPClient.Transport
		if baseTransport == nil {
			baseTransport = http.DefaultTransport
		}
		digestTransport.Transport = baseTransport
		client = &http.Client{
			Transport: digestTransport,
			Timeout:   c.HTTPClient.Timeout,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("mongod_%s_%d_%d_*.log.gz", host, startDate, endDate))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to write log to temp file: %w", err)
	}

	return tmpFile.Name(), nil
}

func GetHostsFromConnectionString(connectionString string) ([]string, error) {
	cs, err := connstring.Parse(connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}
	if cs.Scheme == "mongodb+srv" {
		// For SRV records, the host is the only part we need
		return cs.Hosts, nil
	}

	hosts := make([]string, 0, len(cs.Hosts))
	for _, hostPort := range cs.Hosts {
		host, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			// Handle cases like "localhost" where port is missing
			if addrErr, ok := err.(*net.AddrError); ok && strings.Contains(addrErr.Err, "missing port") {
				host = hostPort
			} else {
				return nil, fmt.Errorf("failed to split host and port from '%s': %w", hostPort, err)
			}
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

type AtlasClusterInfo struct {
	ConnectionStrings struct {
		Standard    string `json:"standard"`
		StandardSrv string `json:"standardSrv"`
	} `json:"connectionStrings"`
}
