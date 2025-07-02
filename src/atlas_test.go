package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestGetHostsFromConnectionString tests the GetHostsFromConnectionString function
// with various valid and invalid inputs.
func TestGetHostsFromConnectionString(t *testing.T) {
	testCases := []struct {
		name          string
		connStr       string
		expectedHosts []string
		expectErr     bool
	}{
		{
			name:          "standard replica set connection string",
			connStr:       "mongodb://test123-shard-00-00.b0cch.mongodb.net:27017,test123-shard-00-01.b0cch.mongodb.net:27017,test123-shard-00-02.b0cch.mongodb.net:27017/?ssl=true&authSource=admin&replicaSet=atlas-6o93v6-shard-0",
			expectedHosts: []string{"test123-shard-00-00.b0cch.mongodb.net", "test123-shard-00-01.b0cch.mongodb.net", "test123-shard-00-02.b0cch.mongodb.net"},
			expectErr:     false,
		},
		{
			name:          "single host with port",
			connStr:       "mongodb://localhost:27017",
			expectedHosts: []string{"localhost"},
			expectErr:     false,
		},
		{
			name:          "single host without port",
			connStr:       "mongodb://localhost",
			expectedHosts: []string{"localhost"},
			expectErr:     false,
		},
		{
			name:      "invalid connection string",
			connStr:   "not-a-connection-string",
			expectErr: true,
		},
		{
			name:      "empty connection string",
			connStr:   "",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, err := GetHostsFromConnectionString(tc.connStr)

			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected an error, but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !reflect.DeepEqual(hosts, tc.expectedHosts) {
					t.Errorf("Expected hosts %v, but got %v", tc.expectedHosts, hosts)
				}
			}
		})
	}
}

// TestGetAtlasClusterInfo tests the retrieval of cluster information.
func TestGetAtlasClusterInfo(t *testing.T) {
	clusterInfoJSON, err := os.ReadFile(filepath.Join("..", "test_fixtures", "cluster-info-response.json"))
	if err != nil {
		t.Fatalf("Failed to read mock cluster info response: %v", err)
	}

	t.Run("successful retrieval", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Basic validation of the request
			if r.URL.Path != "/api/atlas/v2/groups/project1/clusters/cluster1" {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			if r.Header.Get("Accept") != "application/vnd.atlas.2025-03-12+json" {
				http.Error(w, "Bad Accept header", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(clusterInfoJSON)
		}))
		defer server.Close()

		// Create a client and override its BaseURL to point to our test server.
		client := NewAtlasClient(server.Client())
		client.BaseURL = server.URL

		info, err := client.getAtlasClusterInfo(context.Background(), "pubKey", "privKey", "project1", "cluster1")
		if err != nil {
			t.Fatalf("Expected no error, but got: %v", err)
		}
		if info == nil {
			t.Fatal("Expected cluster info, but got nil")
		}
		expectedConnStr := "mongodb://test123-shard-00-00.b0cch.mongodb.net:27017,test123-shard-00-01.b0cch.mongodb.net:27017,test123-shard-00-02.b0cch.mongodb.net:27017/?ssl=true&authSource=admin&replicaSet=atlas-6o93v6-shard-0"
		if info.ConnectionStrings.Standard != expectedConnStr {
			t.Errorf("Expected connection string '%s', but got '%s'", expectedConnStr, info.ConnectionStrings.Standard)
		}
	})

	t.Run("API error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"detail":"You are not authorized for this resource."}`))
		}))
		defer server.Close()

		client := NewAtlasClient(server.Client())
		client.BaseURL = server.URL

		_, err := client.getAtlasClusterInfo(context.Background(), "pubKey", "privKey", "project1", "cluster1")
		if err == nil {
			t.Fatal("Expected an error, but got none")
		}
		if !strings.Contains(err.Error(), "status 401") {
			t.Errorf("Expected error to contain 'status 401', but got: %v", err)
		}
	})
}

// TestDownloadAndCleanupCycle tests the full flow of downloading and deleting logs.
func TestDownloadAndCleanupCycle(t *testing.T) {
	clusterInfoJSON, _ := os.ReadFile(filepath.Join("..", "test_fixtures", "cluster-info-response.json"))
	dummyLogContent := "this is a fake log file"

	// Use a ServeMux to handle different API endpoints
	mux := http.NewServeMux()

	// Handler for cluster info
	mux.HandleFunc("/api/atlas/v2/groups/project1/clusters/cluster1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(clusterInfoJSON)
	})

	// Handler for log downloads. This will match any log download request.
	mux.HandleFunc("/api/atlas/v2/groups/project1/clusters/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs/mongodb.gz") {
			w.Header().Set("Content-Type", "application/gzip")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(dummyLogContent))
		} else {
			http.NotFound(w, r)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Create a client and point it to our test server
	client := NewAtlasClient(server.Client())
	client.BaseURL = server.URL

	// 1. Download logs
	logFiles, err := client.DownloadClusterLogs(context.Background(), "pubKey", "privKey", "project1", "cluster1", 0, 1)
	if err != nil {
		t.Fatalf("DownloadClusterLogs failed: %v", err)
	}

	// The mock response has 3 hosts
	if len(logFiles) != 3 {
		t.Fatalf("Expected 3 log files, got %d", len(logFiles))
	}

	// 2. Verify files were created and have content
	for _, logFile := range logFiles {
		// Ensure we clean up this file even if the test fails mid-way
		defer os.Remove(logFile)

		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			t.Errorf("Log file %s was not created", logFile)
		}
		content, err := os.ReadFile(logFile)
		if err != nil {
			t.Errorf("Failed to read created log file %s: %v", logFile, err)
		}
		if string(content) != dummyLogContent {
			t.Errorf("Log file content mismatch for %s", logFile)
		}
	}

	// 3. Delete logs
	err = client.DeleteClusterLogs(context.Background(), logFiles)
	if err != nil {
		t.Fatalf("DeleteClusterLogs failed: %v", err)
	}

	// 4. Verify files were deleted
	for _, logFile := range logFiles {
		if _, err := os.Stat(logFile); !os.IsNotExist(err) {
			t.Errorf("Log file %s was not deleted", logFile)
		}
	}
}
