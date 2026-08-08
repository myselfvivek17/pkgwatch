package daemon

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The hub and an agent's dashboard both want 4875. Co-resident, the agent must
// fall back rather than crash (§2).
func TestListenFallsBackWhenPreferredPortIsTaken(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	takenPort := occupied.Addr().(*net.TCPAddr).Port

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()

	ln, err := Listen("127.0.0.1", takenPort, freePort)
	if err != nil {
		t.Fatalf("Listen should have fallen back, got: %v", err)
	}
	defer ln.Close()

	if got := ln.Addr().(*net.TCPAddr).Port; got != freePort {
		t.Errorf("bound port %d, want fallback %d", got, freePort)
	}
}

func TestListenFailsWhenNoPortIsAvailable(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	if ln, err := Listen("127.0.0.1", port); err == nil {
		ln.Close()
		t.Error("expected an error when every candidate port is taken")
	}
}

func TestHealthHandler(t *testing.T) {
	tests := []struct {
		name       string
		dbOK       bool
		bundle     string
		wantStatus int
		wantBundle string
	}{
		{"healthy", true, "20260808", http.StatusOK, "20260808"},
		{"no bundle yet", true, "", http.StatusOK, "none"},
		{"db down", false, "20260808", http.StatusServiceUnavailable, "20260808"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := HealthHandler("agent", time.Now().Add(-90*time.Second), func() (bool, string) {
				return tt.dbOK, tt.bundle
			})

			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var got Health
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if got.OK != tt.dbOK {
				t.Errorf("ok = %v, want %v", got.OK, tt.dbOK)
			}
			if got.BundleVersion != tt.wantBundle {
				t.Errorf("bundle_version = %q, want %q", got.BundleVersion, tt.wantBundle)
			}
			if got.UptimeSeconds < 89 {
				t.Errorf("uptime_seconds = %d, want ~90", got.UptimeSeconds)
			}
		})
	}
}
