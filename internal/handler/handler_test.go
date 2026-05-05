package handler_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/cache"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/handler"
	"github.com/tiagowhuber/softserve-url-threat-lookup/internal/lookup"
)

func newTestRouter(t *testing.T) (*gin.Engine, *miniredis.Miniredis) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	c, err := cache.New(100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	svc := lookup.New(rdb, c)
	h := handler.New(svc, slog.Default())

	r := gin.New()
	r.GET("/urlinfo/1/:hostname_port/*path", h.LookupURL)
	r.POST("/admin/urls", h.AddURLs)
	r.GET("/health", h.Health)
	return r, mr
}

func doGet(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	r.ServeHTTP(w, req)
	return w
}

func doPost(r *gin.Engine, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	return m
}

// --- Lookup handler ---

func TestLookupSafeURL(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	w := doGet(r, "/urlinfo/1/safe.com/page")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeBody(t, w.Body)
	if body["safe"] != true {
		t.Errorf("expected safe=true, got %v", body["safe"])
	}
	if body["threat_category"] != "none" {
		t.Errorf("expected threat_category=none, got %v", body["threat_category"])
	}
	if body["url"] != "safe.com/page" {
		t.Errorf("expected url=safe.com/page, got %v", body["url"])
	}
}

func TestLookupMalwareURL(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	mr.Set("evil.com/malware", `{"threat_category":"malware"}`)

	w := doGet(r, "/urlinfo/1/evil.com/malware")
	body := decodeBody(t, w.Body)
	if body["safe"] != false {
		t.Errorf("expected safe=false, got %v", body["safe"])
	}
	if body["threat_category"] != "malware" {
		t.Errorf("expected threat_category=malware, got %v", body["threat_category"])
	}
}

func TestLookupNestedPath(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	// Wildcard *path must capture multiple slash-separated segments.
	mr.Set("evil.com/a/b/c", `{"threat_category":"malware"}`)

	w := doGet(r, "/urlinfo/1/evil.com/a/b/c")
	body := decodeBody(t, w.Body)
	if body["safe"] != false {
		t.Errorf("expected safe=false for nested path, got %v", body["safe"])
	}
	if body["url"] != "evil.com/a/b/c" {
		t.Errorf("unexpected url: %v", body["url"])
	}
}

func TestLookupHostWithPort(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	mr.Set("evil.com:443/path", `{"threat_category":"phishing"}`)

	w := doGet(r, "/urlinfo/1/evil.com:443/path")
	body := decodeBody(t, w.Body)
	if body["safe"] != false {
		t.Errorf("expected safe=false for host:port URL, got %v", body["safe"])
	}
	if body["url"] != "evil.com:443/path" {
		t.Errorf("unexpected url: %v", body["url"])
	}
}

func TestLookupQueryStringIncluded(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	mr.Set("evil.com/path?tracker=abc", `{"threat_category":"spam"}`)

	w := doGet(r, "/urlinfo/1/evil.com/path?tracker=abc")
	body := decodeBody(t, w.Body)
	if body["safe"] != false {
		t.Errorf("expected safe=false when query string matches, got %v", body["safe"])
	}
	if body["url"] != "evil.com/path?tracker=abc" {
		t.Errorf("unexpected url: %v", body["url"])
	}
}

func TestLookupEmptyPath(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	// /urlinfo/1/host.com/ — trailing slash only, path should be stripped to empty.
	w := doGet(r, "/urlinfo/1/host.com/")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeBody(t, w.Body)
	if body["url"] != "host.com" {
		t.Errorf("expected url=host.com (no trailing slash), got %v", body["url"])
	}
}

// --- Health handler ---

func TestHealthOK(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	w := doGet(r, "/health")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeBody(t, w.Body)
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", body["status"])
	}
	if body["redis"] != "ok" {
		t.Errorf("expected redis=ok, got %v", body["redis"])
	}
}

func TestHealthDegraded(t *testing.T) {
	r, mr := newTestRouter(t)
	mr.Close() // Redis down

	w := doGet(r, "/health")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when Redis unreachable, got %d", w.Code)
	}
	body := decodeBody(t, w.Body)
	if body["status"] != "degraded" {
		t.Errorf("expected status=degraded, got %v", body["status"])
	}
}

// --- Admin handler ---

func TestAdminAddURLs(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	body := `[{"url":"new-evil.com/path","threat_category":"malware"}]`
	w := doPost(r, "/admin/urls", body)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodeBody(t, w.Body)
	if resp["added"] != float64(1) {
		t.Errorf("expected added=1, got %v", resp["added"])
	}

	// Verify the URL is now blocked.
	w2 := doGet(r, "/urlinfo/1/new-evil.com/path")
	lookup := decodeBody(t, w2.Body)
	if lookup["safe"] != false {
		t.Errorf("expected URL to be blocked after admin add")
	}
}

func TestAdminAddURLsEmptyBody(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	w := doPost(r, "/admin/urls", "[]")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty list, got %d", w.Code)
	}
}

func TestAdminAddURLsInvalidJSON(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	w := doPost(r, "/admin/urls", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestAdminAddURLsEmptyURL(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	w := doPost(r, "/admin/urls", `[{"url":"","threat_category":"malware"}]`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty url, got %d", w.Code)
	}
}

func TestAdminAddURLsInvalidCategory(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	w := doPost(r, "/admin/urls", `[{"url":"evil.com/path","threat_category":"unknown"}]`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid threat_category, got %d", w.Code)
	}
}

func TestLookupURLTooLong(t *testing.T) {
	r, mr := newTestRouter(t)
	defer mr.Close()

	// Construct a URL longer than 2048 characters.
	long := strings.Repeat("a", 2049)
	w := doGet(r, "/urlinfo/1/host.com/"+long)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized URL, got %d", w.Code)
	}
}
