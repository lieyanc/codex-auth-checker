package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ── constants ────────────────────────────────────────────────────────────────

const (
	defaultCodexBaseURL = "https://chatgpt.com/backend-api/codex"
	defaultRefreshURL   = "https://auth.openai.com/oauth/token"
	defaultClientID     = "app_EMoamEEZ73f0CkXaXp7hrann"
	defaultVersion      = "0.98.0"
	defaultUserAgent    = "codex_cli_rs/0.98.0 (python-port)"
	defaultConfigPath   = "scanner_config.json"
	repoOwner           = "lieyanc"
	repoName            = "codex-auth-checker"
	binaryBaseName      = "codex-scanner"
)

var buildVersion = "dev"

// ── types ────────────────────────────────────────────────────────────────────

type Config struct {
	AuthDir            string
	BaseURL            string
	QuotaPath          string
	Model              string
	Timeout            time.Duration
	MaxRetries         int
	RefreshBeforeCheck bool
	RefreshURL         string
	OutputJSON         bool
	OutputDir          string
	Delete401          bool
	AssumeYes          bool
	HTTPProxy          string
	HTTPSProxy         string
	NoProxy            string
	ConfigPath         string
	Interval           time.Duration
	Cron               string
	WebhookURL         string
	WebhookHeaders     string
	Concurrency        int
}

type CheckResult struct {
	File            string        `json:"file"`
	Provider        string        `json:"provider"`
	Email           string        `json:"email"`
	AccountID       string        `json:"account_id"`
	StatusCode      *int          `json:"status_code"`
	Unauthorized401 bool          `json:"unauthorized_401"`
	Error           string        `json:"error"`
	ResponsePreview string        `json:"response_preview"`
	Latency         time.Duration `json:"-"`
}

type ScanStats struct {
	TotalFiles     int           `json:"total_files"`
	CodexFiles     int           `json:"codex_files"`
	Unauthorized   int           `json:"unauthorized_401"`
	Errors         int           `json:"errors"`
	TotalDuration  time.Duration `json:"-"`
	ProbeDuration  time.Duration `json:"-"`
	Concurrency    int           `json:"concurrency"`
	Latencies      []time.Duration `json:"-"`
}

type jsonStats struct {
	TotalFiles    int     `json:"total_files"`
	CodexFiles    int     `json:"codex_files"`
	Unauthorized  int     `json:"unauthorized_401"`
	Errors        int     `json:"errors"`
	Concurrency   int     `json:"concurrency"`
	TotalDurationMs int64 `json:"total_duration_ms"`
	ProbeDurationMs int64 `json:"probe_duration_ms"`
	AvgLatencyMs  float64 `json:"avg_latency_ms"`
	MinLatencyMs  float64 `json:"min_latency_ms"`
	MaxLatencyMs  float64 `json:"max_latency_ms"`
	MedianLatencyMs float64 `json:"median_latency_ms"`
	P95LatencyMs  float64 `json:"p95_latency_ms"`
}

type DeleteError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

type CronSchedule struct {
	minutes  []bool // [0..59]
	hours    []bool // [0..23]
	days     []bool // [0..31], index 0 unused
	months   []bool // [0..12], index 0 unused
	weekdays []bool // [0..6], 0=Sunday
}

type jsonOutput struct {
	Results  []jsonResult `json:"results"`
	Stats    *jsonStats   `json:"stats,omitempty"`
	Deletion jsonDeletion `json:"deletion"`
}

type jsonResult struct {
	File            string  `json:"file"`
	Provider        string  `json:"provider"`
	Email           string  `json:"email"`
	AccountID       string  `json:"account_id"`
	StatusCode      *int    `json:"status_code"`
	Unauthorized401 bool    `json:"unauthorized_401"`
	Error           string  `json:"error"`
	ResponsePreview string  `json:"response_preview"`
	LatencyMs       float64 `json:"latency_ms,omitempty"`
}

type jsonDeletion struct {
	Requested    bool          `json:"requested"`
	TargetCount  int           `json:"target_count"`
	Confirmed    bool          `json:"confirmed"`
	DeletedCount int           `json:"deleted_count"`
	DeletedFiles []string      `json:"deleted_files"`
	Errors       []DeleteError `json:"errors"`
}

// ── terminal color / progress helpers ────────────────────────────────────────

var (
	useColor  bool
	cRed      string
	cGreen    string
	cYellow   string
	cCyan     string
	cBold     string
	cDim      string
	cReset    string
	eraseLine string
)

func initColors() {
	fi, err := os.Stderr.Stat()
	if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		useColor = true
	}
	if useColor {
		cRed = "\033[31m"
		cGreen = "\033[32m"
		cYellow = "\033[33m"
		cCyan = "\033[36m"
		cBold = "\033[1m"
		cDim = "\033[2m"
		cReset = "\033[0m"
		eraseLine = "\033[2K\r"
	}
}

func bar(done, total, width int) string {
	filled := 0
	if total > 0 {
		filled = (width*done + total/2) / total
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func num(idx, total int) string {
	w := len(strconv.Itoa(total))
	return fmt.Sprintf("%0*d/%d", w, idx, total)
}

func emit(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}

func emitInline(msg string) {
	fmt.Fprint(os.Stderr, msg)
}

func progressHeader(authDir string, total int) {
	emit(fmt.Sprintf("%sScanning%s %s%s%s", cBold, cReset, cCyan, authDir, cReset))
	emit(fmt.Sprintf("Found %s%d%s JSON file(s)", cBold, total, cReset))
	emit("")
}

func progressChecking(idx, total int, label string, retry int) {
	b := bar(idx-1, total, 20)
	n := num(idx, total)
	if useColor {
		suffix := ""
		if retry > 0 {
			suffix = fmt.Sprintf(" %s(retry %d)%s", cYellow, retry, cReset)
		}
		emitInline(fmt.Sprintf("%s  %s[%s]%s %s[%s]%s  %s%s ...",
			eraseLine, cDim, n, cReset, cCyan, b, cReset, label, suffix))
	} else {
		retryNote := ""
		if retry > 0 {
			retryNote = fmt.Sprintf(" (retry %d)", retry)
		}
		emit(fmt.Sprintf("  [%s] %s%s ...", n, label, retryNote))
	}
}

func progressResult(idx, total int, label, tag, color string) {
	b := bar(idx, total, 20)
	n := num(idx, total)
	if useColor {
		emit(fmt.Sprintf("%s  %s[%s]%s %s[%s]%s  %s%s%s%s  %s",
			eraseLine, cDim, n, cReset, cCyan, b, cReset, cBold, color, tag, cReset, label))
	} else {
		emit(fmt.Sprintf("  [%s] %s  %s", n, tag, label))
	}
}

// ── JSON dot-path utilities ──────────────────────────────────────────────────

func dotGet(data interface{}, dottedKey string) interface{} {
	current := data
	for _, key := range strings.Split(dottedKey, ".") {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[key]
	}
	return current
}

func firstNonEmpty(values ...interface{}) string {
	for _, v := range values {
		if s, ok := v.(string); ok {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func pick(data map[string]interface{}, candidates []string) string {
	vals := make([]interface{}, len(candidates))
	for i, key := range candidates {
		vals[i] = dotGet(data, key)
	}
	return firstNonEmpty(vals...)
}

// ── Codex file identification ────────────────────────────────────────────────

func looksLikeCodex(filename string, payload map[string]interface{}) bool {
	provider := pick(payload, []string{"type", "provider", "metadata.type"})
	if provider != "" {
		return strings.EqualFold(provider, "codex")
	}

	nameLower := strings.ToLower(filepath.Base(filename))
	if strings.HasPrefix(nameLower, "codex-") {
		return true
	}

	accessToken := pick(payload, []string{
		"access_token", "accessToken",
		"token.access_token", "token.accessToken",
		"metadata.access_token", "metadata.accessToken",
		"metadata.token.access_token", "metadata.token.accessToken",
		"attributes.api_key",
	})
	refreshToken := pick(payload, []string{
		"refresh_token", "refreshToken",
		"token.refresh_token", "token.refreshToken",
		"metadata.refresh_token", "metadata.refreshToken",
		"metadata.token.refresh_token", "metadata.token.refreshToken",
	})
	accountID := pick(payload, []string{
		"account_id", "accountId",
		"metadata.account_id", "metadata.accountId",
	})

	return accessToken != "" && (refreshToken != "" || accountID != "")
}

// ── auth field extraction ────────────────────────────────────────────────────

func extractAuthFields(payload map[string]interface{}) map[string]string {
	return map[string]string{
		"provider": firstNonEmpty(pick(payload, []string{"type", "provider", "metadata.type"}), "codex"),
		"email":    pick(payload, []string{"email", "metadata.email", "attributes.email"}),
		"access_token": pick(payload, []string{
			"access_token", "accessToken",
			"token.access_token", "token.accessToken",
			"metadata.access_token", "metadata.accessToken",
			"metadata.token.access_token", "metadata.token.accessToken",
			"attributes.api_key",
		}),
		"refresh_token": pick(payload, []string{
			"refresh_token", "refreshToken",
			"token.refresh_token", "token.refreshToken",
			"metadata.refresh_token", "metadata.refreshToken",
			"metadata.token.refresh_token", "metadata.token.refreshToken",
		}),
		"account_id": pick(payload, []string{
			"account_id", "accountId",
			"metadata.account_id", "metadata.accountId",
		}),
		"base_url": pick(payload, []string{
			"base_url", "baseUrl",
			"metadata.base_url", "metadata.baseUrl",
			"attributes.base_url", "attributes.baseUrl",
		}),
	}
}

// ── utility functions ────────────────────────────────────────────────────────

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") || path == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func loadJSON(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // strip UTF-8 BOM
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func stringVal(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		return s
	}
	return nil
}

// ── HTTP client factory ──────────────────────────────────────────────────────

func buildHTTPClient(httpProxy, httpsProxy, noProxy string, timeout time.Duration, maxConnsPerHost int) *http.Client {
	if httpProxy != "" {
		os.Setenv("HTTP_PROXY", httpProxy)
	}
	if httpsProxy != "" {
		os.Setenv("HTTPS_PROXY", httpsProxy)
	}
	if noProxy != "" {
		os.Setenv("NO_PROXY", noProxy)
		os.Setenv("no_proxy", noProxy)
	}
	if maxConnsPerHost < 2 {
		maxConnsPerHost = 2
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConnsPerHost: maxConnsPerHost,
		},
	}
}

// ── HTTP request helper ──────────────────────────────────────────────────────

func httpRequest(client *http.Client, method, reqURL string, headers map[string]string, body []byte) (int, []byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

// ── token refresh ────────────────────────────────────────────────────────────

func refreshAccessToken(client *http.Client, refreshURL, refreshToken string) (string, string, error) {
	data := url.Values{}
	data.Set("client_id", defaultClientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", "openid profile email")

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
	}

	status, respBody, err := httpRequest(client, "POST", refreshURL, headers, []byte(data.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("refresh request failed: %w", err)
	}
	if status != 200 {
		preview := string(respBody)
		if len(preview) > 300 {
			preview = preview[:300]
		}
		return "", "", fmt.Errorf("refresh failed with %d: %s", status, preview)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", "", fmt.Errorf("refresh response is not valid JSON: %w", err)
	}

	newToken := firstNonEmpty(parsed["access_token"])
	newRefresh := firstNonEmpty(parsed["refresh_token"])
	if newToken == "" {
		return "", "", fmt.Errorf("refresh succeeded but access_token missing")
	}
	return newToken, newRefresh, nil
}

// ── probe request building ───────────────────────────────────────────────────

func buildProbeHeaders(accessToken, accountID string) map[string]string {
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/json",
		"Accept":        "application/json",
		"Version":       defaultVersion,
		"Openai-Beta":   "responses=experimental",
		"User-Agent":    defaultUserAgent,
		"Originator":    "codex_cli_rs",
	}
	if accountID != "" {
		headers["Chatgpt-Account-Id"] = accountID
	}
	return headers
}

func buildProbeBody(model string) []byte {
	payload := map[string]interface{}{
		"model":             model,
		"stream":            false,
		"instructions":      "",
		"input":             "ping",
		"max_output_tokens": 1,
	}
	body, _ := json.Marshal(payload)
	return body
}

// ── per-file probe logic ─────────────────────────────────────────────────────

type retryCallback func(retry int)

func resultTagColor(r CheckResult, maxRetries int) (string, string) {
	if r.StatusCode != nil {
		sc := *r.StatusCode
		tag := strconv.Itoa(sc)
		switch {
		case sc == 401:
			return tag, cRed
		case sc < 400:
			return tag, cGreen
		default:
			return tag, cYellow
		}
	}
	switch {
	case r.Error == "missing access token":
		return "no token", cYellow
	case strings.HasPrefix(r.Error, "refresh"):
		return "refresh failed", cYellow
	default:
		tag := "network error"
		if maxRetries > 0 {
			tag += fmt.Sprintf(" (after %d retries)", maxRetries)
		}
		return tag, cYellow
	}
}

func probeOneFile(cfg *Config, client *http.Client, path string, fields map[string]string, onRetry retryCallback) CheckResult {
	probeStart := time.Now()
	accessToken := fields["access_token"]
	refreshToken := fields["refresh_token"]

	if cfg.RefreshBeforeCheck && refreshToken != "" {
		newToken, _, err := refreshAccessToken(client, cfg.RefreshURL, refreshToken)
		if err != nil {
			return CheckResult{
				File:      path,
				Provider:  fields["provider"],
				Email:     fields["email"],
				AccountID: fields["account_id"],
				Error:     err.Error(),
				Latency:   time.Since(probeStart),
			}
		}
		accessToken = newToken
	}

	if accessToken == "" {
		return CheckResult{
			File:      path,
			Provider:  fields["provider"],
			Email:     fields["email"],
			AccountID: fields["account_id"],
			Error:     "missing access token",
			Latency:   time.Since(probeStart),
		}
	}

	baseURL := fields["base_url"]
	if baseURL == "" {
		baseURL = cfg.BaseURL
	}
	probeURL := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(cfg.QuotaPath, "/")
	headers := buildProbeHeaders(accessToken, fields["account_id"])
	body := buildProbeBody(cfg.Model)

	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 && onRetry != nil {
			onRetry(attempt)
		}
		status, respBody, err := httpRequest(client, "POST", probeURL, headers, body)
		if err == nil {
			preview := string(respBody)
			if len(preview) > 300 {
				preview = preview[:300]
			}
			sc := status
			return CheckResult{
				File:            path,
				Provider:        fields["provider"],
				Email:           fields["email"],
				AccountID:       fields["account_id"],
				StatusCode:      &sc,
				Unauthorized401: status == 401,
				ResponsePreview: preview,
				Latency:         time.Since(probeStart),
			}
		}
		lastErr = err
	}

	return CheckResult{
		File:      path,
		Provider:  fields["provider"],
		Email:     fields["email"],
		AccountID: fields["account_id"],
		Error:     fmt.Sprintf("network error: %v", lastErr),
		Latency:   time.Since(probeStart),
	}
}

// ── file scan main loop ──────────────────────────────────────────────────────

func scanAuthFiles(ctx context.Context, cfg *Config, client *http.Client) ([]CheckResult, ScanStats, error) {
	scanStart := time.Now()
	var stats ScanStats
	stats.Concurrency = cfg.Concurrency
	if stats.Concurrency < 1 {
		stats.Concurrency = 1
	}

	authDir, err := filepath.Abs(expandHome(cfg.AuthDir))
	if err != nil {
		return nil, stats, fmt.Errorf("cannot resolve auth directory: %w", err)
	}
	info, err := os.Stat(authDir)
	if err != nil || !info.IsDir() {
		return nil, stats, fmt.Errorf("auth directory not found: %s", authDir)
	}

	var jsonFiles []string
	_ = filepath.WalkDir(authDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			jsonFiles = append(jsonFiles, path)
		}
		return nil
	})
	sort.Strings(jsonFiles)

	progressHeader(authDir, len(jsonFiles))

	// Phase 1: parse all JSON files and filter codex ones (sequential, fast local I/O)
	type resultSlot struct {
		valid  bool
		result CheckResult
	}
	slots := make([]resultSlot, len(jsonFiles))

	type probeJob struct {
		slotIdx int
		path    string
		fields  map[string]string
		label   string
	}
	var jobs []probeJob

	for i, path := range jsonFiles {
		payload, loadErr := loadJSON(path)
		if loadErr != nil {
			slots[i] = resultSlot{valid: true, result: CheckResult{
				File:     path,
				Provider: "unknown",
				Error:    fmt.Sprintf("parse error: %v", loadErr),
			}}
			continue
		}
		if !looksLikeCodex(path, payload) {
			continue
		}
		fields := extractAuthFields(payload)
		label := fields["email"]
		if label == "" {
			label = filepath.Base(path)
		}
		jobs = append(jobs, probeJob{slotIdx: i, path: path, fields: fields, label: label})
	}

	stats.TotalFiles = len(jsonFiles)

	totalCodex := len(jobs)
	if totalCodex == 0 {
		var results []CheckResult
		for _, s := range slots {
			if s.valid {
				results = append(results, s.result)
			}
		}
		stats.TotalDuration = time.Since(scanStart)
		return results, stats, nil
	}

	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > totalCodex {
		concurrency = totalCodex
	}
	concurrent := concurrency > 1

	if concurrent {
		emit(fmt.Sprintf("Probing %s%d%s codex file(s) with concurrency %s%d%s",
			cBold, totalCodex, cReset, cBold, concurrency, cReset))
		emit("")
	}

	// Phase 2: probe codex files with worker pool
	probeStart := time.Now()
	var mu sync.Mutex
	done := 0

	jobsCh := make(chan probeJob, len(jobs))
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsCh {
				if ctx.Err() != nil {
					return
				}

				// Show "checking" line only in sequential mode
				var onRetry retryCallback
				if !concurrent {
					mu.Lock()
					progressChecking(done+1, totalCodex, job.label, 0)
					mu.Unlock()
					onRetry = func(retry int) {
						mu.Lock()
						progressChecking(done+1, totalCodex, job.label, retry)
						mu.Unlock()
					}
				}

				result := probeOneFile(cfg, client, job.path, job.fields, onRetry)
				slots[job.slotIdx] = resultSlot{valid: true, result: result}

				tag, color := resultTagColor(result, cfg.MaxRetries)
				mu.Lock()
				done++
				progressResult(done, totalCodex, job.label, tag, color)
				mu.Unlock()
			}
		}()
	}

	for _, job := range jobs {
		if ctx.Err() != nil {
			break
		}
		jobsCh <- job
	}
	close(jobsCh)
	wg.Wait()
	stats.ProbeDuration = time.Since(probeStart)

	if ctx.Err() != nil {
		mu.Lock()
		emit(fmt.Sprintf("\n%sInterrupted, stopping scan...%s", cYellow, cReset))
		mu.Unlock()
	}

	// Phase 3: collect results in original file order
	var results []CheckResult
	for _, s := range slots {
		if s.valid {
			results = append(results, s.result)
			if s.result.Latency > 0 {
				stats.Latencies = append(stats.Latencies, s.result.Latency)
			}
			if s.result.Unauthorized401 {
				stats.Unauthorized++
			}
			if s.result.Error != "" {
				stats.Errors++
			}
		}
	}
	stats.CodexFiles = totalCodex
	stats.TotalDuration = time.Since(scanStart)
	return results, stats, nil
}

// ── output formatting ────────────────────────────────────────────────────────

func (s ScanStats) computeJSON() jsonStats {
	js := jsonStats{
		TotalFiles:      s.TotalFiles,
		CodexFiles:      s.CodexFiles,
		Unauthorized:    s.Unauthorized,
		Errors:          s.Errors,
		Concurrency:     s.Concurrency,
		TotalDurationMs: s.TotalDuration.Milliseconds(),
		ProbeDurationMs: s.ProbeDuration.Milliseconds(),
	}
	if len(s.Latencies) == 0 {
		return js
	}
	sorted := make([]time.Duration, len(s.Latencies))
	copy(sorted, s.Latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	js.AvgLatencyMs = float64(total.Microseconds()) / float64(len(sorted)) / 1000.0
	js.MinLatencyMs = float64(sorted[0].Microseconds()) / 1000.0
	js.MaxLatencyMs = float64(sorted[len(sorted)-1].Microseconds()) / 1000.0
	js.MedianLatencyMs = float64(sorted[len(sorted)/2].Microseconds()) / 1000.0
	p95Idx := int(float64(len(sorted)) * 0.95)
	if p95Idx >= len(sorted) {
		p95Idx = len(sorted) - 1
	}
	js.P95LatencyMs = float64(sorted[p95Idx].Microseconds()) / 1000.0
	return js
}

func printStats(stats ScanStats) {
	js := stats.computeJSON()
	emit("")
	emit(fmt.Sprintf("%s── Performance ──%s", cBold, cReset))
	emit(fmt.Sprintf("  Total duration    %s%v%s", cCyan, stats.TotalDuration.Round(time.Millisecond), cReset))
	emit(fmt.Sprintf("  Probe duration    %s%v%s", cCyan, stats.ProbeDuration.Round(time.Millisecond), cReset))
	emit(fmt.Sprintf("  Files scanned     %d total, %s%d%s codex", stats.TotalFiles, cBold, stats.CodexFiles, cReset))
	emit(fmt.Sprintf("  Concurrency       %d", stats.Concurrency))

	if len(stats.Latencies) == 0 {
		return
	}
	emit(fmt.Sprintf("  Avg latency       %s%.0f ms%s", cCyan, js.AvgLatencyMs, cReset))
	emit(fmt.Sprintf("  Min latency       %.0f ms", js.MinLatencyMs))
	emit(fmt.Sprintf("  Max latency       %.0f ms", js.MaxLatencyMs))
	emit(fmt.Sprintf("  Median latency    %.0f ms", js.MedianLatencyMs))
	emit(fmt.Sprintf("  P95 latency       %.0f ms", js.P95LatencyMs))
	if stats.CodexFiles > 0 && stats.ProbeDuration > 0 {
		throughput := float64(stats.CodexFiles) / stats.ProbeDuration.Seconds()
		emit(fmt.Sprintf("  Throughput        %s%.1f req/s%s", cCyan, throughput, cReset))
	}
}

func printTable(results []CheckResult) {
	if len(results) == 0 {
		fmt.Println("No codex auth files found.")
		return
	}

	var unauthorized []CheckResult
	for _, r := range results {
		if r.Unauthorized401 {
			unauthorized = append(unauthorized, r)
		}
	}

	fmt.Printf("Checked codex files: %d\n", len(results))
	fmt.Printf("401 unauthorized files: %d\n", len(unauthorized))
	fmt.Println()

	for _, item := range unauthorized {
		fmt.Printf("[401] %s\n", item.File)
	}
	if len(unauthorized) > 0 {
		fmt.Println()
	}

	var others []CheckResult
	for _, r := range results {
		if !r.Unauthorized401 {
			others = append(others, r)
		}
	}
	if len(others) > 0 {
		fmt.Println("Non-401 results:")
		for _, item := range others {
			status := "-"
			if item.StatusCode != nil {
				status = strconv.Itoa(*item.StatusCode)
			}
			reason := item.Error
			if reason == "" {
				reason = strings.ReplaceAll(item.ResponsePreview, "\n", " ")
				if len(reason) > 120 {
					reason = reason[:120]
				}
			}
			fmt.Printf("[%s] %s :: %s\n", status, item.File, reason)
		}
	}
}

func outputJSON(results []CheckResult, stats ScanStats, requested bool, unauthorizedFiles []string,
	confirmed bool, deletedFiles []string, deleteErrors []DeleteError, outputDir string) {
	if deletedFiles == nil {
		deletedFiles = []string{}
	}
	if deleteErrors == nil {
		deleteErrors = []DeleteError{}
	}

	jResults := make([]jsonResult, len(results))
	for i, r := range results {
		jResults[i] = jsonResult{
			File:            r.File,
			Provider:        r.Provider,
			Email:           r.Email,
			AccountID:       r.AccountID,
			StatusCode:      r.StatusCode,
			Unauthorized401: r.Unauthorized401,
			Error:           r.Error,
			ResponsePreview: r.ResponsePreview,
			LatencyMs:       float64(r.Latency.Microseconds()) / 1000.0,
		}
	}

	js := stats.computeJSON()
	out := jsonOutput{
		Results: jResults,
		Stats:   &js,
		Deletion: jsonDeletion{
			Requested:    requested,
			TargetCount:  len(unauthorizedFiles),
			Confirmed:    confirmed,
			DeletedCount: len(deletedFiles),
			DeletedFiles: deletedFiles,
			Errors:       deleteErrors,
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)

	if outputDir == "" {
		fmt.Print(buf.String())
		return
	}

	dateDir := filepath.Join(outputDir, time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(dateDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "%sWarning:%s cannot create output directory %s: %v, printing to stdout\n",
			cYellow, cReset, dateDir, err)
		fmt.Print(buf.String())
		return
	}
	outPath := filepath.Join(dateDir, "scan_results.json")
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "%sWarning:%s cannot write %s: %v, printing to stdout\n",
			cYellow, cReset, outPath, err)
		fmt.Print(buf.String())
		return
	}
	emit(fmt.Sprintf("%sResults saved to%s %s", cGreen, cReset, outPath))
}

// ── file deletion ────────────────────────────────────────────────────────────

func confirmDeletion(targets []string, assumeYes bool) bool {
	if len(targets) == 0 {
		return false
	}
	if assumeYes {
		return true
	}
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Println("No interactive terminal for confirmation; deletion cancelled. Use --assume-yes to force.")
		return false
	}

	fmt.Println()
	fmt.Printf("Delete %d files with 401? This action cannot be undone.\n", len(targets))
	fmt.Print("Confirm deletion? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

func deleteFiles(paths []string, outputDir string) ([]string, []DeleteError) {
	var deleted []string
	var errors []DeleteError
	seen := map[string]bool{}

	// determine target directory for archiving deleted files
	var archiveDir string
	if outputDir != "" {
		archiveDir = filepath.Join(outputDir, time.Now().Format("2006-01-02"), "deleted")
		if err := os.MkdirAll(archiveDir, 0o755); err != nil {
			emit(fmt.Sprintf("%sWarning:%s cannot create archive directory %s: %v, falling back to permanent deletion",
				cYellow, cReset, archiveDir, err))
			archiveDir = ""
		}
	}

	for _, rawPath := range paths {
		absPath, err := filepath.Abs(rawPath)
		if err != nil {
			absPath = rawPath
		}
		if seen[absPath] {
			continue
		}
		seen[absPath] = true

		if archiveDir != "" {
			// move file to archive directory
			destPath := filepath.Join(archiveDir, filepath.Base(rawPath))
			// avoid overwriting: append counter if duplicate name
			if _, statErr := os.Stat(destPath); statErr == nil {
				ext := filepath.Ext(destPath)
				base := strings.TrimSuffix(destPath, ext)
				for i := 1; ; i++ {
					candidate := fmt.Sprintf("%s_%d%s", base, i, ext)
					if _, statErr := os.Stat(candidate); statErr != nil {
						destPath = candidate
						break
					}
				}
			}
			if err := os.Rename(rawPath, destPath); err != nil {
				// rename failed (cross-device?), try copy+remove
				if copyErr := copyFile(rawPath, destPath); copyErr != nil {
					errors = append(errors, DeleteError{File: rawPath, Error: copyErr.Error()})
					continue
				}
				if rmErr := os.Remove(rawPath); rmErr != nil {
					errors = append(errors, DeleteError{File: rawPath, Error: fmt.Sprintf("archived but remove failed: %v", rmErr)})
					continue
				}
			}
			deleted = append(deleted, rawPath)
		} else {
			if err := os.Remove(rawPath); err != nil {
				errors = append(errors, DeleteError{File: rawPath, Error: err.Error()})
			} else {
				deleted = append(deleted, rawPath)
			}
		}
	}
	return deleted, errors
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func printDeletionSummary(requested bool, targetCount int, confirmed bool, deletedFiles []string, errors []DeleteError, outputDir string) {
	if !requested {
		return
	}
	if targetCount == 0 {
		fmt.Println()
		fmt.Println("Delete mode enabled, but no 401 files found.")
		return
	}
	fmt.Println()
	if !confirmed {
		fmt.Println("Deletion cancelled by user.")
		return
	}
	if outputDir != "" {
		archiveDir := filepath.Join(outputDir, time.Now().Format("2006-01-02"), "deleted")
		fmt.Printf("Deletion completed: %d/%d archived to %s\n", len(deletedFiles), targetCount, archiveDir)
	} else {
		fmt.Printf("Deletion completed: %d/%d removed.\n", len(deletedFiles), targetCount)
	}
	for _, p := range deletedFiles {
		fmt.Printf("[deleted] %s\n", p)
	}
	for _, item := range errors {
		fmt.Printf("[delete-failed] %s :: %s\n", item.File, item.Error)
	}
}

// ── webhook notification ─────────────────────────────────────────────────────

func parseWebhookHeaders(raw string) map[string]string {
	headers := map[string]string{}
	if raw == "" {
		return headers
	}
	for _, pair := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func sendWebhook(cfg *Config, client *http.Client, results []CheckResult, deletedFiles []string, deleteErrors []DeleteError) {
	if cfg.WebhookURL == "" {
		return
	}

	var unauthorized []map[string]string
	for _, r := range results {
		if r.Unauthorized401 {
			unauthorized = append(unauthorized, map[string]string{
				"file":       r.File,
				"email":      r.Email,
				"account_id": r.AccountID,
			})
		}
	}

	if len(unauthorized) == 0 {
		return
	}

	errCount := 0
	for _, r := range results {
		if r.Error != "" {
			errCount++
		}
	}

	payload := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"scan_summary": map[string]interface{}{
			"total_checked":    len(results),
			"unauthorized_401": len(unauthorized),
			"errors":           errCount,
		},
		"unauthorized_401": unauthorized,
	}

	if cfg.Delete401 {
		errorCount := len(deleteErrors)
		files := deletedFiles
		if files == nil {
			files = []string{}
		}
		payload["deletion"] = map[string]interface{}{
			"requested":     true,
			"deleted_count": len(files),
			"deleted_files": files,
			"error_count":   errorCount,
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook: failed to marshal payload: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook: failed to create request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", defaultUserAgent)
	for k, v := range parseWebhookHeaders(cfg.WebhookHeaders) {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook: request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "webhook: server returned %d\n", resp.StatusCode)
	}
}

// ── cron expression parser ───────────────────────────────────────────────────

func parseCronField(field string, min, max int) ([]bool, error) {
	result := make([]bool, max+1)

	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)

		step := 0
		if idx := strings.Index(part, "/"); idx >= 0 {
			s, err := strconv.Atoi(part[idx+1:])
			if err != nil || s <= 0 {
				return nil, fmt.Errorf("invalid step in %q", part)
			}
			step = s
			part = part[:idx]
		}

		var lo, hi int
		if part == "*" {
			lo, hi = min, max
		} else if idx := strings.Index(part, "-"); idx >= 0 {
			var err error
			lo, err = strconv.Atoi(part[:idx])
			if err != nil {
				return nil, fmt.Errorf("invalid range start in %q", part)
			}
			hi, err = strconv.Atoi(part[idx+1:])
			if err != nil {
				return nil, fmt.Errorf("invalid range end in %q", part)
			}
		} else {
			val, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", part)
			}
			lo, hi = val, val
		}

		if lo < min || hi > max || lo > hi {
			return nil, fmt.Errorf("value out of range [%d-%d]: %d-%d", min, max, lo, hi)
		}

		if step == 0 {
			step = 1
		}
		for v := lo; v <= hi; v += step {
			result[v] = true
		}
	}

	return result, nil
}

func parseCron(expr string) (*CronSchedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("expected 5 fields, got %d", len(fields))
	}

	minutes, err := parseCronField(fields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	hours, err := parseCronField(fields[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	days, err := parseCronField(fields[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("day: %w", err)
	}
	months, err := parseCronField(fields[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	weekdays, err := parseCronField(fields[4], 0, 7)
	if err != nil {
		return nil, fmt.Errorf("weekday: %w", err)
	}

	// Normalize: cron weekday 7 == Sunday == 0
	if len(weekdays) > 7 && weekdays[7] {
		weekdays[0] = true
	}
	weekdays = weekdays[:7]

	return &CronSchedule{
		minutes:  minutes,
		hours:    hours,
		days:     days,
		months:   months,
		weekdays: weekdays,
	}, nil
}

func (cs *CronSchedule) matches(t time.Time) bool {
	return cs.minutes[t.Minute()] &&
		cs.hours[t.Hour()] &&
		cs.days[t.Day()] &&
		cs.months[int(t.Month())] &&
		cs.weekdays[int(t.Weekday())]
}

func (cs *CronSchedule) NextAfter(t time.Time) (time.Time, bool) {
	next := t.Truncate(time.Minute).Add(time.Minute)
	limit := next.Add(366 * 24 * time.Hour)
	for next.Before(limit) {
		if cs.matches(next) {
			return next, true
		}
		next = next.Add(time.Minute)
	}
	return time.Time{}, false
}

// ── scheduler ────────────────────────────────────────────────────────────────

func runOneScan(ctx context.Context, cfg *Config, client *http.Client) int {
	results, stats, err := scanAuthFiles(ctx, cfg, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	var unauthorizedFiles []string
	for _, r := range results {
		if r.Unauthorized401 {
			unauthorizedFiles = append(unauthorizedFiles, r.File)
		}
	}

	deleteConfirmed := false
	var deletedFiles []string
	var deleteErrors []DeleteError

	if cfg.Delete401 && len(unauthorizedFiles) > 0 {
		deleteConfirmed = confirmDeletion(unauthorizedFiles, cfg.AssumeYes)
		if deleteConfirmed {
			deletedFiles, deleteErrors = deleteFiles(unauthorizedFiles, cfg.OutputDir)
		}
	}

	if cfg.OutputJSON {
		outputJSON(results, stats, cfg.Delete401, unauthorizedFiles, deleteConfirmed, deletedFiles, deleteErrors, cfg.OutputDir)
	} else {
		printTable(results)
		printDeletionSummary(cfg.Delete401, len(unauthorizedFiles), deleteConfirmed, deletedFiles, deleteErrors, cfg.OutputDir)
		printStats(stats)
	}

	sendWebhook(cfg, client, results, deletedFiles, deleteErrors)

	if len(unauthorizedFiles) > 0 {
		return 1
	}
	return 0
}

func runWithInterval(ctx context.Context, cfg *Config, client *http.Client) int {
	emit(fmt.Sprintf("%sScheduled mode:%s interval=%v", cBold, cReset, cfg.Interval))
	emit("")

	runOneScan(ctx, cfg, client)

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			emit(fmt.Sprintf("\n%sShutting down gracefully...%s", cYellow, cReset))
			return 0
		case <-ticker.C:
			emit(fmt.Sprintf("\n%s── Scan cycle at %s ──%s",
				cBold, time.Now().Format("2006-01-02 15:04:05"), cReset))
			runOneScan(ctx, cfg, client)
		}
	}
}

func runWithCron(ctx context.Context, cfg *Config, client *http.Client, sched *CronSchedule) int {
	emit(fmt.Sprintf("%sScheduled mode:%s cron=%q", cBold, cReset, cfg.Cron))
	emit("")

	for {
		next, ok := sched.NextAfter(time.Now())
		if !ok {
			fmt.Fprintln(os.Stderr, "Error: no next cron trigger within 366 days")
			return 2
		}

		wait := time.Until(next)
		emit(fmt.Sprintf("Next scan at %s (in %v)",
			next.Format("2006-01-02 15:04:05"), wait.Round(time.Second)))

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			emit(fmt.Sprintf("\n%sShutting down gracefully...%s", cYellow, cReset))
			return 0
		case <-timer.C:
			emit(fmt.Sprintf("\n%s── Scan cycle at %s ──%s",
				cBold, time.Now().Format("2006-01-02 15:04:05"), cReset))
			runOneScan(ctx, cfg, client)
		}
	}
}

// ── config loading + three-layer merge ───────────────────────────────────────

func configGet(fc map[string]interface{}, key string) interface{} {
	if fc == nil {
		return nil
	}
	if v, ok := fc[key]; ok {
		return v
	}
	dashKey := strings.ReplaceAll(key, "_", "-")
	if v, ok := fc[dashKey]; ok {
		return v
	}
	return nil
}

func coerceBool(v interface{}) (bool, error) {
	switch val := v.(type) {
	case bool:
		return val, nil
	case float64:
		if val == 0 {
			return false, nil
		}
		if val == 1 {
			return true, nil
		}
	case string:
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "1", "true", "yes", "y", "on":
			return true, nil
		case "0", "false", "no", "n", "off":
			return false, nil
		}
	}
	return false, fmt.Errorf("not a boolean value: %v", v)
}

func resolveStr(cliVal string, cliWasSet bool, fc map[string]interface{}, key, def string) string {
	if cliWasSet {
		return cliVal
	}
	if v := configGet(fc, key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func resolveFloat64(cliVal float64, cliWasSet bool, fc map[string]interface{}, key string, def float64) (float64, error) {
	if cliWasSet {
		return cliVal, nil
	}
	if v := configGet(fc, key); v != nil {
		switch n := v.(type) {
		case float64:
			return n, nil
		case string:
			return strconv.ParseFloat(n, 64)
		}
	}
	return def, nil
}

func resolveInt(cliVal int, cliWasSet bool, fc map[string]interface{}, key string, def int) (int, error) {
	if cliWasSet {
		return cliVal, nil
	}
	if v := configGet(fc, key); v != nil {
		switch n := v.(type) {
		case float64:
			return int(n), nil
		case string:
			return strconv.Atoi(n)
		}
	}
	return def, nil
}

func resolveBool(cliVal bool, cliWasSet bool, fc map[string]interface{}, key string, def bool) (bool, error) {
	if cliWasSet {
		return cliVal, nil
	}
	if v := configGet(fc, key); v != nil {
		return coerceBool(v)
	}
	return def, nil
}

func extractProxyFromConfig(fc map[string]interface{}) (httpProxy, httpsProxy, noProxy string) {
	proxy := map[string]interface{}{}
	if raw, ok := fc["proxy"]; ok {
		if m, ok := raw.(map[string]interface{}); ok {
			proxy = m
		}
	}
	httpProxy = firstNonEmpty(
		stringVal(proxy["http"]),
		stringVal(proxy["http_proxy"]),
		stringVal(configGet(fc, "http_proxy")),
	)
	httpsProxy = firstNonEmpty(
		stringVal(proxy["https"]),
		stringVal(proxy["https_proxy"]),
		stringVal(configGet(fc, "https_proxy")),
	)
	noProxy = firstNonEmpty(
		stringVal(proxy["no_proxy"]),
		stringVal(configGet(fc, "no_proxy")),
	)
	return
}

// ── self-update (OTA) ────────────────────────────────────────────────────────

type ghRelease struct {
	TagName string  `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func selfUpdate(httpProxy, httpsProxy, noProxy string) {
	if buildVersion == "dev" {
		fmt.Fprintf(os.Stderr, "%s[update]%s skipped (dev build)\n", cDim, cReset)
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[update]%s cannot determine executable: %v\n", cYellow, cReset, err)
		return
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[update]%s cannot resolve path: %v\n", cYellow, cReset, err)
		return
	}

	// set proxy env so http.ProxyFromEnvironment picks them up
	if httpProxy != "" {
		os.Setenv("HTTP_PROXY", httpProxy)
	}
	if httpsProxy != "" {
		os.Setenv("HTTPS_PROXY", httpsProxy)
	}
	if noProxy != "" {
		os.Setenv("NO_PROXY", noProxy)
		os.Setenv("no_proxy", noProxy)
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}

	// query latest release (pre-release included)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=1", repoOwner, repoName)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[update]%s %v\n", cYellow, cReset, err)
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[update]%s check failed: %v\n", cYellow, cReset, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s[update]%s GitHub API %d\n", cYellow, cReset, resp.StatusCode)
		return
	}

	var releases []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		fmt.Fprintf(os.Stderr, "%s[update]%s parse error: %v\n", cYellow, cReset, err)
		return
	}
	if len(releases) == 0 {
		return
	}

	latest := releases[0]
	if latest.TagName == buildVersion {
		fmt.Fprintf(os.Stderr, "%s[update]%s already latest (%s)\n", cDim, cReset, buildVersion)
		return
	}

	// find matching asset
	assetName := binaryBaseName + "-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	var downloadURL string
	for _, a := range latest.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		fmt.Fprintf(os.Stderr, "%s[update]%s no binary for %s/%s in %s\n",
			cYellow, cReset, runtime.GOOS, runtime.GOARCH, latest.TagName)
		return
	}

	fmt.Fprintf(os.Stderr, "%s[update]%s %s%s%s → %s%s%s  downloading...\n",
		cCyan, cReset, cDim, buildVersion, cReset, cGreen, latest.TagName, cReset)

	// download with no timeout (binary can be large on slow networks)
	dlClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}
	dlResp, err := dlClient.Get(downloadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[update]%s download failed: %v\n", cYellow, cReset, err)
		return
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s[update]%s download HTTP %d\n", cYellow, cReset, dlResp.StatusCode)
		return
	}

	// write to temp file in same directory (so rename is atomic)
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".codex-scanner-update-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[update]%s temp file: %v\n", cYellow, cReset, err)
		return
	}
	tmpPath := tmp.Name()

	if _, err := io.Copy(tmp, dlResp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "%s[update]%s write failed: %v\n", cYellow, cReset, err)
		return
	}
	tmp.Close()

	// preserve file mode
	info, err := os.Stat(exe)
	if err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "%s[update]%s stat: %v\n", cYellow, cReset, err)
		return
	}
	if err := os.Chmod(tmpPath, info.Mode()); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "%s[update]%s chmod: %v\n", cYellow, cReset, err)
		return
	}

	// atomic replace
	if err := os.Rename(tmpPath, exe); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "%s[update]%s replace failed: %v\n", cYellow, cReset, err)
		return
	}

	fmt.Fprintf(os.Stderr, "%s[update]%s updated to %s%s%s, restarting...\n",
		cGreen, cReset, cBold, latest.TagName, cReset)

	// re-exec self
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "%s[update]%s restart failed: %v (please re-run manually)\n", cRed, cReset, err)
	}
}

// ── CLI flag definitions + main ──────────────────────────────────────────────

func run() int {
	// ── define flags ──
	configPath := flag.String("config", defaultConfigPath,
		"JSON config path (default: "+defaultConfigPath+"; ignored if missing).")
	authDir := flag.String("auth-dir", "",
		"Folder containing auth JSON files.")
	baseURL := flag.String("base-url", "",
		"Codex base URL (fallback default: "+defaultCodexBaseURL+")")
	quotaPath := flag.String("quota-path", "",
		"API path used for quota/auth probe (fallback default: /responses)")
	model := flag.String("model", "",
		"Model used in probe request body (fallback default: gpt-5)")
	timeout := flag.Float64("timeout", 0,
		"HTTP timeout in seconds (fallback default: 20)")
	maxRetries := flag.Int("max-retries", 0,
		"Max retry attempts on network error (fallback default: 3, 0 = no retry).")
	refreshBeforeCheck := flag.Bool("refresh-before-check", false,
		"Refresh access token with refresh_token before probe.")
	refreshURL := flag.String("refresh-url", "",
		"Token refresh endpoint (fallback default: "+defaultRefreshURL+")")
	outputJSONFlag := flag.Bool("output-json", false,
		"Print full results as JSON instead of table view.")
	outputDir := flag.String("output-dir", "",
		"Directory for saving results and archived deleted files (default: ./results).")
	delete401 := flag.Bool("delete-401", false,
		"Delete auth files that returned HTTP 401 after confirmation.")
	assumeYes := flag.Bool("assume-yes", false,
		"Skip deletion confirmation prompt (only applies with --delete-401).")
	httpProxy := flag.String("http-proxy", "",
		"HTTP proxy URL, for example: http://127.0.0.1:7890")
	httpsProxy := flag.String("https-proxy", "",
		"HTTPS proxy URL, for example: http://127.0.0.1:7890")
	noProxy := flag.String("no-proxy", "",
		"Comma-separated hosts that bypass proxy.")
	interval := flag.Duration("interval", 0,
		"Scan interval for scheduled mode (e.g. 30m, 1h).")
	cronExpr := flag.String("cron", "",
		"Cron expression for scheduled mode (e.g. \"*/30 * * * *\").")
	webhookURL := flag.String("webhook-url", "",
		"Webhook URL to POST notifications when 401 is found.")
	webhookHeaders := flag.String("webhook-headers", "",
		"Custom webhook headers, format: Key:Value,Key2:Value2")
	concurrencyFlag := flag.Int("concurrency", 0,
		"Number of concurrent probe requests (fallback default: 1).")
	noUpdate := flag.Bool("no-update", false,
		"Skip automatic OTA update check on startup.")
	showVersion := flag.Bool("version", false,
		"Print build version and exit.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Scan Codex auth files and report credentials that fail with HTTP 401.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// ── --version ──
	if *showVersion {
		fmt.Println(buildVersion)
		return 0
	}

	// ── track explicitly set flags ──
	cliSet := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		cliSet[f.Name] = true
	})

	// ── load file config ──
	cfgPath := *configPath
	fc := map[string]interface{}{}
	if p := expandHome(cfgPath); p != "" {
		if loaded, err := loadJSON(p); err == nil {
			fc = loaded
		} else if cliSet["config"] {
			fmt.Fprintf(os.Stderr, "Error: failed to load config file %s: %v\n", p, err)
			return 2
		}
	}

	// ── resolve config (CLI > file > default) ──
	cfg := &Config{ConfigPath: cfgPath}

	cfg.AuthDir = resolveStr(*authDir, cliSet["auth-dir"], fc, "auth_dir", "")
	cfg.BaseURL = resolveStr(*baseURL, cliSet["base-url"], fc, "base_url", defaultCodexBaseURL)
	cfg.QuotaPath = resolveStr(*quotaPath, cliSet["quota-path"], fc, "quota_path", "/responses")
	cfg.Model = resolveStr(*model, cliSet["model"], fc, "model", "gpt-5")
	cfg.RefreshURL = resolveStr(*refreshURL, cliSet["refresh-url"], fc, "refresh_url", defaultRefreshURL)
	cfg.HTTPProxy = resolveStr(*httpProxy, cliSet["http-proxy"], fc, "http_proxy", "")
	cfg.HTTPSProxy = resolveStr(*httpsProxy, cliSet["https-proxy"], fc, "https_proxy", "")
	cfg.NoProxy = resolveStr(*noProxy, cliSet["no-proxy"], fc, "no_proxy", "")
	cfg.WebhookURL = resolveStr(*webhookURL, cliSet["webhook-url"], fc, "webhook_url", "")
	cfg.WebhookHeaders = resolveStr(*webhookHeaders, cliSet["webhook-headers"], fc, "webhook_headers", "")
	cfg.Cron = resolveStr(*cronExpr, cliSet["cron"], fc, "cron", "")

	// proxy: also extract from nested "proxy" object in config
	if !cliSet["http-proxy"] && cfg.HTTPProxy == "" ||
		!cliSet["https-proxy"] && cfg.HTTPSProxy == "" ||
		!cliSet["no-proxy"] && cfg.NoProxy == "" {
		cfgHTTP, cfgHTTPS, cfgNoProxy := extractProxyFromConfig(fc)
		if cfg.HTTPProxy == "" {
			cfg.HTTPProxy = cfgHTTP
		}
		if cfg.HTTPSProxy == "" {
			cfg.HTTPSProxy = cfgHTTPS
		}
		if cfg.NoProxy == "" {
			cfg.NoProxy = cfgNoProxy
		}
	}

	// ── OTA self-update ──
	skipUpdate, _ := resolveBool(*noUpdate, cliSet["no-update"], fc, "no_update", false)
	if !skipUpdate {
		selfUpdate(cfg.HTTPProxy, cfg.HTTPSProxy, cfg.NoProxy)
	}

	// numeric fields
	var err error
	timeoutSecs, err := resolveFloat64(*timeout, cliSet["timeout"], fc, "timeout", 20)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: timeout must be a number\n")
		return 2
	}
	if timeoutSecs <= 0 {
		fmt.Fprintf(os.Stderr, "Error: timeout must be greater than zero\n")
		return 2
	}
	cfg.Timeout = time.Duration(timeoutSecs * float64(time.Second))

	cfg.MaxRetries, err = resolveInt(*maxRetries, cliSet["max-retries"], fc, "max_retries", 3)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: max_retries must be an integer\n")
		return 2
	}
	if cfg.MaxRetries < 0 {
		fmt.Fprintf(os.Stderr, "Error: max_retries must be >= 0\n")
		return 2
	}

	// boolean fields
	cfg.RefreshBeforeCheck, err = resolveBool(*refreshBeforeCheck, cliSet["refresh-before-check"], fc, "refresh_before_check", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: refresh_before_check must be a boolean value\n")
		return 2
	}
	cfg.OutputJSON, err = resolveBool(*outputJSONFlag, cliSet["output-json"], fc, "output_json", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: output_json must be a boolean value\n")
		return 2
	}
	cfg.OutputDir = resolveStr(*outputDir, cliSet["output-dir"], fc, "output_dir", "./results")
	cfg.OutputDir = expandHome(cfg.OutputDir)
	cfg.Delete401, err = resolveBool(*delete401, cliSet["delete-401"], fc, "delete_401", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: delete_401 must be a boolean value\n")
		return 2
	}
	cfg.AssumeYes, err = resolveBool(*assumeYes, cliSet["assume-yes"], fc, "assume_yes", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: assume_yes must be a boolean value\n")
		return 2
	}

	// interval from config file
	if !cliSet["interval"] {
		if v := configGet(fc, "interval"); v != nil {
			if s, ok := v.(string); ok && s != "" {
				d, parseErr := time.ParseDuration(s)
				if parseErr != nil {
					fmt.Fprintf(os.Stderr, "Error: invalid interval in config: %v\n", parseErr)
					return 2
				}
				cfg.Interval = d
			}
		}
	} else {
		cfg.Interval = *interval
	}

	// concurrency
	cfg.Concurrency, err = resolveInt(*concurrencyFlag, cliSet["concurrency"], fc, "concurrency", 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: concurrency must be an integer\n")
		return 2
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}

	// mutual exclusivity
	if cfg.Interval > 0 && cfg.Cron != "" {
		fmt.Fprintln(os.Stderr, "Error: --interval and --cron are mutually exclusive")
		return 2
	}

	// interactive auth_dir prompt
	if cfg.AuthDir == "" || strings.EqualFold(strings.TrimSpace(cfg.AuthDir), "input") {
		fi, statErr := os.Stdin.Stat()
		if statErr != nil || fi.Mode()&os.ModeCharDevice == 0 {
			fmt.Fprintln(os.Stderr, "Error: auth directory missing. Use --auth-dir or set auth_dir in config.")
			return 2
		}
		fmt.Fprint(os.Stderr, "Auth directory path: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		entered := strings.TrimSpace(line)
		if entered == "" {
			fmt.Fprintln(os.Stderr, "Error: auth directory missing. Use --auth-dir or set auth_dir in config.")
			return 2
		}
		cfg.AuthDir = entered
	}

	// ── signal context ──
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client := buildHTTPClient(cfg.HTTPProxy, cfg.HTTPSProxy, cfg.NoProxy, cfg.Timeout, cfg.Concurrency)

	// ── dispatch ──
	if cfg.Interval > 0 {
		return runWithInterval(ctx, cfg, client)
	}
	if cfg.Cron != "" {
		sched, cronErr := parseCron(cfg.Cron)
		if cronErr != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid cron expression: %v\n", cronErr)
			return 2
		}
		return runWithCron(ctx, cfg, client, sched)
	}
	return runOneScan(ctx, cfg, client)
}

func main() {
	initColors()
	os.Exit(run())
}
