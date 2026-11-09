// test823 : project WHY MediaHub Proxy - server
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

//go:embed all:public
var publicFS embed.FS

var embeddedPublic fs.FS

func init() {
	sub, err := fs.Sub(publicFS, "public")
	if err == nil {
		embeddedPublic = sub
	}
}

const (
	SecurityPlain   = "plain"
	SecuritySelfTLS = "selftls"
	SecurityTLS     = "tls"
)

// Server configuration
type Config struct {
	TargetUrl string `json:"target"`   // Target vanilla server URL (default: "https://localhost:8443")
	Security  string `json:"security"` // Security mode: "plain", "selftls", "tls" (Default: "tls")
	Port      string `json:"port"`     // Default: "8444"
	HttpMode  bool   `json:"http"`
	Loopback  bool   `json:"loopback"`

	CertFile string `json:"cert"`
	KeyFile  string `json:"key"`

	CacheMB     int `json:"cache_mb"`     // In-memory cache size limit (MB)
	MaxSessions int `json:"max_sessions"` // Max in-memory active sessions limit
}

var cfg Config

// init environment
func initEnv() {
	exePath, _ := os.Executable()
	realPath, _ := filepath.EvalSymlinks(exePath)
	os.Chdir(filepath.Dir(realPath))

	configPath := "./config/config.json"
	cfg = Config{
		TargetUrl:   "https://localhost:8443",
		Security:    SecurityTLS, // Default security level is "tls"
		Port:        "8444",
		HttpMode:    false,
		Loopback:    false,

		CertFile: "./certs/cert.pem",
		KeyFile:  "./certs/key.pem",

		CacheMB:     32,
		MaxSessions: 5000,
	}

	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Printf("failed to create config directory: %v", err)
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		file, _ := json.MarshalIndent(cfg, "", "  ")
		os.WriteFile(configPath, file, 0644)
		log.Println("config.json file created with default proxy settings")
	} else {
		file, _ := os.ReadFile(configPath)
		json.Unmarshal(file, &cfg)
	}

	// Normalize security mode: "plain", "selftls", "tls" (Default: "tls")
	secMode := strings.ToLower(strings.TrimSpace(cfg.Security))
	switch secMode {
	case SecurityPlain, SecuritySelfTLS, SecurityTLS:
		cfg.Security = secMode
	default:
		if secMode != "" {
			log.Printf("[Security] Unknown security level '%s', defaulting to '%s'", cfg.Security, SecurityTLS)
		}
		cfg.Security = SecurityTLS
	}

	// Normalize target URL according to security level
	rawTarget := strings.TrimSpace(cfg.TargetUrl)
	if rawTarget == "" {
		if cfg.Security == SecurityPlain {
			rawTarget = "http://localhost:8443"
		} else {
			rawTarget = "https://localhost:8443"
		}
	}

	if cfg.Security == SecurityPlain {
		if strings.HasPrefix(rawTarget, "https://") {
			rawTarget = "http://" + strings.TrimPrefix(rawTarget, "https://")
		} else if !strings.HasPrefix(rawTarget, "http://") {
			rawTarget = "http://" + rawTarget
		}
	} else {
		// "selftls" or "tls" strictly require HTTPS
		if strings.HasPrefix(rawTarget, "http://") {
			log.Printf("[Security] Security mode '%s' requires TLS. Upgrading '%s' to HTTPS.", cfg.Security, rawTarget)
			rawTarget = "https://" + strings.TrimPrefix(rawTarget, "http://")
		} else if !strings.HasPrefix(rawTarget, "https://") {
			rawTarget = "https://" + rawTarget
		}
	}
	cfg.TargetUrl = rawTarget

	// Initialize embedded public filesystem
	sub, err := fs.Sub(publicFS, "public")
	if err == nil {
		embeddedPublic = sub
	} else {
		log.Printf("Warning: failed to sub embedded public filesystem: %v", err)
	}

	// Initialize in-memory cache and session managers with capacity bounds
	InitMemoryCache(cfg.CacheMB)
	InitStreamManager(cfg.MaxSessions)
	InitShareManager(cfg.MaxSessions)
	InitOriginHttpClient(cfg.Security)

	// Make certificate if not exists (TLS mode only)
	if !cfg.HttpMode {
		certDir := filepath.Dir(cfg.CertFile)
		if err := os.MkdirAll(certDir, 0755); err != nil {
			log.Printf("failed to create certs directory: %v", err)
		}
		if _, err := os.Stat(cfg.CertFile); os.IsNotExist(err) {
			log.Println("making self-signed certificate")
			makeCert(cfg.CertFile, cfg.KeyFile)
		}
	}
}

// TLS certificate in-memory store
var memCert atomic.Pointer[tls.Certificate]

func loadCert() {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err == nil {
		memCert.Store(&cert)
		log.Println("TLS certificate loaded from disk")
	} else {
		log.Printf("Failed to load TLS certificate: %v", err)
	}
}

// postError returns an error with 0.5s delay following project conventions
func postError(w http.ResponseWriter, errMsg string, code int) {
	time.Sleep(500 * time.Millisecond)
	log.Printf("[ERROR %d] %s", code, errMsg)
	http.Error(w, errMsg, code)
}

// buildReverseProxy creates a reverse proxy forwarding unintercepted requests to origin
func buildReverseProxy(targetUrl string, secMode string) *httputil.ReverseProxy {
	parsedUrl, err := url.Parse(targetUrl)
	if err != nil {
		log.Fatalf("Invalid target URL '%s': %v", targetUrl, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(parsedUrl)

	var transport *http.Transport
	switch secMode {
	case SecurityPlain:
		transport = &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}
	case SecuritySelfTLS:
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}
	case SecurityTLS:
		fallthrough
	default:
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}
	}
	proxy.Transport = transport

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = parsedUrl.Host
		req.URL.Scheme = parsedUrl.Scheme
		req.URL.Host = parsedUrl.Host
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// Deduplicate any CORS or security headers so browsers never see multiple values
		dedupHeader(resp.Header, "Access-Control-Allow-Origin")
		dedupHeader(resp.Header, "Access-Control-Allow-Methods")
		dedupHeader(resp.Header, "Access-Control-Allow-Headers")
		dedupHeader(resp.Header, "Access-Control-Expose-Headers")
		dedupHeader(resp.Header, "Content-Security-Policy")
		dedupHeader(resp.Header, "X-Content-Type-Options")
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[Proxy Error] %s %s: %v", r.Method, r.URL.Path, err)
		postError(w, "Proxy Destination Unreachable", http.StatusBadGateway)
	}

	return proxy
}

func dedupHeader(h http.Header, key string) {
	if vals, ok := h[key]; ok && len(vals) > 1 {
		h[key] = vals[:1]
	}
}

// findPublicFile searches for a file in local ./public or embedded publicFS
func findPublicFile(urlPath string) (data []byte, matchedName string, found bool) {
	// Normalize URL path using forward slashes
	slashPath := filepath.ToSlash(urlPath)
	cleanPath := path.Clean(slashPath)
	cleanPath = strings.TrimPrefix(cleanPath, "/")
	if cleanPath == "" || cleanPath == "." {
		return nil, "", false
	}

	// Try matching variants:
	// 1. Exact relative path (e.g. "js/core/adapter.js" or "core/adapter.js")
	// 2. Stripped "js/" prefix (for code/public/core/adapter.js layout)
	// 3. Stripped "public/" prefix
	candidates := []string{cleanPath}
	if strings.HasPrefix(cleanPath, "js/") {
		candidates = append(candidates, strings.TrimPrefix(cleanPath, "js/"))
	}
	if strings.HasPrefix(cleanPath, "public/") {
		candidates = append(candidates, strings.TrimPrefix(cleanPath, "public/"))
	}

	for _, rel := range candidates {
		rel = path.Clean(rel)

		// 1. Check local disk ./public first
		localPath := filepath.Join(".", "public", filepath.FromSlash(rel))
		if info, err := os.Stat(localPath); err == nil && !info.IsDir() {
			d, err := os.ReadFile(localPath)
			if err == nil {
				return d, rel, true
			}
		}

		// 2. Check embedded publicFS
		if embeddedPublic != nil {
			f, err := embeddedPublic.Open(rel)
			if err == nil {
				info, err := f.Stat()
				if err == nil && !info.IsDir() {
					d, err := io.ReadAll(f)
					f.Close()
					if err == nil {
						return d, rel, true
					}
				} else {
					f.Close()
				}
			}
		}
	}

	return nil, "", false
}

// tryInterceptPublicFile checks if requested file exists in embedded or local public;
// if found, serves with <= 1MB TTL 3h caching and returns true; otherwise returns false.
func tryInterceptPublicFile(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	urlPath := r.URL.Path
	cacheKey := "pubfile:" + urlPath

	// 1. Check in-memory cache (TTL 3 hours)
	if globalDataCache != nil {
		if cached, ok := globalDataCache.Get(cacheKey); ok {
			applySecurityHeaders(w)
			mimeType := GetMimeType(urlPath)
			w.Header().Set("Content-Type", mimeType)
			w.WriteHeader(http.StatusOK)
			w.Write(cached)
			return true
		}
	}

	// 2. Search local and embedded filesystem
	data, matchedName, ok := findPublicFile(urlPath)
	if !ok {
		return false
	}

	// 3. Cache in memory if size <= 1MB (1048576 B) with TTL 3h
	if globalDataCache != nil && len(data) <= 1048576 {
		globalDataCache.Set(cacheKey, data, 3*time.Hour)
	}

	applySecurityHeaders(w)
	mimeType := GetMimeType(matchedName)
	w.Header().Set("Content-Type", mimeType)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return true
}

// applySecurityHeaders applies CORS and CSP headers to proxy-served responses
func applySecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")
	h.Set("Access-Control-Expose-Headers", "Content-Range, Accept-Ranges, Content-Length")
	h.Set("X-Content-Type-Options", "nosniff")

	cdn := []string{"https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://esm.sh"}
	cdnstr := strings.Join(cdn, " ")
	h.Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'wasm-unsafe-eval' "+cdnstr+"; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "+cdnstr+"; "+
			"font-src 'self' https://fonts.gstatic.com "+cdnstr+"; "+
			"img-src 'self' blob: data: "+cdnstr+"; "+
			"media-src 'self' blob:; object-src 'self' blob:; "+
			"connect-src 'self' blob: "+cdnstr+"; "+
			"worker-src 'self' blob:; base-uri 'none'; frame-ancestors 'none'")
}

// makeCert generates self-signed ECDSA certificate
func makeCert(certOut string, keyOut string) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, limit)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"MediaHub Proxy"},
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	cFile, _ := os.Create(certOut)
	defer cFile.Close()
	pem.Encode(cFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})

	kFile, _ := os.OpenFile(keyOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	defer kFile.Close()
	b, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}

func main() {
	initEnv()

	reverseProxy := buildReverseProxy(cfg.TargetUrl, cfg.Security)

	// Main routing multiplexer with selective interception
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.Contains(path, "..") || strings.Contains(path, "\\") {
			postError(w, "Directory Traversal Detected", http.StatusBadRequest)
			return
		}

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.WriteHeader(http.StatusOK)
			return
		}

		// 1. Intercept Additional Proxy APIs
		// Streaming session APIs
		if path == "/api/stream/register" {
			applySecurityHeaders(w)
			handleStreamRegister(w, r)
			return
		}
		if strings.HasPrefix(path, "/api/stream/") {
			applySecurityHeaders(w)
			handleStreamRoute(w, r)
			return
		}

		// Share session APIs
		if path == "/api/share/create" {
			applySecurityHeaders(w)
			handleShareCreate(w, r)
			return
		}
		if path == "/api/share/info" {
			applySecurityHeaders(w)
			handleShareInfo(w, r)
			return
		}
		if strings.HasPrefix(path, "/api/share/stream/") {
			applySecurityHeaders(w)
			handleShareStream(w, r)
			return
		}
		if strings.HasPrefix(path, "/api/share/download/") {
			applySecurityHeaders(w)
			handleShareDownload(w, r)
			return
		}

		// 2. Intercept Embedded / Local Public Files
		// If requested file exists in own public directory, intercept and serve;
		// otherwise pass through to reverse proxy.
		if tryInterceptPublicFile(w, r) {
			return
		}

		// 3. Fallback: Reverse proxy all other requests to target origin
		reverseProxy.ServeHTTP(w, r)
	})

	// Server mode and address configuration
	modeStr := "TLS"
	if cfg.HttpMode {
		modeStr = "HTTP"
	}
	bindStr := "All"
	host := ""
	if cfg.Loopback {
		bindStr = "Loopback"
		host = "127.0.0.1"
	}
	addr := host + ":" + cfg.Port
	log.Printf("MediaHub Proxy is running on port %s (%s, %s) -> target: %s (security: %s)", cfg.Port, modeStr, bindStr, cfg.TargetUrl, cfg.Security)

	var err error
	if cfg.HttpMode {
		err = http.ListenAndServe(addr, handler)
	} else {
		loadCert()
		go func() {
			for range time.Tick(24 * time.Hour) {
				loadCert()
			}
		}()

		server := &http.Server{
			Addr:    addr,
			Handler: handler,
			TLSConfig: &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					cert := memCert.Load()
					if cert == nil {
						return nil, fmt.Errorf("no TLS certificate in memory")
					}
					return cert, nil
				},
			},
		}
		err = server.ListenAndServeTLS("", "")
	}

	if err != nil {
		log.Fatalf("Proxy server startup error: %v", err)
	}
}
