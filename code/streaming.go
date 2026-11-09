// test823 : project WHY MediaHub Proxy - streaming
package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	PlainChunkSize  int64 = 1048576      // 1 MiB
	CipherChunkSize int64 = 1048576 + 16 // 1 MiB + 16B GCM tag
	MaxStreamChunk  int64 = 4 * 1048576  // 4 MiB max payload per range response
)

// ========== Stream Decryption & Origin Fetcher ==========

var originHttpClient *http.Client

func InitOriginHttpClient(secMode string) {
	var transport *http.Transport
	switch secMode {
	case "plain":
		transport = &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}
	case "selftls":
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}
	case "tls":
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

	originHttpClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

func init() {
	InitOriginHttpClient("tls")
}

// fetchOriginBytes fetches a specific byte range from origin /api/media/{folderId}/{filePid}/dat
func fetchOriginBytes(targetUrl, folderID, filePID string, start, end int64) ([]byte, error) {
	if !strings.HasPrefix(targetUrl, "http://") && !strings.HasPrefix(targetUrl, "https://") {
		targetUrl = "https://" + targetUrl
	}
	url := fmt.Sprintf("%s/api/media/%s/%s/dat", strings.TrimRight(targetUrl, "/"), folderID, filePID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	resp, err := originHttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("origin fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("origin HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading origin body failed: %w", err)
	}
	return data, nil
}

// getGlobalIV retrieves 12-byte global IV with in-memory caching
func getGlobalIV(targetUrl, folderID, filePID string, maskedIV *[]byte) ([]byte, error) {
	if maskedIV != nil && len(*maskedIV) > 0 {
		raw := UnmaskBytes(*maskedIV)
		if len(raw) == 12 {
			return raw, nil
		}
		sclear(raw)
	}
	data, err := fetchOriginBytes(targetUrl, folderID, filePID, 0, 11)
	if err != nil {
		return nil, err
	}
	if len(data) != 12 {
		return nil, fmt.Errorf("invalid global IV size: got %d, expected 12", len(data))
	}
	if maskedIV != nil {
		*maskedIV = MaskBytes(data)
	}
	out := make([]byte, 12)
	copy(out, data)
	return out, nil
}

// DecryptMediaRange fetches and decrypts requested plaintext byte range from origin with 1MB chunk caching
func DecryptMediaRange(targetUrl, folderID, filePID string, rawKey []byte, maskedIV *[]byte, origSize, rangeStart, rangeEnd int64) ([]byte, error) {
	if rangeStart > rangeEnd || rangeStart >= origSize {
		return nil, errors.New("unsatisfiable range")
	}

	globalIV, err := getGlobalIV(targetUrl, folderID, filePID, maskedIV)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain global IV: %w", err)
	}
	defer sclear(globalIV)

	firstChunk := rangeStart / PlainChunkSize
	lastChunk := rangeEnd / PlainChunkSize
	totalLen := rangeEnd - rangeStart + 1
	resultBuf := make([]byte, totalLen)
	var writeOffset int64 = 0

	for chunkIdx := firstChunk; chunkIdx <= lastChunk; chunkIdx++ {
		plainLen := PlainChunkSize
		if (chunkIdx+1)*PlainChunkSize > origSize {
			plainLen = origSize - chunkIdx*PlainChunkSize
		}
		if plainLen <= 0 {
			break
		}

		cacheKey := fmt.Sprintf("chunk:%s:%s:%d", folderID, filePID, chunkIdx)
		var plainData []byte

		// Check in-memory 1MB chunk cache (TTL 3 hours)
		if globalDataCache != nil {
			if cached, ok := globalDataCache.Get(cacheKey); ok {
				plainData = cached
			}
		}

		if plainData == nil {
			cipherLen := plainLen + 16
			cStart := 12 + chunkIdx*CipherChunkSize
			cEnd := cStart + cipherLen - 1

			cipherData, err := fetchOriginBytes(targetUrl, folderID, filePID, cStart, cEnd)
			if err != nil {
				return nil, fmt.Errorf("chunk %d fetch failed: %w", chunkIdx, err)
			}
			if int64(len(cipherData)) != cipherLen {
				return nil, fmt.Errorf("chunk %d length mismatch: got %d, expected %d", chunkIdx, len(cipherData), cipherLen)
			}

			chunkIV := mkiv(globalIV, uint64(chunkIdx))
			decrypted, err := DeAESGCM(rawKey[:32], chunkIV, cipherData)
			sclear(chunkIV)
			if err != nil {
				return nil, fmt.Errorf("chunk %d decryption failed: %w", chunkIdx, err)
			}
			plainData = decrypted

			// Store decrypted chunk into cache if <= 1MB (TTL 3 hours)
			if globalDataCache != nil && int64(len(plainData)) <= 1048576 {
				globalDataCache.Set(cacheKey, plainData, 3*time.Hour)
			}
		}

		chunkBase := chunkIdx * PlainChunkSize
		from := max(rangeStart, chunkBase) - chunkBase
		to := min(rangeEnd, chunkBase+int64(len(plainData))-1) - chunkBase
		if from <= to && from < int64(len(plainData)) {
			slice := plainData[from : to+1]
			copy(resultBuf[writeOffset:], slice)
			writeOffset += int64(len(slice))
		}
	}

	return resultBuf[:writeOffset], nil
}

// ========== HTTP Handlers ==========

// handleStreamRegister handles POST /api/stream/register
func handleStreamRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FolderID     string `json:"folderId"`
		FilePID      string `json:"filePid"`
		FileKey      string `json:"fileKey"` // Hex
		OriginalSize int64  `json:"originalSize"`
		FileName     string `json:"fileName"`
		ShareID      string `json:"shareId"` // Support registering directly from share session
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		postError(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	var session *SecureSession

	if req.ShareID != "" {
		shareSession, exists := globalShareManager.Get(req.ShareID)
		if !exists {
			postError(w, "Share session not found or expired", http.StatusNotFound)
			return
		}
		folderID, filePID, rawKey, err := shareSession.GetUnmaskedCredentials()
		if err != nil {
			postError(w, "Failed to load share credentials", http.StatusInternalServerError)
			return
		}
		defer sclear(rawKey)

		fileName := shareSession.FileName
		if req.FileName != "" {
			fileName = req.FileName
		}
		origSize := shareSession.OrigSize
		if req.OriginalSize > 0 {
			origSize = req.OriginalSize
		}

		s, err := globalStreamManager.Create(folderID, filePID, rawKey, origSize, fileName, 24*time.Hour)
		if err != nil {
			postError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session = s
	} else {
		keyBytes, err := hex.DecodeString(req.FileKey)
		if err != nil || len(keyBytes) < 32 {
			postError(w, "Invalid File Key", http.StatusBadRequest)
			return
		}
		defer sclear(keyBytes)

		s, err := globalStreamManager.Create(req.FolderID, req.FilePID, keyBytes, req.OriginalSize, req.FileName, 24*time.Hour)
		if err != nil {
			postError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session = s
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sessionId": session.ID,
		"streamUrl": fmt.Sprintf("/api/stream/%s", session.ID),
	})
}

// handleStreamRoute dispatches /api/stream/{sessionId} (GET/HEAD to stream, DELETE to destroy)
func handleStreamRoute(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/stream/")
	if sessionID == "" || strings.Contains(sessionID, "/") {
		postError(w, "Invalid Stream Session ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		globalStreamManager.Delete(sessionID)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	case http.MethodGet, http.MethodHead:
		session, exists := globalStreamManager.Get(sessionID)
		if !exists {
			postError(w, "Stream Session Not Found or Expired", http.StatusNotFound)
			return
		}
		folderID, filePID, rawKey, err := session.GetUnmaskedCredentials()
		if err != nil {
			postError(w, "Failed to unmask credentials", http.StatusInternalServerError)
			return
		}
		defer sclear(rawKey)

		servePlaintextRange(w, r, cfg.TargetUrl, folderID, filePID, rawKey, &session.CachedIV, session.OrigSize, session.FileName, session.Mime)
	default:
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleShareCreate handles POST /api/share/create
func handleShareCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FolderID     string `json:"folderId"`
		FilePID      string `json:"filePid"`
		FileKey      string `json:"fileKey"` // Hex
		OriginalSize int64  `json:"originalSize"`
		FileName     string `json:"fileName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		postError(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	keyBytes, err := hex.DecodeString(req.FileKey)
	if err != nil || len(keyBytes) < 32 {
		postError(w, "Invalid File Key", http.StatusBadRequest)
		return
	}
	defer sclear(keyBytes)

	// Create share session (Default 7 days TTL)
	session, err := globalShareManager.Create(req.FolderID, req.FilePID, keyBytes, req.OriginalSize, req.FileName, 7*24*time.Hour)
	if err != nil {
		postError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"shareId":  session.ID,
		"shareUrl": fmt.Sprintf("/viewer?s=%s", session.ID),
	})
}

// handleShareInfo handles GET /api/share/info?s={shareId}
func handleShareInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	shareID := r.URL.Query().Get("s")
	if shareID == "" {
		postError(w, "Share ID Required", http.StatusBadRequest)
		return
	}

	session, exists := globalShareManager.Get(shareID)
	if !exists {
		postError(w, "Share Not Found or Expired", http.StatusNotFound)
		return
	}

	folderID, filePID, rawKey, err := session.GetUnmaskedCredentials()
	if err != nil {
		postError(w, "Failed to load share credentials", http.StatusInternalServerError)
		return
	}
	hexKey := hex.EncodeToString(rawKey)
	sclear(rawKey)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"shareId":   session.ID,
		"folderId":  folderID,
		"filePid":   filePID,
		"fileKey":   hexKey,
		"fileName":  session.FileName,
		"origSize":  session.OrigSize,
		"mime":      session.Mime,
		"expiresAt": session.ExpiresAt.Unix(),
	})
}

// handleShareStream handles GET /api/share/stream/{shareId} for keyless playback
func handleShareStream(w http.ResponseWriter, r *http.Request) {
	shareID := strings.TrimPrefix(r.URL.Path, "/api/share/stream/")
	if shareID == "" || strings.Contains(shareID, "/") {
		postError(w, "Invalid Share ID", http.StatusBadRequest)
		return
	}

	session, exists := globalShareManager.Get(shareID)
	if !exists {
		postError(w, "Share Not Found or Expired", http.StatusNotFound)
		return
	}

	folderID, filePID, rawKey, err := session.GetUnmaskedCredentials()
	if err != nil {
		postError(w, "Failed to unmask credentials", http.StatusInternalServerError)
		return
	}
	defer sclear(rawKey)

	var cachedIV []byte
	servePlaintextRange(w, r, cfg.TargetUrl, folderID, filePID, rawKey, &cachedIV, session.OrigSize, session.FileName, session.Mime)
}

// handleShareDownload handles GET /api/share/download/{shareId} for keyless file download
func handleShareDownload(w http.ResponseWriter, r *http.Request) {
	shareID := strings.TrimPrefix(r.URL.Path, "/api/share/download/")
	if shareID == "" || strings.Contains(shareID, "/") {
		postError(w, "Invalid Share ID", http.StatusBadRequest)
		return
	}

	session, exists := globalShareManager.Get(shareID)
	if !exists {
		postError(w, "Share Not Found or Expired", http.StatusNotFound)
		return
	}

	folderID, filePID, rawKey, err := session.GetUnmaskedCredentials()
	if err != nil {
		postError(w, "Failed to unmask credentials", http.StatusInternalServerError)
		return
	}
	defer sclear(rawKey)

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(session.FileName)))

	var cachedIV []byte
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		servePlaintextFull(w, r, cfg.TargetUrl, folderID, filePID, rawKey, &cachedIV, session.OrigSize, session.FileName, session.Mime)
		return
	}
	servePlaintextRange(w, r, cfg.TargetUrl, folderID, filePID, rawKey, &cachedIV, session.OrigSize, session.FileName, session.Mime)
}

// servePlaintextFull streams the entire decrypted file chunk-by-chunk for complete downloads
func servePlaintextFull(w http.ResponseWriter, r *http.Request, targetUrl, folderID, filePID string, rawKey []byte, maskedIV *[]byte, origSize int64, fileName, mime string) {
	globalIV, err := getGlobalIV(targetUrl, folderID, filePID, maskedIV)
	if err != nil {
		log.Printf("[Download] getGlobalIV error: %v", err)
		http.Error(w, "Failed to get IV", http.StatusInternalServerError)
		return
	}
	defer sclear(globalIV)

	w.Header().Set("Content-Type", mime)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(origSize, 10))
	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodHead {
		return
	}

	flusher, _ := w.(http.Flusher)
	lastChunk := (origSize - 1) / PlainChunkSize

	for chunkIdx := int64(0); chunkIdx <= lastChunk; chunkIdx++ {
		plainLen := PlainChunkSize
		if (chunkIdx+1)*PlainChunkSize > origSize {
			plainLen = origSize - chunkIdx*PlainChunkSize
		}
		if plainLen <= 0 {
			break
		}

		cacheKey := fmt.Sprintf("chunk:%s:%s:%d", folderID, filePID, chunkIdx)
		var plainData []byte

		if globalDataCache != nil {
			if cached, ok := globalDataCache.Get(cacheKey); ok {
				plainData = cached
			}
		}

		if plainData == nil {
			cipherLen := plainLen + 16
			cStart := 12 + chunkIdx*CipherChunkSize
			cEnd := cStart + cipherLen - 1

			cipherData, err := fetchOriginBytes(targetUrl, folderID, filePID, cStart, cEnd)
			if err != nil {
				log.Printf("[Download] chunk %d fetch error: %v", chunkIdx, err)
				return
			}

			chunkIV := mkiv(globalIV, uint64(chunkIdx))
			decrypted, err := DeAESGCM(rawKey[:32], chunkIV, cipherData)
			sclear(chunkIV)
			if err != nil {
				log.Printf("[Download] chunk %d decrypt error: %v", chunkIdx, err)
				return
			}
			plainData = decrypted

			if globalDataCache != nil && int64(len(plainData)) <= 1048576 {
				globalDataCache.Set(cacheKey, plainData, 3*time.Hour)
			}
		}

		if _, err := w.Write(plainData); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// servePlaintextRange handles range requests and streams decrypted media via ServeDecryptedContent
func servePlaintextRange(w http.ResponseWriter, r *http.Request, targetUrl, folderID, filePID string, rawKey []byte, cachedIV *[]byte, origSize int64, fileName, mime string) {
	// Parse range offsets simply to decide what to fetch from origin
	var rangeStart, rangeEnd int64 = 0, origSize - 1
	rangeHeader := r.Header.Get("Range")
	if strings.HasPrefix(rangeHeader, "bytes=") {
		spec := strings.TrimPrefix(rangeHeader, "bytes=")
		parts := strings.Split(spec, "-")
		if len(parts) >= 2 {
			if s, err := strconv.ParseInt(parts[0], 10, 64); err == nil && s >= 0 {
				rangeStart = s
			}
			if parts[1] != "" {
				if e, err := strconv.ParseInt(parts[1], 10, 64); err == nil && e >= rangeStart {
					rangeEnd = e
				}
			}
		}
	}

	if rangeEnd-rangeStart+1 > MaxStreamChunk {
		rangeEnd = rangeStart + MaxStreamChunk - 1
	}
	if rangeEnd >= origSize {
		rangeEnd = origSize - 1
	}

	plainData, err := DecryptMediaRange(targetUrl, folderID, filePID, rawKey, cachedIV, origSize, rangeStart, rangeEnd)
	if err != nil {
		log.Printf("[Stream] DecryptMediaRange error: %v", err)
		http.Error(w, "Failed to stream media", http.StatusInternalServerError)
		return
	}

	// Serve decrypted chunk directly with standard partial content response
	actualLen := int64(len(plainData))
	actualEnd := rangeStart + actualLen - 1

	w.Header().Set("Content-Type", mime)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rangeStart, actualEnd, origSize))
	w.Header().Set("Content-Length", strconv.FormatInt(actualLen, 10))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges")
	w.WriteHeader(http.StatusPartialContent)

	if r.Method != http.MethodHead {
		w.Write(plainData)
	}
}
