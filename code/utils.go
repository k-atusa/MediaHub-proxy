// test823 : project WHY MediaHub Proxy - utils
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"mime"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
)

// ========== Cryptographic & Memory Safety Helpers (USAG-Lib Integration) ==========

var SCLEAR_BACK = func(b []byte) { clear(b) }

func sclear(data []byte) {
	SCLEAR_BACK(data)
	runtime.KeepAlive(data)
}

// RandomHex generates a random hex-encoded string of given byte length using USAG-Lib Bencrypt.Random
func RandomHex(byteLen int) string {
	return hex.EncodeToString(Bencrypt.Random(byteLen))
}

// MaskBytes masks sensitive bytes in memory using USAG-Lib Bencrypt Masker
func MaskBytes(data []byte) []byte {
	m := Bencrypt.GetMasker(-1)
	out, err := m.XOR(data)
	if err != nil {
		out = make([]byte, len(data))
		copy(out, data)
	}
	return out
}

// UnmaskBytes unmasks masked bytes from memory using USAG-Lib Bencrypt Masker
func UnmaskBytes(data []byte) []byte {
	m := Bencrypt.GetMasker(-1)
	out, err := m.XOR(data)
	if err != nil {
		out = make([]byte, len(data))
		copy(out, data)
	}
	return out
}

// mkiv derives chunk-IV by XOR(counter bytes 4-11, base-IV) in little-endian order
func mkiv(globalIV []byte, counter uint64) []byte {
	iv := make([]byte, len(globalIV))
	copy(iv, globalIV)

	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, counter)

	for i := 0; i < 8 && 4+i < len(iv); i++ {
		iv[4+i] ^= counterBytes[i]
	}
	return iv
}

// DeAESGCM decrypts ciphertext using AES-GCM with 16-byte tag
func DeAESGCM(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, iv, ciphertext, nil)
}

// ========== MIME Mapping (Standard Library) ==========

func init() {
	mime.AddExtensionType(".js", "text/javascript; charset=utf-8")
	mime.AddExtensionType(".mjs", "text/javascript; charset=utf-8")
	mime.AddExtensionType(".wasm", "application/wasm")
	mime.AddExtensionType(".mkv", "video/x-matroska")
	mime.AddExtensionType(".flac", "audio/flac")
}

// GetMimeType derives standard MIME type from filename using standard library
func GetMimeType(fileName string) string {
	if t := mime.TypeByExtension(filepath.Ext(fileName)); t != "" {
		return t
	}
	return "application/octet-stream"
}

// ========== In-Memory Cache (TTL & Max Size Bounded) ==========

type cacheItem struct {
	data      []byte
	expiresAt time.Time
}

type MemoryCache struct {
	mu         sync.RWMutex
	items      map[string]cacheItem
	totalBytes int64
	maxBytes   int64
}

var globalDataCache *MemoryCache

// InitMemoryCache initializes global in-memory cache with specified MB limit
func InitMemoryCache(maxMB int) *MemoryCache {
	if maxMB <= 0 {
		maxMB = 32
	}
	c := &MemoryCache{
		items:    make(map[string]cacheItem),
		maxBytes: int64(maxMB) * 1048576,
	}
	globalDataCache = c

	// Periodic purge goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			c.PurgeExpired()
		}
	}()

	return c
}

// Set stores data into cache with TTL (only caches payloads <= 1MB)
func (c *MemoryCache) Set(key string, data []byte, ttl time.Duration) {
	if c == nil || len(data) > 1048576 { // Strictly enforce 1MB threshold
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	itemSize := int64(len(data))
	if old, exists := c.items[key]; exists {
		c.totalBytes -= int64(len(old.data))
		delete(c.items, key)
	}

	// Simple eviction if exceeding max capacity
	if c.totalBytes+itemSize > c.maxBytes {
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.expiresAt) || c.totalBytes+itemSize > c.maxBytes {
				c.totalBytes -= int64(len(v.data))
				delete(c.items, k)
			}
		}
	}

	if c.totalBytes+itemSize <= c.maxBytes {
		c.items[key] = cacheItem{
			data:      data,
			expiresAt: time.Now().Add(ttl),
		}
		c.totalBytes += itemSize
	}
}

// Get retrieves cached payload if present and unexpired
func (c *MemoryCache) Get(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.RLock()
	item, exists := c.items[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}
	if time.Now().After(item.expiresAt) {
		c.mu.Lock()
		if it, ok := c.items[key]; ok && time.Now().After(it.expiresAt) {
			c.totalBytes -= int64(len(it.data))
			delete(c.items, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	return item.data, true
}

// PurgeExpired clears expired cache items
func (c *MemoryCache) PurgeExpired() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, v := range c.items {
		if now.After(v.expiresAt) {
			c.totalBytes -= int64(len(v.data))
			delete(c.items, k)
		}
	}
}

// ========== Secure In-Memory Session Management (Masked in Memory) ==========

// SecureSession holds credentials and metadata masked in memory for both stream and share sessions
type SecureSession struct {
	ID           string    `json:"id"`
	MaskedFolder []byte    `json:"-"`
	MaskedPID    []byte    `json:"-"`
	MaskedKey    []byte    `json:"-"`
	CachedIV     []byte    `json:"-"`
	OrigSize     int64     `json:"orig_size"`
	FileName     string    `json:"file_name"`
	Mime         string    `json:"mime"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// GetUnmaskedCredentials returns unmasked credentials. Caller MUST sclear(rawKey) when done!
func (s *SecureSession) GetUnmaskedCredentials() (folderID, filePID string, rawKey []byte, err error) {
	rawFolder := UnmaskBytes(s.MaskedFolder)
	defer sclear(rawFolder)
	rawPID := UnmaskBytes(s.MaskedPID)
	defer sclear(rawPID)
	key := UnmaskBytes(s.MaskedKey)

	return string(rawFolder), string(rawPID), key, nil
}

// SessionStore manages active sessions in memory with capacity bounds and automatic TTL cleanup
type SessionStore struct {
	mu          sync.RWMutex
	sessions    map[string]*SecureSession
	maxSessions int
}

var (
	globalStreamManager *SessionStore
	globalShareManager  *SessionStore
)

// NewSessionStore creates a generic in-memory session store
func NewSessionStore(maxSessions int, cleanupInterval time.Duration) *SessionStore {
	if maxSessions <= 0 {
		maxSessions = 5000
	}
	ss := &SessionStore{
		sessions:    make(map[string]*SecureSession),
		maxSessions: maxSessions,
	}

	go func() {
		ticker := time.NewTicker(cleanupInterval)
		for range ticker.C {
			ss.Cleanup()
		}
	}()

	return ss
}

// InitStreamManager initializes the in-memory stream manager
func InitStreamManager(maxSessions int) *SessionStore {
	globalStreamManager = NewSessionStore(maxSessions, 5*time.Minute)
	return globalStreamManager
}

// InitShareManager initializes the in-memory share manager
func InitShareManager(maxSessions int) *SessionStore {
	globalShareManager = NewSessionStore(maxSessions, 10*time.Minute)
	return globalShareManager
}

// Create stores a new session with masked credentials and specified TTL
func (ss *SessionStore) Create(folderID, filePID string, fileKey []byte, origSize int64, fileName string, ttl time.Duration) (*SecureSession, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Enforce capacity bounds
	if len(ss.sessions) >= ss.maxSessions {
		var oldestID string
		var oldestTime time.Time
		first := true
		for id, s := range ss.sessions {
			if first || s.CreatedAt.Before(oldestTime) {
				oldestID = id
				oldestTime = s.CreatedAt
				first = false
			}
		}
		if oldestID != "" {
			if old, ok := ss.sessions[oldestID]; ok {
				sclear(old.MaskedKey)
				sclear(old.MaskedFolder)
				sclear(old.MaskedPID)
				sclear(old.CachedIV)
			}
			delete(ss.sessions, oldestID)
		}
	}

	now := time.Now()
	session := &SecureSession{
		ID:           RandomHex(16),
		MaskedFolder: MaskBytes([]byte(folderID)),
		MaskedPID:    MaskBytes([]byte(filePID)),
		MaskedKey:    MaskBytes(fileKey),
		OrigSize:     origSize,
		FileName:     fileName,
		Mime:         GetMimeType(fileName),
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}

	ss.sessions[session.ID] = session
	return session, nil
}

// Get retrieves an unexpired session
func (ss *SessionStore) Get(id string) (*SecureSession, bool) {
	ss.mu.RLock()
	session, exists := ss.sessions[id]
	ss.mu.RUnlock()

	if !exists {
		return nil, false
	}
	if time.Now().After(session.ExpiresAt) {
		ss.Delete(id)
		return nil, false
	}
	return session, true
}

// Delete purges a session and securely zeroes memory
func (ss *SessionStore) Delete(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if s, exists := ss.sessions[id]; exists {
		sclear(s.MaskedKey)
		sclear(s.MaskedFolder)
		sclear(s.MaskedPID)
		sclear(s.CachedIV)
		delete(ss.sessions, id)
	}
}

// Cleanup purges expired sessions
func (ss *SessionStore) Cleanup() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	now := time.Now()
	for id, s := range ss.sessions {
		if now.After(s.ExpiresAt) {
			sclear(s.MaskedKey)
			sclear(s.MaskedFolder)
			sclear(s.MaskedPID)
			sclear(s.CachedIV)
			delete(ss.sessions, id)
		}
	}
}
