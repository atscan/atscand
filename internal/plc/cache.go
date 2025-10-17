package plc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

type Cache struct {
	dir     string
	enabled bool
	encoder *zstd.Encoder
	decoder *zstd.Decoder
}

func NewCache(dir string, enabled bool) (*Cache, error) {
	if !enabled {
		return &Cache{enabled: false}, nil
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache dir: %w", err)
	}

	// Create zstd encoder
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}

	// Create zstd decoder
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}

	return &Cache{
		dir:     dir,
		enabled: true,
		encoder: encoder,
		decoder: decoder,
	}, nil
}

func (c *Cache) Close() {
	if c.encoder != nil {
		c.encoder.Close()
	}
	if c.decoder != nil {
		c.decoder.Close()
	}
}

// getCacheKey generates a unique cache key from the after timestamp
func (c *Cache) getCacheKey(after string) string {
	if after == "" {
		return "initial"
	}
	// Hash the timestamp to create a valid filename
	hash := sha256.Sum256([]byte(after))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter filename
}

// GetCachePath returns the full path for a cache file
func (c *Cache) GetCachePath(after string) string {
	key := c.getCacheKey(after)
	return filepath.Join(c.dir, fmt.Sprintf("plc_export_%s.json.zst", key))
}

// Has checks if a cache file exists
func (c *Cache) Has(after string) bool {
	if !c.enabled {
		return false
	}
	path := c.GetCachePath(after)
	_, err := os.Stat(path)
	return err == nil
}

// Get retrieves operations from cache
func (c *Cache) Get(after string) ([]PLCOperation, error) {
	if !c.enabled {
		return nil, fmt.Errorf("cache disabled")
	}

	path := c.GetCachePath(after)

	// Read compressed file
	compressedData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	// Decompress
	decompressed, err := c.decoder.DecodeAll(compressedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress cache: %w", err)
	}

	// Unmarshal JSON
	var operations []PLCOperation
	if err := json.Unmarshal(decompressed, &operations); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	return operations, nil
}

// Set stores operations in cache
func (c *Cache) Set(after string, operations []PLCOperation) error {
	if !c.enabled {
		return nil // Silently skip if cache is disabled
	}

	path := c.GetCachePath(after)

	// Marshal to JSON
	jsonData, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("failed to marshal operations: %w", err)
	}

	// Compress
	compressed := c.encoder.EncodeAll(jsonData, nil)

	// Write to file
	if err := os.WriteFile(path, compressed, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// Stats returns cache statistics
func (c *Cache) Stats() (int, int64, error) {
	if !c.enabled {
		return 0, 0, nil
	}

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return 0, 0, err
	}

	var totalSize int64
	count := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) == ".zst" {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			totalSize += info.Size()
			count++
		}
	}

	return count, totalSize, nil
}
