package plc

import (
	"context"
	"fmt"
	"time"

	"github.com/atscan/atscanner/internal/log"
	"github.com/atscan/atscanner/internal/storage"
	plcbundle "github.com/atscan/plcbundle"
)

// BundleManager wraps the library's manager with database integration
type BundleManager struct {
	libManager *plcbundle.Manager
	db         storage.Database
	bundleDir  string
	indexDIDs  bool
}

func NewBundleManager(bundleDir string, plcURL string, db storage.Database, indexDIDs bool) (*BundleManager, error) {
	// Create library config
	config := plcbundle.DefaultConfig(bundleDir)

	// Create PLC client
	var client *plcbundle.PLCClient
	if plcURL != "" {
		client = plcbundle.NewPLCClient(plcURL)
	}

	// Create library manager
	libMgr, err := plcbundle.NewManager(config, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create library manager: %w", err)
	}

	return &BundleManager{
		libManager: libMgr,
		db:         db,
		bundleDir:  bundleDir,
		indexDIDs:  indexDIDs,
	}, nil
}

func (bm *BundleManager) Close() {
	if bm.libManager != nil {
		bm.libManager.Close()
	}
}

// LoadBundle loads a bundle (from library) and returns operations
func (bm *BundleManager) LoadBundleOperations(ctx context.Context, bundleNum int) ([]PLCOperation, error) {
	bundle, err := bm.libManager.LoadBundle(ctx, bundleNum)
	if err != nil {
		return nil, err
	}
	return bundle.Operations, nil
}

// LoadBundle loads a full bundle with metadata
func (bm *BundleManager) LoadBundle(ctx context.Context, bundleNum int) (*plcbundle.Bundle, error) {
	return bm.libManager.LoadBundle(ctx, bundleNum)
}

// FetchAndSaveBundle fetches next bundle from PLC and saves to both disk and DB
func (bm *BundleManager) FetchAndSaveBundle(ctx context.Context) (*plcbundle.Bundle, error) {
	// Fetch from PLC using library
	bundle, err := bm.libManager.FetchNextBundle(ctx)
	if err != nil {
		return nil, err
	}

	// Save to disk (library)
	if err := bm.libManager.SaveBundle(ctx, bundle); err != nil {
		return nil, fmt.Errorf("failed to save bundle to disk: %w", err)
	}

	// Save to database
	if err := bm.saveBundleToDatabase(ctx, bundle); err != nil {
		return nil, fmt.Errorf("failed to save bundle to database: %w", err)
	}

	log.Info("✓ Saved bundle %06d (disk + database)", bundle.BundleNumber)

	return bundle, nil
}

// saveBundleToDatabase saves bundle metadata to PostgreSQL
func (bm *BundleManager) saveBundleToDatabase(ctx context.Context, bundle *plcbundle.Bundle) error {
	// Convert library bundle to storage bundle
	dbBundle := &storage.PLCBundle{
		BundleNumber:     bundle.BundleNumber,
		StartTime:        bundle.StartTime,
		EndTime:          bundle.EndTime,
		DIDCount:         bundle.DIDCount,
		Hash:             bundle.Hash,
		CompressedHash:   bundle.CompressedHash,
		CompressedSize:   bundle.CompressedSize,
		UncompressedSize: bundle.UncompressedSize,
		Cursor:           bundle.Cursor,
		PrevBundleHash:   bundle.PrevBundleHash,
		Compressed:       bundle.Compressed,
		CreatedAt:        bundle.CreatedAt,
	}

	// Save to database
	if err := bm.db.CreateBundle(ctx, dbBundle); err != nil {
		return err
	}

	// Index DIDs if enabled
	if bm.indexDIDs && len(bundle.Operations) > 0 {
		if err := bm.indexBundleDIDs(ctx, bundle); err != nil {
			log.Error("Failed to index DIDs for bundle %d: %v", bundle.BundleNumber, err)
			// Don't fail the entire operation
		}
	}

	return nil
}

// indexBundleDIDs indexes DIDs from a bundle into the database
func (bm *BundleManager) indexBundleDIDs(ctx context.Context, bundle *plcbundle.Bundle) error {
	start := time.Now()
	log.Verbose("Indexing DIDs for bundle %06d...", bundle.BundleNumber)

	// Extract DID info from operations
	didInfoMap := ExtractDIDInfoMap(bundle.Operations)

	successCount := 0
	errorCount := 0
	invalidHandleCount := 0

	// Upsert each DID
	for did, info := range didInfoMap {
		validHandle := ValidateHandle(info.Handle)
		if info.Handle != "" && validHandle == "" {
			invalidHandleCount++
		}

		if err := bm.db.UpsertDID(ctx, did, bundle.BundleNumber, validHandle, info.PDS); err != nil {
			log.Error("Failed to index DID %s: %v", did, err)
			errorCount++
		} else {
			successCount++
		}
	}

	elapsed := time.Since(start)
	log.Info("✓ Indexed %d DIDs for bundle %06d (%d errors, %d invalid handles) in %v",
		successCount, bundle.BundleNumber, errorCount, invalidHandleCount, elapsed)

	return nil
}

// VerifyChain verifies bundle chain integrity
func (bm *BundleManager) VerifyChain(ctx context.Context, endBundle int) error {
	result, err := bm.libManager.VerifyChain(ctx)
	if err != nil {
		return err
	}

	if !result.Valid {
		return fmt.Errorf("chain verification failed at bundle %d: %s", result.BrokenAt, result.Error)
	}

	return nil
}

// GetChainInfo returns chain information
func (bm *BundleManager) GetChainInfo(ctx context.Context) (map[string]interface{}, error) {
	return bm.libManager.GetInfo(), nil
}
