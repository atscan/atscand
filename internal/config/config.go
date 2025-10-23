package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database DatabaseConfig `yaml:"database"`
	PLC      PLCConfig      `yaml:"plc"`
	PDS      PDSConfig      `yaml:"pds"`
	API      APIConfig      `yaml:"api"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
	Type string `yaml:"type"` // postgres
}

type PLCConfig struct {
	DirectoryURL string        `yaml:"directory_url"`
	ScanInterval time.Duration `yaml:"scan_interval"`
	BatchSize    int           `yaml:"batch_size"`
	BundleDir    string        `yaml:"bundles_dir"`
	UseCache     bool          `yaml:"use_cache"`
	IndexDIDs    bool          `yaml:"index_dids"`
}

type PDSConfig struct {
	ScanInterval    time.Duration `yaml:"scan_interval"`
	Timeout         time.Duration `yaml:"timeout"`
	Workers         int           `yaml:"workers"`
	RecheckInterval time.Duration `yaml:"recheck_interval"`
	ScanRetention   int           `yaml:"scan_retention"`
}

type APIConfig struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	Verbose bool   `yaml:"verbose"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Set defaults
	if cfg.PLC.DirectoryURL == "" {
		cfg.PLC.DirectoryURL = "https://plc.directory"
	}
	if cfg.PLC.ScanInterval == 0 {
		cfg.PLC.ScanInterval = 1 * time.Hour
	}
	if cfg.PLC.BatchSize == 0 {
		cfg.PLC.BatchSize = 1000
	}
	if cfg.PLC.BundleDir == "" {
		cfg.PLC.BundleDir = "./plc_bundles"
	}
	if cfg.PDS.ScanInterval == 0 {
		cfg.PDS.ScanInterval = 15 * time.Minute
	}
	if cfg.PDS.Timeout == 0 {
		cfg.PDS.Timeout = 30 * time.Second
	}
	if cfg.PDS.Workers == 0 {
		cfg.PDS.Workers = 10
	}
	if cfg.PDS.ScanRetention == 0 {
		cfg.PDS.ScanRetention = 3
	}
	if cfg.API.Port == 0 {
		cfg.API.Port = 8080
	}

	return &cfg, nil
}
