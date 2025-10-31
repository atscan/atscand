package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PLC struct {
		BundleDir string `yaml:"bundle_dir"`
	} `yaml:"plc"`
}

var CONFIG_FILE = "config.yaml"

// ---------------------

func main() {
	// Define a new flag for changing the directory
	workDir := flag.String("C", ".", "Change to this directory before running (for finding config.yaml)")
	flag.Usage = func() { // Custom usage message
		fmt.Fprintf(os.Stderr, "Usage: ... | %s [-C /path/to/dir]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Reads sorted CSV from stdin and writes compressed bundle files.")
		flag.PrintDefaults()
	}
	flag.Parse() // Parse all defined flags

	// Change directory if the flag was used
	if *workDir != "." {
		fmt.Printf("Changing working directory to %s...\n", *workDir)
		if err := os.Chdir(*workDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error changing directory to %s: %v\n", *workDir, err)
			os.Exit(1)
		}
	}

	// --- REMOVED UNUSED CODE ---
	// The csvFilePath variable and NArg check were removed
	// as the script now reads from stdin.
	// ---------------------------

	fmt.Println("========================================")
	fmt.Println("PLC Operation Labels Import (Go STDIN)")
	fmt.Println("========================================")

	// 1. Read config (will now read from the new CWD)
	fmt.Printf("Loading config from %s...\n", CONFIG_FILE)
	configData, err := os.ReadFile(CONFIG_FILE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
		os.Exit(1)
	}

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing config.yaml: %v\n", err)
		os.Exit(1)
	}

	if config.PLC.BundleDir == "" {
		fmt.Fprintln(os.Stderr, "Error: Could not parse plc.bundle_dir from config.yaml")
		os.Exit(1)
	}

	finalLabelsDir := filepath.Join(config.PLC.BundleDir, "labels")
	if err := os.MkdirAll(finalLabelsDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Output Dir:     %s\n", finalLabelsDir)
	fmt.Println("Waiting for sorted data from stdin...")

	// 2. Process sorted data from stdin
	// This script *requires* the input to be sorted by bundle number.

	var currentWriter *zstd.Encoder
	var currentFile *os.File
	var lastBundleKey string = ""

	lineCount := 0
	startTime := time.Now()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 1 {
			continue // Skip empty/bad lines
		}

		bundleNumStr := parts[0]
		bundleKey := fmt.Sprintf("%06s", bundleNumStr) // Pad with zeros

		// If the bundle key is new, close the old writer and open a new one.
		if bundleKey != lastBundleKey {
			// Close the previous writer/file
			if currentWriter != nil {
				if err := currentWriter.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "Error closing writer for %s: %v\n", lastBundleKey, err)
				}
				currentFile.Close()
			}

			// Start the new one
			fmt.Printf("  -> Writing bundle %s\n", bundleKey)
			outPath := filepath.Join(finalLabelsDir, fmt.Sprintf("%s.csv.zst", bundleKey))

			file, err := os.Create(outPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating file %s: %v\n", outPath, err)
				os.Exit(1)
			}
			currentFile = file

			writer, err := zstd.NewWriter(file)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating zstd writer: %v\n", err)
				os.Exit(1)
			}
			currentWriter = writer
			lastBundleKey = bundleKey
		}

		// Write the line to the currently active writer
		if _, err := currentWriter.Write([]byte(line + "\n")); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing line: %v\n", err)
		}

		// Progress update
		if lineCount%100000 == 0 {
			elapsed := time.Since(startTime).Seconds()
			rate := float64(lineCount) / elapsed
			fmt.Printf("  ... processed %d lines (%.0f lines/sec)\n", lineCount, rate)
		}
	}

	// 3. Close the very last writer
	if currentWriter != nil {
		if err := currentWriter.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing final writer: %v\n", err)
		}
		currentFile.Close()
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
	}

	totalTime := time.Since(startTime)
	fmt.Println("\n========================================")
	fmt.Println("Import Summary")
	fmt.Println("========================================")
	fmt.Printf("✓ Import completed in %v\n", totalTime)
	fmt.Printf("Total lines processed: %d\n", lineCount)
}
