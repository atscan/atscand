import { file, write } from "bun";
import { join } from "path";
import { mkdir } from "fs/promises";
import { init, compress } from "@bokuweb/zstd-wasm";

// --- Configuration ---
const CSV_FILE = process.argv[2];
const CONFIG_FILE = "config.yaml";
const COMPRESSION_LEVEL = 5; // zstd level 1-22 (5 is a good balance)
// ---------------------

if (!CSV_FILE) {
  console.error("Usage: bun run utils/import-labels.js <path-to-csv-file>");
  process.exit(1);
}

console.log("========================================");
console.log("PLC Operation Labels Import (Bun + WASM)");
console.log("========================================");

// 1. Read and parse config
console.log(`Loading config from ${CONFIG_FILE}...`);
const configFile = await file(CONFIG_FILE).text();
const config = Bun.YAML.parse(configFile);
const bundleDir = config?.plc?.bundle_dir;

if (!bundleDir) {
  console.error("Error: Could not parse plc.bundle_dir from config.yaml");
  process.exit(1);
}

const FINAL_LABELS_DIR = join(bundleDir, "labels");
await mkdir(FINAL_LABELS_DIR, { recursive: true });

console.log(`CSV File:       ${CSV_FILE}`);
console.log(`Output Dir:     ${FINAL_LABELS_DIR}`);
console.log("");

// 2. Initialize Zstd WASM module
await init();

// --- Pass 1: Read entire file into memory and group by bundle ---
console.log("Pass 1/2: Reading and grouping all lines by bundle...");
console.warn("This will use a large amount of RAM!");

const startTime = Date.now();
const bundles = new Map(); // Map<string, string[]>
let lineCount = 0;

const inputFile = file(CSV_FILE);
const fileStream = inputFile.stream();
const decoder = new TextDecoder();
let remainder = "";

for await (const chunk of fileStream) {
  const text = remainder + decoder.decode(chunk);
  const lines = text.split("\n");
  remainder = lines.pop() || "";

  for (const line of lines) {
    if (line === "") continue;
    lineCount++;

    if (lineCount === 1 && line.startsWith("bundle,")) {
      continue; // Skip header
    }

    const firstCommaIndex = line.indexOf(",");
    if (firstCommaIndex === -1) {
      console.warn(`Skipping malformed line: ${line}`);
      continue;
    }
    const bundleNumStr = line.substring(0, firstCommaIndex);
    const bundleKey = bundleNumStr.padStart(6, "0");

    // Add line to the correct bundle's array
    if (!bundles.has(bundleKey)) {
      bundles.set(bundleKey, []);
    }
    bundles.get(bundleKey).push(line);
  }
}
// Note: We ignore any final `remainder` as it's likely an empty line

console.log(`Finished reading ${lineCount.toLocaleString()} lines.`);
console.log(`Found ${bundles.size} unique bundles.`);

// --- Pass 2: Compress and write each bundle ---
console.log("\nPass 2/2: Compressing and writing bundle files...");
let i = 0;
for (const [bundleKey, lines] of bundles.entries()) {
  i++;
  console.log(`  (${i}/${bundles.size}) Compressing bundle ${bundleKey}...`);

  // Join all lines for this bundle into one big string
  const content = lines.join("\n");
  
  // Compress the string
  const compressedData = compress(Buffer.from(content), COMPRESSION_LEVEL);

  // Write the compressed data to the file
  const outPath = join(FINAL_LABELS_DIR, `${bundleKey}.csv.zst`);
  await write(outPath, compressedData);
}

// 3. Clean up
const totalTime = (Date.now() - startTime) / 1000;
console.log("\n========================================");
console.log("Import Summary");
console.log("========================================");
console.log(`✓ Import completed in ${totalTime.toFixed(2)} seconds.`);
console.log(`Total lines processed: ${lineCount.toLocaleString()}`);
console.log(`Label files are stored in: ${FINAL_LABELS_DIR}`);