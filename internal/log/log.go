package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var (
	verboseLog *log.Logger
	infoLog    *log.Logger
	errorLog   *log.Logger
)

func Init(verbose bool) {
	infoWriter := os.Stdout
	verboseWriter := io.Discard
	if verbose {
		verboseWriter = os.Stdout
	}

	infoLog = log.New(infoWriter, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	verboseLog = log.New(verboseWriter, "VERBOSE: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func Verbose(format string, v ...interface{}) {
	verboseLog.Printf(format, v...)
}

func Info(format string, v ...interface{}) {
	infoLog.Printf(format, v...)
}

func Error(format string, v ...interface{}) {
	errorLog.Printf(format, v...)
}

func Fatal(format string, v ...interface{}) {
	errorLog.Fatalf(format, v...)
}

// Banner prints a startup banner
func Banner(version string) {
	banner := `
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     █████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗     ║
║    ██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║     ║
║    ███████║   ██║   ███████╗██║     ███████║██╔██╗ ██║     ║
║    ██╔══██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║     ║
║    ██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║     ║
║    ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝     ║
║                                                            ║
║            AT Protocol Network Scanner & Indexer           ║
║                      Version %s                       ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
`
	fmt.Printf(banner, padVersion(version))
}

// padVersion pads the version string to fit the banner
func padVersion(version string) string {
	targetLen := 7
	if len(version) < targetLen {
		padding := strings.Repeat(" ", (targetLen-len(version))/2)
		return padding + version + padding
	}
	return version
}

// RedactPassword redacts passwords from connection strings
func RedactPassword(connStr string) string {
	// Handle PostgreSQL URI format: postgresql://user:password@host/db
	// Pattern: find everything between :// and @ that contains a colon
	if strings.Contains(connStr, "://") && strings.Contains(connStr, "@") {
		// Find the credentials section
		parts := strings.SplitN(connStr, "://", 2)
		if len(parts) == 2 {
			scheme := parts[0]
			remainder := parts[1]

			// Find the @ symbol
			atIndex := strings.Index(remainder, "@")
			if atIndex > 0 {
				credentials := remainder[:atIndex]
				hostAndDb := remainder[atIndex:]

				// Check if there's a password (look for colon in credentials)
				colonIndex := strings.Index(credentials, ":")
				if colonIndex > 0 {
					username := credentials[:colonIndex]
					return fmt.Sprintf("%s://%s:***%s", scheme, username, hostAndDb)
				}
			}
		}
	}

	// Handle key-value format: host=localhost password=secret user=myuser
	if strings.Contains(connStr, "password=") {
		parts := strings.Split(connStr, " ")
		for i, part := range parts {
			if strings.HasPrefix(part, "password=") {
				parts[i] = "password=***"
			}
		}
		return strings.Join(parts, " ")
	}

	return connStr
}

// PrintConfig prints configuration summary
func PrintConfig(items map[string]string) {
	Info("=== Configuration ===")
	maxKeyLen := 0
	for key := range items {
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
	}

	for key, value := range items {
		padding := strings.Repeat(" ", maxKeyLen-len(key))

		// Redact database connection strings
		displayValue := value
		if strings.Contains(key, "Database Path") || strings.Contains(key, "Connection") || strings.Contains(strings.ToLower(key), "password") {
			displayValue = RedactPassword(value)
		}

		fmt.Printf("  %s:%s %s\n", key, padding, displayValue)
	}
	Info("====================")
}
