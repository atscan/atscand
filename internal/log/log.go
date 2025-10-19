package log

import (
	"io"
	"log"
	"os"
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
