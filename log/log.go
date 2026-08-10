package log

import (
	"encoding/hex"
	"io"
	"log"
	"os"
	"sync/atomic"
)

var debug atomic.Bool

func Init() {
	log.SetOutput(os.Stdout)
}

func EnableDebug() {
	debug.Store(true)
}

func DisableDebug() {
	debug.Store(false)
}

func DebugEnabled() bool {
	return debug.Load()
}

func Print(v ...any) {
	log.Print(v...)
}

func DebugPrint(v ...any) {
	if debug.Load() {
		log.Print(v...)
	}
}

func Println(v ...any) {
	log.Println(v...)
}

func DebugPrintln(v ...any) {
	if debug.Load() {
		log.Println(v...)
	}
}

func Printf(format string, v ...any) {
	log.Printf(format, v...)
}

func DebugPrintf(format string, v ...any) {
	if debug.Load() {
		log.Printf(format, v...)
	}
}

func Fatal(v ...any) {
	log.Fatal(v...)
}

func Fatalf(format string, v ...any) {
	log.Fatalf(format, v...)
}

func DumpHex(buf []byte) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer func(stdoutDumper io.WriteCloser) {
		_ = stdoutDumper.Close()
	}(stdoutDumper)
	_, _ = stdoutDumper.Write(buf)
}

func DebugDumpHex(buf []byte) {
	if debug.Load() {
		stdoutDumper := hex.Dumper(os.Stdout)
		defer func(stdoutDumper io.WriteCloser) {
			_ = stdoutDumper.Close()
		}(stdoutDumper)
		_, _ = stdoutDumper.Write(buf)
	}
}

func NewLogger(prefix string) *log.Logger {
	return log.New(os.Stdout, prefix, log.LstdFlags)
}
