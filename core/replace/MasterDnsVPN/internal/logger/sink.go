// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package logger: a sink for programs that embed the client as a library and
// have a logger of their own (hiddify-sing-box).
// ==============================================================================

package logger

// Sink receives every log line instead of the console and file writers. level is one of
// LevelDebug, LevelInfo, LevelWarn and LevelError; message has the color tags removed.
type Sink func(level int, message string)

// SetSink routes every line at or above the logger's level to sink. A nil sink restores the
// console and file output.
func (l *Logger) SetSink(sink Sink) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.sink = sink
	l.mu.Unlock()
}
