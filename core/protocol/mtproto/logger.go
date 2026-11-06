package mtproto

import (
	"fmt"

	"github.com/9seconds/mtg/v2/mtglib"

	"github.com/sagernet/sing/common/logger"
)

// mtgLogger adapts a sing-box logger to mtglib.Logger. sing-box loggers have no
// structured field binding, so Named/Bind* accumulate a short bracketed prefix. //H
type mtgLogger struct {
	logger logger.ContextLogger
	prefix string
}

func newMTGLogger(l logger.ContextLogger) mtglib.Logger {
	return &mtgLogger{logger: l}
}

func (l *mtgLogger) with(field string) mtglib.Logger {
	prefix := l.prefix + "[" + field + "] "
	return &mtgLogger{logger: l.logger, prefix: prefix}
}

func (l *mtgLogger) Named(name string) mtglib.Logger { return l.with(name) }

func (l *mtgLogger) BindInt(name string, value int) mtglib.Logger {
	return l.with(fmt.Sprintf("%s=%d", name, value))
}

func (l *mtgLogger) BindStr(name, value string) mtglib.Logger {
	return l.with(name + "=" + value)
}

func (l *mtgLogger) BindJSON(name, value string) mtglib.Logger {
	return l.with(name + "=" + value)
}

func (l *mtgLogger) Printf(format string, args ...any) {
	l.logger.Debug(l.prefix, fmt.Sprintf(format, args...))
}

func (l *mtgLogger) Info(msg string)                    { l.logger.Info(l.prefix, msg) }
func (l *mtgLogger) InfoError(msg string, err error)    { l.logger.Info(l.prefix, msg, ": ", err) }
func (l *mtgLogger) Warning(msg string)                 { l.logger.Warn(l.prefix, msg) }
func (l *mtgLogger) WarningError(msg string, err error) { l.logger.Warn(l.prefix, msg, ": ", err) }
func (l *mtgLogger) Debug(msg string)                   { l.logger.Debug(l.prefix, msg) }
func (l *mtgLogger) DebugError(msg string, err error)   { l.logger.Debug(l.prefix, msg, ": ", err) }
