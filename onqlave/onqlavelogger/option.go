package onqlavelogger

import (
	"github.com/google/uuid"
	"go.uber.org/zap/zapcore"
)

type Option func(*Logger)

func WithFilters(filters ...Filter) Option {
	return func(l *Logger) {
		l.filters = append(l.filters, filters...)
	}
}

func WithCid(cid string) Option {
	return func(l *Logger) {
		if cid == "" {
			cid = uuid.New().String()
		}

		l.correlationID = cid
	}
}

func WithTimeEncoder(encoder zapcore.TimeEncoder) Option {
	return func(l *Logger) {
		l.encodeTime = encoder
	}
}

func WithDurationEncoder(encoder zapcore.DurationEncoder) Option {
	return func(l *Logger) {
		l.encodeDuration = encoder
	}
}

func WithDevelopment(isDevelop bool) Option {
	return func(l *Logger) {
		l.isDevelopment = isDevelop
	}
}

func WithLevel(level zapcore.Level) Option {
	return func(l *Logger) {
		l.level = level
	}
}
