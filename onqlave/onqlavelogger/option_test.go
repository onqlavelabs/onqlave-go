package onqlavelogger

import (
	"fmt"
	"testing"

	"go.uber.org/zap/zapcore"

	"gopkg.in/go-playground/assert.v1"
)

func TestWithCid(t *testing.T) {
	loggerWithoutCid := NewLog("TestWithFilter", WithCid(""))
	loggerWithCid := NewLog("TestWithFilter", WithCid("custom-correlation-id"))

	assert.NotEqual(t, loggerWithoutCid.correlationID, "")
	assert.Equal(t, loggerWithCid.correlationID, "custom-correlation-id")
}

func TestWithTimeEncoder(t *testing.T) {
	loggerTimeEncoder := NewLog("TestWithTimeEncoder", WithTimeEncoder(zapcore.RFC3339TimeEncoder))

	assert.Equal(t, fmt.Sprintf("%T", loggerTimeEncoder.encodeTime), "zapcore.TimeEncoder")
}

func TestWithDurationEncoder(t *testing.T) {
	loggerDurationEncoder := NewLog("TestWithDurationEncoder", WithDurationEncoder(zapcore.NanosDurationEncoder))

	assert.Equal(t, fmt.Sprintf("%T", loggerDurationEncoder.encodeDuration), "zapcore.DurationEncoder")
}

func TestWithDevelopment(t *testing.T) {
	loggerDevelopment := NewLog("loggerDevelopment", WithDevelopment(true))

	assert.Equal(t, loggerDevelopment.isDevelopment, true)
}

func TestWithLevel(t *testing.T) {
	loggerDebug := NewLog("loggerDebug", WithLevel(zapcore.DebugLevel))
	loggerInfo := NewLog("loggerInfo")
	loggerWarn := NewLog("loggerWarn", WithLevel(zapcore.WarnLevel))

	assert.Equal(t, loggerDebug.level, zapcore.DebugLevel)
	assert.Equal(t, loggerInfo.level, zapcore.InfoLevel)
	assert.Equal(t, loggerWarn.level, zapcore.WarnLevel)
}
