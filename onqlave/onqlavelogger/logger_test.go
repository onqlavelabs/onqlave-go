package onqlavelogger

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gopkg.in/go-playground/assert.v1"
)

func TestLogger_WithCid(t *testing.T) {
	logWithEmptyCid := NewLog("logWithEmptyCid").WithCid("")
	logWithCid := NewLog("logWithCid").WithCid("custom-correlation-id")

	assert.NotEqual(t, logWithEmptyCid.correlationID, "")
	assert.Equal(t, logWithCid.correlationID, "custom-correlation-id")
}

func TestLogger_WithFields(t *testing.T) {
	loggerCore, observerLog := observer.New(zapcore.InfoLevel)
	logWithFields := NewLog("TestLogger_WithFields")
	logWithFields.Logger = zap.New(loggerCore)

	logWithFields.WithFields(map[string]any{"one": 1}).Info("")
	logWithFields.WithFields(map[string]any{"foo": "bar"}).Info("")
	logWithFields.WithFields(map[string]any{"bool": true}).Info("")
	logWithFields.Info("")

	assert.Equal(t, []observer.LoggedEntry{
		{Context: []zap.Field{zap.Int("one", 1)}},
		{Context: []zap.Field{zap.String("foo", "bar")}},
		{Context: []zap.Field{zap.Bool("bool", true)}},
		{Context: []zap.Field{}},
	}, observerLog.AllUntimed())
}
