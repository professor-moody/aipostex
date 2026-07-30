package main

import (
	"net/url"
	"strings"
	"sync"

	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
)

var (
	targetWarningMu   sync.Mutex
	targetWarningSeen = make(map[string]struct{})
)

func normalizeAndWarnTarget(raw string) string {
	normalized := exploitcommon.NormalizeTarget(raw)
	if strings.TrimSpace(normalized) == "" {
		return normalized
	}

	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Host == "" {
		warnTargetOnce(raw, "appears malformed; attempting request anyway")
		return normalized
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		warnTargetOnce(raw, "uses a non-http(s) scheme; attempting request anyway")
	}
	return normalized
}

func warnTargetOnce(raw, message string) {
	key := strings.TrimSpace(raw) + "|" + message
	targetWarningMu.Lock()
	defer targetWarningMu.Unlock()
	if _, ok := targetWarningSeen[key]; ok {
		return
	}
	targetWarningSeen[key] = struct{}{}
	warnf("target %q %s", strings.TrimSpace(raw), message)
}
