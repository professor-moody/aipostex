// Package main tests use a shared global cfg. Tests in this package MUST NOT
// call t.Parallel() because withTestConfig saves and restores cfg by value.
// Adding t.Parallel() will introduce data races on the shared config.
package main

import "testing"

func withTestConfig(t *testing.T, fn func()) {
	t.Helper()

	saved := *cfg
	saved.ScanPaths = append([]string(nil), cfg.ScanPaths...)
	saved.ExcludePaths = append([]string(nil), cfg.ExcludePaths...)
	saved.Targets = append([]string(nil), cfg.Targets...)
	saved.Ports = append([]int(nil), cfg.Ports...)
	saved.Tags = append([]string(nil), cfg.Tags...)
	saved.Severities = append([]string(nil), cfg.Severities...)

	defer func() {
		*cfg = saved
	}()

	fn()
}
