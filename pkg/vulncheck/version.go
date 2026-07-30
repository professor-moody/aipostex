package vulncheck

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type VersionRange struct {
	Operator string
	Version  semanticVersion
}

type semanticVersion struct {
	Parts []int
}

var versionRangePattern = regexp.MustCompile(`^\s*(<=|>=|<|>|=)?\s*v?([0-9]+(?:\.[0-9]+){0,3})(?:[-+][A-Za-z0-9_.-]+)?\s*$`)

func ParseVersionRange(expr string) (VersionRange, error) {
	matches := versionRangePattern.FindStringSubmatch(strings.TrimSpace(expr))
	if matches == nil {
		return VersionRange{}, fmt.Errorf("expected semver range like '< 1.2.3'")
	}
	op := matches[1]
	if op == "" {
		op = "="
	}
	version, err := parseSemanticVersion(matches[2])
	if err != nil {
		return VersionRange{}, err
	}
	return VersionRange{Operator: op, Version: version}, nil
}

func VersionSatisfies(version, expr string) (bool, error) {
	actual, err := parseSemanticVersion(version)
	if err != nil {
		return false, err
	}
	for _, part := range strings.Split(expr, ",") {
		rangeExpr, err := ParseVersionRange(part)
		if err != nil {
			return false, err
		}
		cmp := compareSemanticVersion(actual, rangeExpr.Version)
		matched := false
		switch rangeExpr.Operator {
		case "<":
			matched = cmp < 0
		case "<=":
			matched = cmp <= 0
		case ">":
			matched = cmp > 0
		case ">=":
			matched = cmp >= 0
		case "=":
			matched = cmp == 0
		default:
			return false, fmt.Errorf("unsupported version range operator %q", rangeExpr.Operator)
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func parseSemanticVersion(value string) (semanticVersion, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "v"))
	if idx := strings.IndexAny(value, "-+"); idx >= 0 {
		value = value[:idx]
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return semanticVersion{}, fmt.Errorf("invalid semantic version %q", value)
	}
	out := make([]int, len(parts))
	for i, part := range parts {
		if part == "" {
			return semanticVersion{}, fmt.Errorf("invalid semantic version %q", value)
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return semanticVersion{}, fmt.Errorf("invalid semantic version %q: %w", value, err)
		}
		out[i] = n
	}
	return semanticVersion{Parts: out}, nil
}

func compareSemanticVersion(a, b semanticVersion) int {
	maxLen := len(a.Parts)
	if len(b.Parts) > maxLen {
		maxLen = len(b.Parts)
	}
	for i := 0; i < maxLen; i++ {
		av, bv := 0, 0
		if i < len(a.Parts) {
			av = a.Parts[i]
		}
		if i < len(b.Parts) {
			bv = b.Parts[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}
