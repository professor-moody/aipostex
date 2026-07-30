package vulncheck

import "testing"

func TestVersionSatisfiesRanges(t *testing.T) {
	tests := []struct {
		version string
		expr    string
		want    bool
	}{
		{"v0.14.0", "< 0.14.1", true},
		{"0.14.1", "< 0.14.1", false},
		{"0.12.3", "<= 0.12.3", true},
		{"0.12.4", "<= 0.12.3", false},
		{"0.10.2", ">= 0.10.2, < 0.11.1", true},
		{"0.11.1", ">= 0.10.2, < 0.11.1", false},
		{"1.2.3-rc1", "= 1.2.3", true},
	}
	for _, tc := range tests {
		got, err := VersionSatisfies(tc.version, tc.expr)
		if err != nil {
			t.Fatalf("VersionSatisfies(%q, %q) returned error: %v", tc.version, tc.expr, err)
		}
		if got != tc.want {
			t.Fatalf("VersionSatisfies(%q, %q) = %t, want %t", tc.version, tc.expr, got, tc.want)
		}
	}
}

func TestVersionSatisfiesRejectsInvalidRange(t *testing.T) {
	if _, err := VersionSatisfies("1.2.3", "before someday"); err == nil {
		t.Fatal("expected invalid range to fail")
	}
}
