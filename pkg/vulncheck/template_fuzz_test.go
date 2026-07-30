package vulncheck

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzLoadTemplate(f *testing.F) {
	f.Add([]byte("id: test\ninfo:\n  name: test\n  severity: info\n  tags:\n    - test\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var tmpl Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return
		}
		_ = tmpl.Validate()
	})
}

func FuzzInterpolate(f *testing.F) {
	f.Add("{{var}}", "hello")
	f.Add("{{base_url}}/path", "http://example.com")
	f.Add("no placeholders here", "value")
	f.Add("{{var}} and {{base_url}}/api", "test")
	f.Add("", "")
	f.Add("{{missing}}", "x")

	f.Fuzz(func(t *testing.T, tmpl, val string) {
		interpolate(tmpl, map[string]string{
			"var":      val,
			"base_url": "http://example.com",
		})
	})
}
