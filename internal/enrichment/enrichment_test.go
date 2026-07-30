package enrichment

import (
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestSummarizeJSONShape(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"empty string", "", ""},
		{"non-json", "hello world", ""},
		{"simple object", `{"b":1,"a":2}`, "json keys=a,b"},
		{"nested object", `{"z":{"nested":true},"a":1}`, "json keys=a,z"},
		{"array", `[1,2,3]`, "json array len=3"},
		{"empty array", `[]`, "json array len=0"},
		{"empty object", `{}`, "json keys="},
		{"object with many keys", `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8}`, "json keys=a,b,c,d,e,f,+2 more"},
		{"scalar string", `"hello"`, ""},
		{"scalar number", `42`, ""},
		{"whitespace padded", `  {"x":1}  `, "json keys=x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeJSONShape(tc.raw)
			if got != tc.want {
				t.Errorf("SummarizeJSONShape(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestExtractFileReferences(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{"empty", "", 0},
		{"no paths", "just some text", 0},
		{"tmp path", `found at /tmp/model.bin ok`, 1},
		{"home path", `user data at /home/user/.config/secret.json`, 1},
		{"var tmp path", `/var/tmp/output.log`, 1},
		{"file= prefix", `file=/tmp/gradio/upload.txt`, 1},
		{"json with paths", `{"path":"/tmp/data.csv","other":"/home/user/file.txt"}`, 2},
		{"duplicates", `/tmp/a.txt and /tmp/a.txt again`, 1},
		{"gradio file obj path only", `{"path":"/tmp/gradio/123/output.csv","orig_name":"output.csv","size":1024}`, 1},
		{"gradio file obj path and url", `{"path":"/tmp/gradio/456/model.pkl","url":"http://example.com/file/model.pkl","orig_name":"model.pkl"}`, 1},
		{"gradio nested in data array", `{"data":[{"path":"/tmp/gradio/789/result.txt","orig_name":"result.txt"}]}`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractFileReferences(tc.raw)
			if len(got) != tc.want {
				t.Errorf("ExtractFileReferences(%q) returned %d refs, want %d: %v", tc.raw, len(got), tc.want, got)
			}
		})
	}
}

func TestArtifactKind(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{"json extension", "data.json", "", "json-artifact"},
		{"yaml extension", "config.yaml", "", "yaml-artifact"},
		{"yml extension", "config.yml", "", "yaml-artifact"},
		{"txt extension", "output.txt", "", "text-artifact"},
		{"log extension", "output.log", "", "text-artifact"},
		{"csv extension", "data.csv", "", "tabular-artifact"},
		{"notebook extension", "analysis.ipynb", "", "notebook-artifact"},
		{"model pt", "model.pt", "", "model-artifact"},
		{"model safetensors", "weights.safetensors", "", "model-artifact"},
		{"model bin", "model.bin", "", "model-artifact"},
		{"model onnx", "model.onnx", "", "model-artifact"},
		{"model pkl", "model.pkl", "", "model-artifact"},
		{"json body no ext", "data", `{"key":"value"}`, "json-artifact"},
		{"array body no ext", "data", `[1,2,3]`, "json-artifact"},
		{"model metadata body", "readme", "artifact_uri: s3://bucket", "model-metadata"},
		{"mlmodel body", "readme", "some mlmodel content", "model-metadata"},
		{"log body", "output", "traceback (most recent call last)", "log-artifact"},
		{"error body", "output", "there was an error in processing", "log-artifact"},
		{"plain text fallback", "output", "just some text", "text-artifact"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ArtifactKind(tc.path, tc.body)
			if got != tc.want {
				t.Errorf("ArtifactKind(%q, %q) = %q, want %q", tc.path, tc.body, got, tc.want)
			}
		})
	}
}

func TestSensitivityHints(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		body     string
		wantAny  []string
		wantNone bool
	}{
		{"credential keyword", ".env", "api_key=secret123", []string{"credential"}, false},
		{"pii keyword", "data.csv", "ssn: 123-45-6789", []string{"pii"}, false},
		{"training data keyword", "prompts.jsonl", "instruction: do something", []string{"training-data"}, false},
		{"model material keyword", "model.bin", "checkpoint data with tensor values", []string{"model-material"}, false},
		{"no matches", "readme.md", "nothing sensitive here", nil, true},
		{"multiple hints", "secrets.json", "api_key=x, ssn=y, embedding=z, mlmodel=w", []string{"credential", "pii", "training-data", "model-material"}, false},
		{"pii requires delimiter", "readme.md", "the email address is safe", nil, true},
		{"pii with colon matches", "report.txt", "email: user@example.com", []string{"pii"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SensitivityHints(tc.path, tc.body)
			if tc.wantNone {
				if len(got) != 0 {
					t.Errorf("SensitivityHints(%q, %q) = %v, want empty", tc.path, tc.body, got)
				}
				return
			}
			for _, want := range tc.wantAny {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("SensitivityHints(%q, %q) = %v, missing %q", tc.path, tc.body, got, want)
				}
			}
		})
	}
}

func TestGradioEndpointRiskLabel(t *testing.T) {
	tests := []struct {
		name                         string
		queue, fileInput, fileOutput bool
		want                         string
	}{
		{"all true", true, true, true, "queue+file-roundtrip"},
		{"file roundtrip no queue", false, true, true, "file-roundtrip"},
		{"queue only", true, false, false, "queue-capable"},
		{"file ingest only", false, true, false, "file-ingest"},
		{"file emit only", false, false, true, "file-emit"},
		{"none", false, false, false, "predict-only"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GradioEndpointRiskLabel(tc.queue, tc.fileInput, tc.fileOutput)
			if got != tc.want {
				t.Errorf("GradioEndpointRiskLabel(%v,%v,%v) = %q, want %q", tc.queue, tc.fileInput, tc.fileOutput, got, tc.want)
			}
		})
	}
}

func TestLandedRank(t *testing.T) {
	tests := []struct {
		value string
		want  int
	}{
		{"takeover-capable", 5},
		{"execution-confirmed", 4},
		{"read-confirmed", 3},
		{"influenced", 2},
		{"reachable", 1},
		{"", 0},
		{"unknown", 0},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			got := LandedRank(tc.value)
			if got != tc.want {
				t.Errorf("LandedRank(%q) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

func TestStrongerLanded(t *testing.T) {
	tests := []struct {
		current, candidate, want string
	}{
		{"reachable", "read-confirmed", "read-confirmed"},
		{"read-confirmed", "reachable", "read-confirmed"},
		{"", "influenced", "influenced"},
		{"takeover-capable", "reachable", "takeover-capable"},
	}
	for _, tc := range tests {
		t.Run(tc.current+"_vs_"+tc.candidate, func(t *testing.T) {
			got := StrongerLanded(tc.current, tc.candidate)
			if got != tc.want {
				t.Errorf("StrongerLanded(%q, %q) = %q, want %q", tc.current, tc.candidate, got, tc.want)
			}
		})
	}
}

func TestApplyStageLanded(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		got := ApplyStageLanded(nil, "recon", "reachable", "fingerprint")
		if got["stage"] != "recon" || got["landed"] != "reachable" || got["chain_source"] != "fingerprint" {
			t.Errorf("unexpected metadata: %v", got)
		}
	})

	t.Run("existing metadata preserved", func(t *testing.T) {
		existing := map[string]interface{}{"module": "ray"}
		got := ApplyStageLanded(existing, "impact", "read-confirmed", "ray-logs", "jobs-api")
		if got["module"] != "ray" {
			t.Error("existing key 'module' was lost")
		}
		if got["stage"] != "impact" {
			t.Errorf("stage = %v, want proof", got["stage"])
		}
		if got["capability_labels"] != "jobs-api" {
			t.Errorf("capability_labels = %v, want jobs-api", got["capability_labels"])
		}
	})

	t.Run("empty strings skipped", func(t *testing.T) {
		got := ApplyStageLanded(nil, "", "", "")
		if _, ok := got["stage"]; ok {
			t.Error("empty stage should not be set")
		}
	})
}

func TestAnnotateStageLanded(t *testing.T) {
	t.Run("nil finding", func(t *testing.T) {
		AnnotateStageLanded(nil, "recon", "reachable", "test")
	})

	t.Run("sets metadata on finding", func(t *testing.T) {
		f := &report.Finding{ID: "test-1"}
		AnnotateStageLanded(f, "impact", "execution-confirmed", "ray-submit", "env-disclosure")
		if f.Metadata["stage"] != "impact" {
			t.Errorf("stage = %v, want proof", f.Metadata["stage"])
		}
		if f.Metadata["landed"] != "execution-confirmed" {
			t.Errorf("landed = %v, want execution-confirmed", f.Metadata["landed"])
		}
	})
}

func TestClassifyRayLogLanded(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"execution markers", "uid=1000 gid=1000 python3 site-packages", "execution-confirmed"},
		{"read markers", "/etc/passwd contents here", "read-confirmed"},
		{"traceback", "Traceback (most recent call last)", "read-confirmed"},
		{"generic", "job completed successfully", "reachable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyRayLogLanded(tc.raw)
			if got != tc.want {
				t.Errorf("ClassifyRayLogLanded(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestClassifyArtifactPreview(t *testing.T) {
	t.Run("model artifact is takeover-capable", func(t *testing.T) {
		kind, _, strength := ClassifyArtifactPreview("model.safetensors", "binary data")
		if kind != "model-artifact" {
			t.Errorf("kind = %q, want model-artifact", kind)
		}
		if strength != "takeover-capable" {
			t.Errorf("strength = %q, want takeover-capable", strength)
		}
	})

	t.Run("credential text stays read-confirmed (reading a secret is not execution)", func(t *testing.T) {
		_, hints, strength := ClassifyArtifactPreview("config.txt", "api_key=secret")
		if len(hints) == 0 {
			t.Error("expected sensitivity hints")
		}
		// Reading a file that contains a credential is a READ, not execution.
		if strength != "read-confirmed" {
			t.Errorf("strength = %q, want read-confirmed", strength)
		}
	})

	t.Run("pii-only text stays read-confirmed", func(t *testing.T) {
		_, hints, strength := ClassifyArtifactPreview("report.txt", "ssn: 123-45-6789")
		if len(hints) == 0 {
			t.Error("expected pii hint")
		}
		if strength != "read-confirmed" {
			t.Errorf("strength = %q, want read-confirmed (pii alone should not escalate)", strength)
		}
	})

	t.Run("training-data-only text stays read-confirmed", func(t *testing.T) {
		_, hints, strength := ClassifyArtifactPreview("data.jsonl", "instruction: summarize the document")
		if len(hints) == 0 {
			t.Error("expected training-data hint")
		}
		if strength != "read-confirmed" {
			t.Errorf("strength = %q, want read-confirmed (training-data alone should not escalate)", strength)
		}
	})

	t.Run("plain text is read-confirmed", func(t *testing.T) {
		_, hints, strength := ClassifyArtifactPreview("readme.txt", "just a readme")
		if len(hints) != 0 {
			t.Errorf("unexpected hints: %v", hints)
		}
		if strength != "read-confirmed" {
			t.Errorf("strength = %q, want read-confirmed", strength)
		}
	})
}

func TestClassifyGradioServeChain(t *testing.T) {
	tests := []struct {
		name       string
		downloaded bool
		fileRef    string
		body       string
		want       string
	}{
		{"full chain", true, "/tmp/file.txt", "content", "read-confirmed"},
		{"file ref only", false, "/tmp/file.txt", "", "reachable"},
		{"no ref", false, "", "", "influenced"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyGradioServeChain(tc.downloaded, tc.fileRef, tc.body)
			if got != tc.want {
				t.Errorf("ClassifyGradioServeChain(%v, %q, %q) = %q, want %q", tc.downloaded, tc.fileRef, tc.body, got, tc.want)
			}
		})
	}
}

func TestFileReferencePattern(t *testing.T) {
	re := FileReferencePattern()
	if re == nil {
		t.Fatal("FileReferencePattern returned nil")
	}
	if !re.MatchString("/tmp/model.bin") {
		t.Error("expected /tmp path to match")
	}
	if !re.MatchString("/home/user/.config/key") {
		t.Error("expected /home path to match")
	}
}

func TestErrorWordPattern(t *testing.T) {
	re := ErrorWordPattern()
	if re == nil {
		t.Fatal("ErrorWordPattern returned nil")
	}
	if !re.MatchString("an error occurred") {
		t.Error("expected 'error' to match")
	}
	if re.MatchString("no issues here") {
		t.Error("expected no match without error keyword")
	}
}

func TestSummarizeCapabilityLabels(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"empty", nil, ""},
		{"single", []string{"jobs-api"}, "jobs-api"},
		{"multiple sorted", []string{"dashboard", "jobs-api"}, "dashboard,jobs-api"},
		{"duplicates", []string{"a", "b", "a"}, "a,b"},
		{"whitespace", []string{" ", "a", " b "}, "a,b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeCapabilityLabels(tc.values...)
			if got != tc.want {
				t.Errorf("SummarizeCapabilityLabels(%v) = %q, want %q", tc.values, got, tc.want)
			}
		})
	}
}
