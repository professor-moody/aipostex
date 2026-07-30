package main

import (
	"strings"
	"testing"
)

func TestExtractFileReferences(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "empty string",
			raw:  "",
			want: nil,
		},
		{
			name: "no file references",
			raw:  "just some text without paths",
			want: nil,
		},
		{
			name: "tmp path in plain text",
			raw:  "wrote output to /tmp/results.json",
			want: []string{"/tmp/results.json"},
		},
		{
			name: "multiple paths",
			raw:  "reading /tmp/a.txt and /home/user/b.txt",
			want: []string{"/home/user/b.txt", "/tmp/a.txt"},
		},
		{
			name: "deduplicates paths",
			raw:  "/tmp/dup.txt is at /tmp/dup.txt",
			want: []string{"/tmp/dup.txt"},
		},
		{
			name: "json with file references",
			raw:  `{"path": "/tmp/model.bin", "log": "/var/tmp/train.log"}`,
			want: []string{"/tmp/model.bin", "/var/tmp/train.log"},
		},
		{
			name: "file= prefix",
			raw:  "file=/tmp/secret.key",
			want: []string{"/tmp/secret.key"},
		},
		{
			name: "home directory path",
			raw:  "loaded from /home/deploy/.ssh/id_rsa",
			want: []string{"/home/deploy/.ssh/id_rsa"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractFileReferences(tc.raw)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("index %d: got %q, want %q", i, got[i], tc.want[i])
				}
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
		{"json extension", "model/config.json", "", "json-artifact"},
		{"yaml extension", "pipeline.yaml", "", "yaml-artifact"},
		{"yml extension", "config.yml", "", "yaml-artifact"},
		{"txt extension", "notes.txt", "", "text-artifact"},
		{"log extension", "train.log", "", "text-artifact"},
		{"csv extension", "data.csv", "", "tabular-artifact"},
		{"ipynb extension", "notebook.ipynb", "", "notebook-artifact"},
		{"pt model file", "weights.pt", "", "model-artifact"},
		{"bin model file", "model.bin", "", "model-artifact"},
		{"safetensors file", "model.safetensors", "", "model-artifact"},
		{"onnx file", "model.onnx", "", "model-artifact"},
		{"pkl file", "data.pkl", "", "model-artifact"},
		{"json body no extension", "unknown", `{"key": "value"}`, "json-artifact"},
		{"array body no extension", "unknown", `[1, 2, 3]`, "json-artifact"},
		{"body with artifact_uri", "meta", "artifact_uri: s3://bucket", "model-metadata"},
		{"body with mlmodel", "meta", "flavors:\n  python_function:\n    mlmodel", "model-metadata"},
		{"body with traceback", "output", "Traceback (most recent call last):", "log-artifact"},
		{"body with error", "output", "an error occurred during training", "log-artifact"},
		{"plain text fallback", "readme", "hello world", "text-artifact"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := artifactKind(tc.path, tc.body)
			if got != tc.want {
				t.Fatalf("artifactKind(%q, %q) = %q, want %q", tc.path, tc.body, got, tc.want)
			}
		})
	}
}

func TestSensitivityHints(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want []string
	}{
		{"no hints", "readme.txt", "hello world", nil},
		{"credential via api_key", "config", "api_key=sk-abc", []string{"credential"}},
		{"credential via token", "auth", "bearer token xyz", []string{"credential"}},
		{"credential via secret", ".env", "my_secret=foo", []string{"credential"}},
		{"credential via password", "config", "password=hunter2", []string{"credential"}},
		{"pii via email", "data", "email: user@example.com", []string{"pii"}},
		{"training-data via dataset", "manifest", "dataset config", []string{"training-data"}},
		{"model-material via safetensors", "model/weights.safetensors", "", []string{"model-material"}},
		{"model-material via mlmodel", "MLmodel", "mlmodel flavors", []string{"model-material"}},
		{
			"multiple hints",
			"model.yaml",
			"api_key=sk-abc\nembedding data\nmlmodel checkpoint",
			[]string{"credential", "model-material", "training-data"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sensitivityHints(tc.path, tc.body)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("sensitivityHints(%q, ...) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestClassifyRayLogLanded(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"empty string", "", "reachable"},
		{"generic log output", "INFO: server started", "reachable"},
		{"contains python keyword", "python 3.9.0 started", "execution-confirmed"},
		{"contains pip keyword", "pip install torch", "execution-confirmed"},
		{"contains site-packages", "/usr/lib/python3/site-packages/ray", "execution-confirmed"},
		{"contains hostname", "hostname: worker-node-1", "execution-confirmed"},
		{"contains uid", "uid=1000 gid=1000", "execution-confirmed"},
		{"contains /etc/ path", "reading /etc/hosts", "read-confirmed"},
		{"contains /home/ path", "loading /home/user/config", "read-confirmed"},
		{"contains /tmp/ path", "writing to /tmp/output", "read-confirmed"},
		{"contains traceback", "Traceback (most recent call last)", "read-confirmed"},
		{"contains permission denied", "permission denied for /root", "read-confirmed"},
		{"case insensitive", "PYTHON 3.9", "execution-confirmed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyRayLogLanded(tc.raw)
			if got != tc.want {
				t.Fatalf("classifyRayLogLanded(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestClassifyArtifactPreview(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		body         string
		wantKind     string
		wantStrength string
		wantHintsGt0 bool
	}{
		{
			name:         "model artifact gets takeover-capable",
			path:         "model.safetensors",
			body:         "",
			wantKind:     "model-artifact",
			wantStrength: "takeover-capable",
			wantHintsGt0: true,
		},
		{
			name:         "model metadata gets takeover-capable",
			path:         "meta",
			body:         "mlmodel flavors",
			wantKind:     "model-metadata",
			wantStrength: "takeover-capable",
			wantHintsGt0: true,
		},
		{
			name:         "mlflow MLmodel path gets takeover-capable",
			path:         "model/MLmodel",
			body:         "artifact_path: model/MLmodel",
			wantKind:     "model-metadata",
			wantStrength: "takeover-capable",
			wantHintsGt0: true,
		},
		{
			name:         "credential content stays read-confirmed (reading a secret is not execution)",
			path:         "config.json",
			body:         `{"api_key": "sk-abc123"}`,
			wantKind:     "json-artifact",
			wantStrength: "read-confirmed",
			wantHintsGt0: true,
		},
		{
			name:         "plain text stays read-confirmed",
			path:         "notes.txt",
			body:         "some plain text",
			wantKind:     "text-artifact",
			wantStrength: "read-confirmed",
			wantHintsGt0: false,
		},
		{
			name:         "log artifact stays read-confirmed",
			path:         "output.log",
			body:         "some log output",
			wantKind:     "text-artifact",
			wantStrength: "read-confirmed",
			wantHintsGt0: false,
		},
		{
			name:         "training data with embedding stays read-confirmed",
			path:         "data.csv",
			body:         "embedding vectors",
			wantKind:     "tabular-artifact",
			wantStrength: "read-confirmed",
			wantHintsGt0: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, hints, strength := classifyArtifactPreview(tc.path, tc.body)
			if kind != tc.wantKind {
				t.Fatalf("kind = %q, want %q", kind, tc.wantKind)
			}
			if strength != tc.wantStrength {
				t.Fatalf("strength = %q, want %q", strength, tc.wantStrength)
			}
			if tc.wantHintsGt0 && len(hints) == 0 {
				t.Fatal("expected hints, got none")
			}
			if !tc.wantHintsGt0 && len(hints) > 0 {
				t.Fatalf("expected no hints, got %v", hints)
			}
		})
	}
}

func TestClassifyGradioServeChain(t *testing.T) {
	tests := []struct {
		name       string
		downloaded bool
		fileRef    string
		body       string
		want       string
	}{
		{
			name:       "all present gives read-confirmed",
			downloaded: true,
			fileRef:    "/tmp/file.txt",
			body:       "file content here",
			want:       "read-confirmed",
		},
		{
			name:       "fileRef only gives reachable",
			downloaded: false,
			fileRef:    "/tmp/file.txt",
			body:       "",
			want:       "reachable",
		},
		{
			name:       "fileRef with body but not downloaded gives reachable",
			downloaded: false,
			fileRef:    "/tmp/file.txt",
			body:       "content",
			want:       "reachable",
		},
		{
			name:       "no fileRef gives influenced",
			downloaded: false,
			fileRef:    "",
			body:       "",
			want:       "influenced",
		},
		{
			name:       "downloaded but no fileRef gives influenced",
			downloaded: true,
			fileRef:    "",
			body:       "content",
			want:       "influenced",
		},
		{
			name:       "whitespace-only fileRef gives influenced",
			downloaded: true,
			fileRef:    "   ",
			body:       "content",
			want:       "influenced",
		},
		{
			name:       "downloaded with fileRef but whitespace body gives reachable",
			downloaded: true,
			fileRef:    "/tmp/file.txt",
			body:       "   ",
			want:       "reachable",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyGradioServeChain(tc.downloaded, tc.fileRef, tc.body)
			if got != tc.want {
				t.Fatalf("classifyGradioServeChain(%v, %q, %q) = %q, want %q",
					tc.downloaded, tc.fileRef, tc.body, got, tc.want)
			}
		})
	}
}
