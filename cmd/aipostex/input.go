package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

// loadFindingCollection accepts a standard FindingCollection JSON file, JSONL with
// one Finding per line, OR a dossier directory (from `--format dossier -o <dir>`),
// in which case it reads the dossier's findings.jsonl. The directory check comes
// first so plain file paths keep working unchanged.
func loadFindingCollection(path string) (report.FindingCollection, error) {
	if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
		path = filepath.Join(path, "findings.jsonl")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return report.FindingCollection{}, fmt.Errorf("reading %s: %w", path, err)
	}

	if collection, ok, err := parseFindingCollectionJSON(data); err != nil {
		return report.FindingCollection{}, fmt.Errorf("parsing %s: %w", path, err)
	} else if ok {
		return collection, nil
	}

	collection, err := parseFindingJSONL(data)
	if err != nil {
		return report.FindingCollection{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return collection, nil
}

func parseFindingCollectionJSON(data []byte) (report.FindingCollection, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return report.FindingCollection{}, false, fmt.Errorf("input is empty")
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &root); err != nil {
		return report.FindingCollection{}, false, nil
	}
	if _, ok := root["findings"]; !ok {
		return report.FindingCollection{}, false, nil
	}

	var collection report.FindingCollection
	if err := json.Unmarshal(trimmed, &collection); err != nil {
		return report.FindingCollection{}, true, err
	}
	return collection, true, nil
}

func parseFindingJSONL(data []byte) (report.FindingCollection, error) {
	collection := report.NewCollection()
	collection.StartTime = time.Time{}
	collection.EndTime = time.Time{}
	reader := bufio.NewReader(bytes.NewReader(data))
	lineNo := 0

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			trimmed := strings.TrimSpace(string(line))
			if trimmed != "" {
				var finding report.Finding
				if unmarshalErr := json.Unmarshal([]byte(trimmed), &finding); unmarshalErr != nil {
					return report.FindingCollection{}, fmt.Errorf("invalid jsonl finding on line %d: %w", lineNo, unmarshalErr)
				}
				collection.Findings = append(collection.Findings, finding)
			}
		}
		if err != nil {
			break
		}
	}

	if len(collection.Findings) == 0 {
		return report.FindingCollection{}, fmt.Errorf("input did not contain a finding collection or jsonl findings")
	}

	return *collection, nil
}
