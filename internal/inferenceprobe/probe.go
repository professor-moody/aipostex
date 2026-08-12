// Package inferenceprobe verifies whether an inference endpoint runs input-dependent
// handler code versus returning a canned/fixture response.
//
// The GPU-bound inference servers (Triton, TF-Serving, TorchServe, BentoML, vLLM)
// cannot be distinguished from a protocol-accurate fixture by status code alone: a
// CPU mock happily returns 200 with a static prediction. Claiming "execution-confirmed"
// off a 2xx would therefore over-claim against a canned fixture. This probe sends two
// distinct inputs and compares the (normalized) outputs:
//
//   - output VARIES with input  -> input-dependent handler execution -> execution-confirmed
//   - IDENTICAL output for distinct inputs -> canned/fixture response -> reachable (detection)
//
// This makes the tool honest without hardcoding either outcome: it earns
// execution-confirmed whenever output varies with input — a real GPU-backed model and a
// CPU handler that transforms its input both pass, because both ran attacker-reachable,
// input-sensitive code (so the lab's input-transforming serving mocks are correctly
// execution-confirmed, matching a real handler's observable behavior) — and stays at
// detection only for a truly canned, identical-output response. The earned claim is
// therefore "input-dependent handler execution," NOT a warranty of real ML-model
// semantics. Mirrors the openai-compat ScoreInferenceResponse / litellm credential-gate
// control-probe patterns.
package inferenceprobe

import (
	"encoding/json"
	"sort"
	"strings"
)

// Result reports whether an inference endpoint performs real inference.
type Result struct {
	Real     bool   // output varied with input -> genuine inference
	Compared bool   // both probe requests succeeded and were compared
	Evidence string // human-readable explanation for finding evidence/metadata
}

// Landed returns the honest landed for this probe result:
// "execution-confirmed" only when real input-dependent inference was verified,
// otherwise "reachable" (the endpoint responded but inference was not verified).
func (r Result) Landed() string {
	if r.Real {
		return "execution-confirmed"
	}
	return "reachable"
}

// SendFunc performs one inference request and returns (body, statusCode, err).
type SendFunc func(input []byte) (body string, status int, err error)

// Verify sends inputA and a mutated variant through send and compares outputs.
// If inputB is nil it is derived from inputA via MutateInput.
func Verify(inputA []byte, send SendFunc) Result {
	inputB := MutateInput(inputA)
	bodyA, stA, errA := send(inputA)
	bodyB, stB, errB := send(inputB)
	if errA != nil || errB != nil || stA == 0 || stB == 0 || stA >= 400 || stB >= 400 {
		return Result{Real: false, Compared: false,
			Evidence: "inference reality probe could not complete (request failed); not verified as real inference"}
	}
	if normalize(bodyA) != normalize(bodyB) {
		return Result{Real: true, Compared: true,
			Evidence: "output varied with distinct inputs — verified real, input-dependent inference"}
	}
	return Result{Real: false, Compared: true,
		Evidence: "identical output for distinct inputs — canned/fixture response, not verified inference"}
}

// structuralKeys name input-schema fields that must be preserved when mutating an
// input (mutating them would make the request invalid), as opposed to data values.
var structuralKeys = map[string]bool{
	"name": true, "datatype": true, "dtype": true, "shape": true,
	"model": true, "model_name": true, "signature_name": true,
	"version": true, "parameters": true, "id": true,
}

// volatileKeys name output fields that legitimately vary between identical-input
// calls against a real server (ids, timestamps); ignored when comparing outputs so
// two canned responses differing only in such fields still read as identical.
var volatileKeys = map[string]bool{
	"id": true, "created": true, "created_at": true, "timestamp": true,
	"request_id": true, "requestid": true, "trace_id": true, "completion_id": true,
}

// MutateInput returns a copy of raw (JSON) with non-structural leaf values changed,
// producing a structurally-valid but semantically-distinct input. Non-JSON input gets
// a marker appended.
func MutateInput(raw []byte) []byte {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return append(append([]byte{}, raw...), []byte(" probe-variant")...)
	}
	out, err := json.Marshal(mutate(v))
	if err != nil {
		return raw
	}
	return out
}

func mutate(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k := range t {
			if structuralKeys[strings.ToLower(k)] {
				continue
			}
			t[k] = mutate(t[k])
		}
		return t
	case []interface{}:
		for i := range t {
			t[i] = mutate(t[i])
		}
		return t
	case string:
		return t + "_aipxq"
	case float64:
		return t + 7
	case bool:
		return !t
	default:
		return v
	}
}

// normalize canonicalizes a response body for comparison: JSON gets volatile keys
// stripped and is re-marshaled with sorted keys; non-JSON is trimmed.
func normalize(body string) string {
	var v interface{}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return strings.TrimSpace(body)
	}
	stripVolatile(v)
	return canonical(v)
}

func stripVolatile(v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k := range t {
			if volatileKeys[strings.ToLower(k)] {
				delete(t, k)
				continue
			}
			stripVolatile(t[k])
		}
	case []interface{}:
		for i := range t {
			stripVolatile(t[i])
		}
	}
}

// canonical renders v with map keys sorted, so key ordering does not affect equality.
func canonical(v interface{}) string {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.WriteString(canonical(t[k]))
		}
		b.WriteByte('}')
		return b.String()
	case []interface{}:
		var b strings.Builder
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(canonical(e))
		}
		b.WriteByte(']')
		return b.String()
	default:
		out, _ := json.Marshal(v)
		return string(out)
	}
}
