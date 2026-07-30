package inferenceprobe

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestVerify_CannedFixtureStaysReachable(t *testing.T) {
	// A canned fixture returns the same body regardless of input.
	send := func(input []byte) (string, int, error) {
		return `{"prediction":"acme-fraud","score":0.99}`, 200, nil
	}
	r := Verify([]byte(`{"instances":[{"x":1}]}`), send)
	if r.Real {
		t.Fatalf("canned fixture must not be verified real")
	}
	if !r.Compared {
		t.Fatalf("probe should have compared two successful responses")
	}
	if got := r.Landed(); got != "reachable" {
		t.Fatalf("canned fixture landed = %q, want reachable", got)
	}
}

func TestVerify_RealInferenceEarnsExecutionConfirmed(t *testing.T) {
	// A real model's output depends on the input (echo the input as the prediction).
	send := func(input []byte) (string, int, error) {
		return fmt.Sprintf(`{"prediction":%q}`, string(input)), 200, nil
	}
	r := Verify([]byte(`{"instances":[{"x":1}]}`), send)
	if !r.Real {
		t.Fatalf("input-dependent output must be verified real")
	}
	if got := r.Landed(); got != "execution-confirmed" {
		t.Fatalf("real inference landed = %q, want execution-confirmed", got)
	}
}

func TestVerify_VolatileOnlyDiffStaysReachable(t *testing.T) {
	// Output differs only in volatile fields (id/created) — must still read as canned.
	n := 0
	send := func(input []byte) (string, int, error) {
		n++
		return fmt.Sprintf(`{"id":"req-%d","created":%d,"prediction":"same"}`, n, 1700000000+n), 200, nil
	}
	r := Verify([]byte(`{"x":1}`), send)
	if r.Real {
		t.Fatalf("volatile-only difference must not count as real inference")
	}
}

func TestVerify_FailedRequestNotVerified(t *testing.T) {
	send := func(input []byte) (string, int, error) {
		return `{"error":"missing session"}`, 401, nil
	}
	r := Verify([]byte(`{"x":1}`), send)
	if r.Real || r.Compared {
		t.Fatalf("a failed probe request must yield Real=false, Compared=false")
	}
	if got := r.Landed(); got != "reachable" {
		t.Fatalf("failed probe landed = %q, want reachable", got)
	}
}

func TestMutateInput_PreservesStructuralKeysChangesData(t *testing.T) {
	// Triton-style tensor input: name/datatype/shape are structural and must be preserved;
	// the data values must change so a real model produces different output.
	orig := []byte(`{"inputs":[{"name":"input__0","datatype":"FP32","shape":[1,3],"data":[1.0,2.0,3.0]}]}`)
	mut := MutateInput(orig)
	var got struct {
		Inputs []struct {
			Name     string    `json:"name"`
			Datatype string    `json:"datatype"`
			Shape    []int     `json:"shape"`
			Data     []float64 `json:"data"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal(mut, &got); err != nil {
		t.Fatalf("mutated input is not valid JSON: %v (%s)", err, mut)
	}
	in := got.Inputs[0]
	if in.Name != "input__0" || in.Datatype != "FP32" {
		t.Fatalf("structural keys changed: name=%q datatype=%q", in.Name, in.Datatype)
	}
	if len(in.Shape) != 2 || in.Shape[0] != 1 || in.Shape[1] != 3 {
		t.Fatalf("shape changed: %v", in.Shape)
	}
	if in.Data[0] == 1.0 && in.Data[1] == 2.0 && in.Data[2] == 3.0 {
		t.Fatalf("data values were not mutated: %v", in.Data)
	}
}

func TestMutateInput_ChangesTextLeaf(t *testing.T) {
	mut := MutateInput([]byte(`{"text":"hello"}`))
	if strings.Contains(string(mut), `"hello"`) {
		t.Fatalf("text leaf was not mutated: %s", mut)
	}
}

func TestMutateInput_NonJSON(t *testing.T) {
	mut := MutateInput([]byte(`not json`))
	if string(mut) == "not json" {
		t.Fatalf("non-JSON input should be altered for the probe variant")
	}
}
