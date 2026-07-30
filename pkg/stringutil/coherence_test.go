package stringutil

import "testing"

func TestLooksLikeGibberish(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{
			name: "real LLM output",
			text: "Hello! How can I help you today? I'm a language model assistant ready to answer your questions.",
			want: false,
		},
		{
			name: "honeypot garbage",
			text: "j2dh082yj30 kijjj tin q0a0j0zd4 xr7bm2 plq9z vvvnk",
			want: true,
		},
		{
			name: "random hex tokens",
			text: "4f2c 8a3d 1b7e 0c9f 5d6a 3e2b 7f1c 9d0e 2a4b 6c8d",
			want: true,
		},
		{
			name: "empty string",
			text: "",
			want: false,
		},
		{
			name: "short valid text",
			text: "Yes, hello",
			want: false,
		},
		{
			name: "single word",
			text: "hello",
			want: false,
		},
		{
			name: "code output still coherent",
			text: "The function returns a list of integers sorted in ascending order using the quicksort algorithm.",
			want: false,
		},
		{
			name: "mixed gibberish with some words",
			text: "the x7q2 br9k hello z3m1 w8p4 y6n5 v2k8 t9j3 r1h7",
			want: true,
		},
		{
			name: "numeric heavy but structured",
			text: "Port 8080 is open on 10.0.0.1 and port 443 is open on 10.0.0.2",
			want: false,
		},
		{
			name: "all consonants no vowels",
			text: "bkfgm dlprt cnvxz hqwst jmkrl bfgtn dplrt cnvxz hqwst",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeGibberish(tt.text)
			if got != tt.want {
				t.Errorf("LooksLikeGibberish(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestIsWordLike(t *testing.T) {
	tests := []struct {
		token string
		want  bool
	}{
		{"hello", true},
		{"the", true},
		{"I", true},
		{"a", true},
		{"x7q2", false},
		{"4f2c", false},
		{"bkfgm", false},
		{"Hello!", true},
		{"", false},
		{"today?", true},
		{"kijjj", false},
		{"vvvnk", false},
	}
	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			got := isWordLike(tt.token)
			if got != tt.want {
				t.Errorf("isWordLike(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}
