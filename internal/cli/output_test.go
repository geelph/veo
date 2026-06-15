package cli

import "testing"

func TestShouldUseRealtimeCSVReport(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "", want: false},
		{path: "report.json", want: false},
		{path: "report.html", want: true},
		{path: "report.HTML", want: true},
		{path: "report.csv", want: true},
		{path: "report.txt", want: true},
	}

	for _, tt := range tests {
		if got := shouldUseRealtimeCSVReport(tt.path); got != tt.want {
			t.Fatalf("shouldUseRealtimeCSVReport(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
