package formatter

import (
	"strings"
	"testing"
)

func TestFormatLogLineOmitsContentType(t *testing.T) {
	line := FormatLogLine(
		"http://example.com",
		200,
		"login",
		123,
		[]string{"<若依>"},
	)

	if strings.Contains(line, "text/html") {
		t.Fatalf("FormatLogLine should not print Content-Type: %s", line)
	}
}

func TestFormatTitleAlwaysUsesHighlightColor(t *testing.T) {
	SetColorEnabled(true)
	defer SetColorEnabled(true)

	got := FormatTitle("login")
	want := ColorTitleHighlightFallback + "[login]" + ColorReset
	if got != want {
		t.Fatalf("FormatTitle() = %q, want %q", got, want)
	}
}

func TestFormatLogLineTitleColorDoesNotDependOnFingerprints(t *testing.T) {
	SetColorEnabled(true)
	defer SetColorEnabled(true)

	withFingerprint := FormatLogLine("http://example.com", 200, "login", 1, []string{"<若依>"})
	withoutFingerprint := FormatLogLine("http://example.com", 200, "login", 1, nil)
	wantTitle := ColorTitleHighlightFallback + "[login]" + ColorReset

	if !strings.Contains(withFingerprint, wantTitle) {
		t.Fatalf("matched line title is not highlighted: %q", withFingerprint)
	}
	if !strings.Contains(withoutFingerprint, wantTitle) {
		t.Fatalf("no-match line title is not highlighted: %q", withoutFingerprint)
	}
}

func TestFormatFingerprintNameUsesLightPurple(t *testing.T) {
	SetColorEnabled(true)
	defer SetColorEnabled(true)

	got := FormatFingerprintName("若依")
	want := ColorFingerprintLightPurpleFallback + "若依" + ColorReset
	if got != want {
		t.Fatalf("FormatFingerprintName() = %q, want %q", got, want)
	}
}
