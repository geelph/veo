package redirect

import (
	"testing"
)

func TestDetectClientRedirectURL_UserCase(t *testing.T) {
	body := `<html><head><title>Object moved</title></head><body>
<h2>Object moved to <a href="/Services/Identification/login.ashx?ReturnUrl=%2f">here</a>.</h2>
</body></html>`

	expected := "/Services/Identification/login.ashx?ReturnUrl=%2f"
	result := DetectClientRedirectURL(body)

	if result != expected {
		t.Errorf("DetectClientRedirectURL() failed. Got '%v', want '%v'", result, expected)
	} else {
		t.Logf("Success! Got '%v'", result)
	}
}
