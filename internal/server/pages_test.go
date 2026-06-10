package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStandalonePages_RenderAndEscape verifies every standalone template renders
// and that structured fields are HTML-escaped (the migration from fmt.Fprintf to
// html/template exists specifically to make this guarantee).
func TestStandalonePages_RenderAndEscape(t *testing.T) {
	s := &Server{}
	evil := `<script>alert(1)</script>`

	cases := []struct {
		name string
		data any
	}{
		{"error", errorPageData{Title: "Oops", Status: 403, Heading: "Denied", Message: "plain message"}},
		{"enroll", enrollPageData{Title: "Authorize", Heading: "Authorize Access", IP: evil, Mode: "", Token: evil}},
		{"enroll", enrollPageData{Title: "Authorize", Heading: "Extend", IP: "1.2.3.4", Mode: "extend", Remaining: "3 days", Token: "tok"}},
		{"ip-authorize", ipAuthorizePageData{Title: "Authorize IP", IP: evil, Name: evil, ReturnURL: evil, CSRF: evil}},
		{"ip-authorized", ipAuthorizedPageData{Title: "Done", Heading: "Authorized", IP: evil, Name: evil}},
		{"ip-restricted", ipRestrictedPageData{Title: "Restricted", Host: evil, IP: evil, AuthorizeURL: "https://admin/x"}},
	}

	for _, c := range cases {
		rec := httptest.NewRecorder()
		s.renderStandalonePage(rec, 200, c.name, c.data)
		body := rec.Body.String()
		if rec.Code != 200 {
			t.Fatalf("%s: status %d", c.name, rec.Code)
		}
		if !strings.Contains(body, "<!DOCTYPE html>") || !strings.Contains(body, "Gatecrash") {
			t.Fatalf("%s: missing page shell", c.name)
		}
		// No structured field should appear as a live <script> tag.
		if strings.Contains(body, "<script>alert(1)</script>") {
			t.Fatalf("%s: unescaped script injection in output", c.name)
		}
	}
}

// TestServeErrorPage_TrustsMessageHTML documents that serveErrorPage intentionally
// renders its message as trusted HTML (callers pre-escape dynamic parts), so
// markup like <strong> is preserved.
func TestServeErrorPage_TrustsMessageHTML(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.serveErrorPage(rec, httptest.NewRequest("GET", "/", nil), 404, "Not Found", "Missing <strong>thing</strong>.")
	body := rec.Body.String()
	if rec.Code != 404 {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(body, "Missing <strong>thing</strong>.") {
		t.Fatalf("error message HTML should be preserved, got: %s", body)
	}
}
