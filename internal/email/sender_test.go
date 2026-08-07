package email

import "testing"

func TestSendOtp_DisabledLogsAndSucceeds(t *testing.T) {
	s := New("", 587, "", "", "")
	if s.Enabled() {
		t.Fatal("expected disabled sender when host empty")
	}
	if err := s.SendOtp("user@example.com", "123456"); err != nil {
		t.Fatalf("disabled sender should not error: %v", err)
	}
}

func TestNew_DefaultPort(t *testing.T) {
	s := New("smtp.example.com", 587, "u", "p", "no-reply@example.com")
	if !s.Enabled() {
		t.Fatal("expected enabled sender when host set")
	}
	if s.Port != 587 || s.Username != "u" || s.From != "no-reply@example.com" {
		t.Fatalf("sender fields not preserved: %+v", s)
	}
}
