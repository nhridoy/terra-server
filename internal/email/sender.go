package email

import (
	"fmt"
	"log/slog"
	"net/smtp"
)

type Sender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

func New(host string, port int, username, password, from string) *Sender {
	return &Sender{Host: host, Port: port, Username: username, Password: password, From: from}
}

func (s *Sender) Enabled() bool {
	return s.Host != ""
}

func (s *Sender) SendOtp(to, code string) error {
	subject := "Your TermVault verification code"
	html := fmt.Sprintf("<p>Your TermVault verification code is:</p><p style=\"font-size:24px;font-weight:bold\">%s</p><p>It expires in 15 minutes.</p>", code)

	if !s.Enabled() {
		slog.Info("verification otp", "email", to, "code", code)
		return nil
	}

	msg := []byte("From: " + s.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		html)

	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}
	if err := smtp.SendMail(addr, auth, s.From, []string{to}, msg); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}
	return nil
}
