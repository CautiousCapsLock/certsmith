// Package notify delivers alerts by SMTP email and/or a JSON webhook.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

type Message struct {
	Subject string
	Body    string
}

// Send delivers to every configured channel. Unconfigured channels are skipped;
// the error joins failures from the channels that were attempted.
func Send(ctx context.Context, s model.Settings, smtpPassword string, m Message) error {
	var errs []error
	if s.SMTP.Enabled {
		if err := sendMail(s.SMTP, smtpPassword, m); err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		}
	}
	if s.WebhookURL != "" {
		if err := sendWebhook(ctx, s.WebhookURL, m); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}
	return errors.Join(errs...)
}

func Configured(s model.Settings) bool { return s.SMTP.Enabled || s.WebhookURL != "" }

func sendWebhook(ctx context.Context, url string, m Message) error {
	// "text" works for Slack/Mattermost/Teams-style incoming webhooks.
	body, _ := json.Marshal(map[string]string{"text": m.Subject + "\n" + m.Body, "subject": m.Subject, "body": m.Body})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendMail(c model.SMTP, password string, m Message) error {
	if c.Host == "" || c.From == "" || len(c.To) == 0 {
		return errors.New("SMTP host, from and recipients are required")
	}
	addr := net.JoinHostPort(c.Host, fmt.Sprint(c.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	var err error
	if c.Security == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if c.Security == "starttls" {
		if err := cl.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, password, c.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return err
	}
	for _, to := range c.To {
		if err := cl.Rcpt(to); err != nil {
			return fmt.Errorf("recipient %s: %w", to, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		c.From, strings.Join(c.To, ", "), mime.QEncoding.Encode("utf-8", m.Subject),
		time.Now().Format(time.RFC1123Z), strings.ReplaceAll(m.Body, "\n", "\r\n"))
	if _, err := w.Write(msg.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}
