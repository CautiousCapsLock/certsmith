package notify

import "github.com/CautiousCapsLock/certsmith/internal/model"

// Alert types: the kinds of message CertSmith can send. The settings page lets each be switched on
// or off per channel (email, webhook).
const (
	CertFailed       = "cert.failed"
	CertExpiring     = "cert.expiring"
	CertIssued       = "cert.issued"
	DeployFailed     = "deploy.failed"
	DeployOK         = "deploy.ok"
	EndpointDown     = "endpoint.down"
	EndpointMismatch = "endpoint.mismatch"
	EndpointChain    = "endpoint.chain"
	EndpointExpiring = "endpoint.expiring"
	AlertCleared     = "alert.cleared"
	UserCreated      = "admin.user_created"
	UserDeleted      = "admin.user_deleted"
	PasswordChanged  = "admin.password_changed"
	SettingsChanged  = "admin.settings_changed"
	UICertRenewed    = "admin.ui_cert_renewed"
)

// Type describes one alert type for the settings page.
type Type struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	Label string `json:"label"`
	// Problem types are on for every channel until the choice is made, as alerts always were.
	// Others (successes, administration) are off until someone ticks them.
	Problem bool `json:"problem"`
}

// Types is every alert type, in the order the settings page lists them.
var Types = []Type{
	{CertFailed, "Certificates", "Issuance or renewal fails", true},
	{CertExpiring, "Certificates", "A certificate is close to expiry", true},
	{CertIssued, "Certificates", "A certificate is issued or renewed", false},
	{DeployFailed, "Devices", "A deployment to a device fails", true},
	{DeployOK, "Devices", "A certificate is deployed to a device", false},
	{EndpointDown, "Devices", "A device cannot be reached", true},
	{EndpointMismatch, "Devices", "A device serves a different certificate than the one deployed", true},
	{EndpointChain, "Devices", "A device sends an incomplete certificate chain", true},
	{EndpointExpiring, "Devices", "A device is serving a certificate that is close to expiry", true},
	{AlertCleared, "Devices", "A problem is resolved", false},
	{UserCreated, "Administration", "A user account is created", false},
	{UserDeleted, "Administration", "A user account is deleted", false},
	{PasswordChanged, "Administration", "A password is changed or reset", false},
	{SettingsChanged, "Administration", "Settings are changed", false},
	{UICertRenewed, "Administration", "The web page's self-signed certificate is regenerated or renewed", false},
}

// Known reports whether id is an alert type.
func Known(id string) bool {
	for _, t := range Types {
		if t.ID == id {
			return true
		}
	}
	return false
}

// Routes returns, for one alert type, whether it goes to email and whether to the webhook.
func Routes(s model.Settings, id string) (email, webhook bool) {
	if r := s.AlertRouting; r != nil {
		has := func(list []string) bool {
			for _, x := range list {
				if x == id {
					return true
				}
			}
			return false
		}
		return has(r.Email), has(r.Webhook)
	}
	for _, t := range Types {
		if t.ID == id {
			on := t.Problem || (s.NotifySuccess && (id == CertIssued || id == DeployOK || id == AlertCleared))
			return on, on
		}
	}
	return false, false
}

// Only returns settings with the channels this alert should not use switched off, so the one send
// routine delivers to exactly the routed channels.
func Only(s model.Settings, email, webhook bool) model.Settings {
	if !email {
		s.SMTP.Enabled = false
	}
	if !webhook {
		s.WebhookURL = ""
	}
	return s
}
