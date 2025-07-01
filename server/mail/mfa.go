package mail

import (
	"bytes"
	"github.com/notawar/mobius/v4/server/mobius"
	"html/template"
	"time"

	"github.com/notawar/mobius set/v4/server"
)

// MFAMailer is used to build an email template for the MFA email.
type MFAMailer struct {
	FullName     string
	Token        string
	BaseURL      template.URL
	AssetURL     template.URL
	CurrentYear  int
	TTLInMinutes float64 // due to rounding below, will always be a whole number
}

func (i *MFAMailer) Message() ([]byte, error) {
	i.CurrentYear = time.Now().Year()
	i.TTLInMinutes = mobius.MFALinkTTL.Truncate(time.Minute).Minutes() // better to show a whole, rounded-down number
	t, err := server.GetTemplate("server/mail/templates/mfa.html", "email_template")
	if err != nil {
		return nil, err
	}

	var msg bytes.Buffer
	if err = t.Execute(&msg, i); err != nil {
		return nil, err
	}
	return msg.Bytes(), nil
}
