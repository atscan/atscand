package pds

import "time"

type ServerDescription struct {
	AvailableUserDomains      []string `json:"availableUserDomains"`
	InviteCodeRequired        bool     `json:"inviteCodeRequired"`
	PhoneVerificationRequired bool     `json:"phoneVerificationRequired"`
	Links                     *Links   `json:"links,omitempty"`
	Contact                   *Contact `json:"contact,omitempty"`
	DID                       string   `json:"did"`
}

type Links struct {
	PrivacyPolicy  string `json:"privacyPolicy,omitempty"`
	TermsOfService string `json:"termsOfService,omitempty"`
}

type Contact struct {
	Email string `json:"email,omitempty"`
}

type PDSStatus struct {
	PDSID        int64 // NEW: PDS ID
	Endpoint     string
	Available    bool
	ResponseTime time.Duration
	LastChecked  time.Time
	ErrorMessage string
	Description  *ServerDescription
	DIDs         []string
}
