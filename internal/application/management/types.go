package management

import "time"

// Settings describes management authorization settings passed by external systems.
type Settings struct {
	Issuer            string
	Audience          string
	JWKSURL           string
	RequiredScope     string
	GuardedPortsRange string
	Iface             string
}

// StoredSettings represents settings persisted by the application.
type StoredSettings struct {
	Settings

	UpdatedAt time.Time
}
