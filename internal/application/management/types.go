package management

import "time"

// RuntimeStatus describes runtime state of dynamic network controls.
type RuntimeStatus struct {
	Attached bool
	Iface    string
}

// Settings describes management authorization settings passed by external systems.
type Settings struct {
	Issuer             string
	Audience           string
	JWKSURL            string
	RequiredScope      string
	GuardedPortsRange  string
	Iface              string
	HandshakeWindowSec int
}

// StoredSettings represents settings persisted by the application.
type StoredSettings struct {
	Settings

	UpdatedAt time.Time
	Runtime   RuntimeStatus
}
