package management

import "time"

// Settings describes management token settings passed by external systems.
type Settings struct {
	Token             string
	GuardedPortsRange string
	Iface             string
}

// StoredSettings represents settings persisted by the application.
type StoredSettings struct {
	Settings

	UpdatedAt time.Time
}
