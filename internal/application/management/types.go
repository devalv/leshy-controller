package management

import "time"

// RuntimeStatus описывает состояние runtime для того, к чему будет применяться фильтрация.
type RuntimeStatus struct {
	Attached bool
	Iface    string
}

// Settings описывает настройки присылаемые внешней системой при интеграции.
type Settings struct {
	Issuer             string
	Audience           string
	JWKSURL            string
	RequiredScope      string
	GuardedPortsRange  string
	Iface              string
	HandshakeWindowSec int
}

// StoredSettings описывает настройки хранящиеся в БД.
type StoredSettings struct {
	Settings

	UpdatedAt time.Time
	Runtime   RuntimeStatus
}
