package v1

// AllowRequest — JSON контракт REST API v1 для POST /allow.
type AllowRequest struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// AllowResponse — JSON контракт REST API v1 ответ на POST /allow.
type AllowResponse struct {
	Message string `json:"message"`
	Expires string `json:"expires"` // RFC3339 (UTC)
	IP      string `json:"ip"`
	Port    uint16 `json:"port"`
}

// StatsResponse — JSON контракт REST API v1 ответ на GET /stats.
type StatsResponse struct {
	Allowed                uint64 `json:"allowed"`
	Dropped                uint64 `json:"dropped"`
	SYNAllowed             uint64 `json:"syn_allowed"`
	SYNDropped             uint64 `json:"syn_dropped"`
	ActiveFlowHits         uint64 `json:"active_flow_hits"`
	PendingPromotions      uint64 `json:"pending_promotions"`
	PendingExpiredCleanups uint64 `json:"pending_expired_cleanups"`
	IPPortAuthHits         uint64 `json:"ip_port_auth_hits"`
	NonGuardedPortAllowed  uint64 `json:"non_guarded_port_allowed"`
	GuardedPortDropped     uint64 `json:"guarded_port_dropped"`

	AllowRatePercent float64 `json:"allow_rate_percent"`
	DropRatePercent  float64 `json:"drop_rate_percent"`
}

// UpsertManagementSettingsRequest is a JSON contract for POST /management/settings.
type UpsertManagementSettingsRequest struct {
	Issuer             string `json:"issuer"`
	Audience           string `json:"audience"`
	JWKSURL            string `json:"jwks_url"`
	RequiredScope      string `json:"required_scope"`
	GuardedPortsRange  string `json:"guarded_ports_range"`
	Iface              string `json:"iface"`
	HandshakeWindowSec int    `json:"handshake_window_sec"`
}

// UpsertManagementSettingsResponse is a JSON contract for POST /management/settings response.
type UpsertManagementSettingsResponse struct {
	Message            string `json:"message"`
	AuthConfigured     bool   `json:"auth_configured"`
	RuntimeAttached    bool   `json:"runtime_attached"`
	RuntimeIface       string `json:"runtime_iface"`
	Issuer             string `json:"issuer"`
	Audience           string `json:"audience"`
	JWKSURL            string `json:"jwks_url"`
	RequiredScope      string `json:"required_scope"`
	GuardedPortsRange  string `json:"guarded_ports_range"`
	Iface              string `json:"iface"`
	HandshakeWindowSec int    `json:"handshake_window_sec"`
	UpdatedAt          string `json:"updated_at"` // RFC3339 (UTC)
}

// GetManagementSettingsResponse is a JSON contract for GET /management/settings response.
type GetManagementSettingsResponse struct {
	AuthConfigured     bool   `json:"auth_configured"`
	RuntimeAttached    bool   `json:"runtime_attached"`
	RuntimeIface       string `json:"runtime_iface"`
	Issuer             string `json:"issuer"`
	Audience           string `json:"audience"`
	JWKSURL            string `json:"jwks_url"`
	RequiredScope      string `json:"required_scope"`
	GuardedPortsRange  string `json:"guarded_ports_range"`
	Iface              string `json:"iface"`
	HandshakeWindowSec int    `json:"handshake_window_sec"`
	UpdatedAt          string `json:"updated_at"` // RFC3339 (UTC)
}

// BlockManagementResponse is a JSON contract for POST /management/block response.
type BlockManagementResponse struct {
	Message               string `json:"message"`
	PendingEntriesRemoved uint64 `json:"pending_entries_removed"`
	ActiveFlowsRemoved    uint64 `json:"active_flows_removed"`
	RuntimeAttached       bool   `json:"runtime_attached"`
	RuntimeIface          string `json:"runtime_iface"`
}
