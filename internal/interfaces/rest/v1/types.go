package v1

// AllowRequest — JSON контракт REST API v1.
type AllowRequest struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// AllowResponse — JSON контракт REST API v1.
type AllowResponse struct {
	Message string `json:"message"`
	Expires string `json:"expires"`
	IP      string `json:"ip"`
	Port    uint16 `json:"port"`
}

// StatsResponse — JSON контракт REST API v1 для /stats.
// (типизированная версия вместо map[string]interface{}).
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
