package filter

// Counters — “сырые” счетчики из BPF.
type Counters struct {
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
}

// Stats — то, что отдаём наружу (usecase результат).
type Stats struct {
	Counters

	AllowRatePercent float64 `json:"allow_rate_percent"`
	DropRatePercent  float64 `json:"drop_rate_percent"`
}
