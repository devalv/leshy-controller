package filter

// FlushResult describes how many runtime allow-related entries were removed.
type FlushResult struct {
	PendingEntriesRemoved uint64 `json:"pending_entries_removed"`
	ActiveFlowsRemoved    uint64 `json:"active_flows_removed"`
}
