package filter

// FlushResult описывает, сколько записей, связанных с разрешениями времени выполнения, было удалено.
type FlushResult struct {
	PendingEntriesRemoved uint64 `json:"pending_entries_removed"`
	ActiveFlowsRemoved    uint64 `json:"active_flows_removed"`
}
