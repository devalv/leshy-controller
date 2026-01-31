package leshybpf

const (
	PendingSrcMapName   = "l4_pending_src"
	StatsMapName        = "l4_stats"
	ActiveFlowsMapName  = "l4_active_flows"
	GuardedPortsMapName = "l4_guarded_ports"
	LogsMapName         = "l4_logs"

	ProgramName   = "l4_filter"
	PinnedProgRel = "l4_filter" // имя pinned файла в BPFPinPath
)
