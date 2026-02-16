package leshybpf

// Имя мапы не может превышать 15 символов!
const (
	PendingSrcMapName    = "l4_pending_src"
	StatsMapName         = "l4_stats"
	ActiveFlowsMapName   = "l4_active_flows"
	GuardedPortsMapName  = "l4_guarded_port"
	LogsMapName          = "l4_logs"
	RuntimeConfigMapName = "l4_runtime_cfg"
	GuardedPortsMax      = 2048

	ProgramName   = "l4_filter"
	PinnedProgRel = "l4_filter" // имя pinned файла в BPFPinPath
)
