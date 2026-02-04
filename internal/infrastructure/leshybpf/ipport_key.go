package leshybpf

// IpPortKey — ключ для pending map (eBPF).
type IpPortKey struct {
	Saddr uint32 // source IP
	Dport uint16 // destination port (network byte order)
	Pad   uint16
}
