package leshybpf

// HostToNetworkPort преобразует формат порта HOST -> NETWORK BYTE.
func HostToNetworkPort(port uint16) uint16 {
	return hostToNetworkPort(port)
}

func hostToNetworkPort(port uint16) uint16 {
	return (port >> 8) | (port << 8) //nolint:mnd
}

func networkToHostPort(port uint16) uint16 {
	return (port >> 8) | (port << 8) //nolint:mnd
}
