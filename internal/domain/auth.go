package domain

type AllowRequest struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type AllowResponse struct {
	Message string `json:"message"`
	Expires string `json:"expires"`
	IP      string `json:"ip"`
	Port    uint16 `json:"port"`
}

type IpPortKey struct {
	Saddr uint32 // source IP
	Dport uint16 // destination port (network byte order)
	Pad   uint16
}
