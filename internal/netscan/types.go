// Package netscan provides local-network device discovery helpers: MAC/OUI
// vendor lookup, reverse-DNS hostname resolution, a heuristic for flagging
// likely camera devices, and an opt-in active (TCP connect) subnet sweep.
//
// Everything here operates on the local network the agent runs on. It is
// intended for use on networks you own or are authorized to scan.
package netscan

// Device is a single host observed on the local network.
type Device struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname,omitempty"`

	// Enrichment (populated by Enrich / classification).
	Vendor       string `json:"vendor,omitempty"`
	LikelyCamera bool   `json:"likely_camera,omitempty"`
	// CameraReasons explains why the device was flagged (vendor match,
	// open RTSP port, etc.) so results stay auditable rather than opaque.
	CameraReasons []string `json:"camera_reasons,omitempty"`
	// OpenPorts lists ports that answered during an active probe (if run).
	OpenPorts []int `json:"open_ports,omitempty"`
}

// Network describes one local network interface the agent is attached to.
type Network struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	CIDR      string `json:"cidr"`
	MAC       string `json:"mac,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
}
