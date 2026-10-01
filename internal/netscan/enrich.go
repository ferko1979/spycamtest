package netscan

import (
	"context"
	"net"
	"time"
)

// Resolver abstracts reverse-DNS lookups so tests can stub them.
type Resolver interface {
	LookupAddr(ip string) ([]string, error)
}

type netResolver struct{ timeout time.Duration }

func (r netResolver) LookupAddr(ip string) ([]string, error) {
	rr := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return rr.LookupAddr(ctx, ip)
}

// Enrich fills in vendor, hostname (reverse DNS), and a camera
// classification for each device. openPorts maps IP -> open ports observed
// by an optional active Sweep; pass nil if no active probe was run (vendor
// and hostname heuristics still apply). The input slice is modified in
// place and returned for convenience.
func Enrich(devices []Device, openPorts map[string][]int, res Resolver) []Device {
	if res == nil {
		res = netResolver{timeout: 800 * time.Millisecond}
	}
	for i := range devices {
		d := &devices[i]
		if d.Vendor == "" {
			d.Vendor = LookupVendor(d.MAC)
		}
		if d.Hostname == "" {
			if names, err := res.LookupAddr(d.IP); err == nil && len(names) > 0 {
				d.Hostname = trimTrailingDot(names[0])
			}
		}

		ports := openPorts[d.IP]
		if len(ports) > 0 {
			d.OpenPorts = ports
		}

		flag, reasons := classifyCamera(d.Vendor, ports)
		if hostnameSuggestsCamera(d.Hostname) {
			reasons = append(reasons, "hostname looks camera-related")
			flag = true
		}
		d.LikelyCamera = flag
		d.CameraReasons = reasons
	}
	return devices
}

// Cameras returns only the devices flagged as likely cameras.
func Cameras(devices []Device) []Device {
	var out []Device
	for _, d := range devices {
		if d.LikelyCamera {
			out = append(out, d)
		}
	}
	return out
}

func trimTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
