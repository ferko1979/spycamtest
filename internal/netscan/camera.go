package netscan

import "strings"

// cameraVendors is the set of vendor names (as returned by LookupVendor)
// that predominantly make IP cameras / NVRs / video doorbells. A vendor
// match alone is a weak signal, so it is reported with a reason rather than
// treated as proof.
var cameraVendors = map[string]bool{
	"Hikvision":           true,
	"Dahua":               true,
	"Axis Communications": true,
	"Reolink":             true,
	"Amcrest":             true,
	"Wyze":                true,
	"Nest (Google)":       true,
	"Netgear (Arlo)":      true,
	"Foscam":              true,
	"Ring (Amazon)":       true,
}

// CameraPorts are TCP ports commonly exposed by IP cameras and NVRs:
// RTSP (554/8554), ONVIF/HTTP (80/8000), and vendor control ports
// (Dahua 37777, some NVRs 34567).
var CameraPorts = []int{554, 8554, 80, 8000, 37777, 34567}

// cameraPortMeaning labels a port for human-readable reasons.
var cameraPortMeaning = map[int]string{
	554:   "RTSP (554)",
	8554:  "RTSP-alt (8554)",
	80:    "HTTP (80)",
	8000:  "camera HTTP (8000)",
	37777: "Dahua control (37777)",
	34567: "NVR control (34567)",
}

// classifyCamera decides whether a device looks like a camera, using its
// vendor and any ports found open during an active probe. It returns the
// decision plus the reasons behind it. A strong signal (RTSP open, or a
// camera vendor together with any camera HTTP/control port) flags the
// device; a camera vendor alone is reported as a reason but, on its own,
// is treated as "possible" via the returned reasons without a hard flag.
func classifyCamera(vendor string, openPorts []int) (bool, []string) {
	var reasons []string
	open := make(map[int]bool, len(openPorts))
	for _, p := range openPorts {
		open[p] = true
	}

	vendorIsCamera := cameraVendors[vendor]
	if vendorIsCamera {
		reasons = append(reasons, "vendor "+vendor+" commonly makes cameras")
	}

	rtsp := open[554] || open[8554]
	controlOpen := open[37777] || open[34567] || open[8000]
	httpOpen := open[80]

	for _, p := range CameraPorts {
		if open[p] {
			if m := cameraPortMeaning[p]; m != "" {
				reasons = append(reasons, "open "+m)
			}
		}
	}

	// Decision:
	//  - RTSP open is a strong, near-definitive camera signal.
	//  - A camera vendor + any camera control/HTTP port is strong.
	//  - Otherwise leave unflagged (reasons may still hint "possible").
	flag := rtsp || (vendorIsCamera && (controlOpen || httpOpen))
	return flag, reasons
}

// hostnameSuggestsCamera reports whether a hostname contains tokens often
// used by camera devices. Used as an additional soft reason.
func hostnameSuggestsCamera(hostname string) bool {
	h := strings.ToLower(hostname)
	for _, tok := range []string{"cam", "ipcam", "camera", "nvr", "dvr", "doorbell", "reolink", "hikvision", "dahua", "wyze", "arlo"} {
		if strings.Contains(h, tok) {
			return true
		}
	}
	return false
}
