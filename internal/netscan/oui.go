package netscan

import "strings"

// ouiVendors maps a 24-bit OUI prefix (uppercase hex, no separators) to a
// vendor name. This is a curated subset of common consumer/network and
// camera vendors — not the full IEEE registry — so LookupVendor returns ""
// for anything not listed rather than guessing. Extend as needed.
var ouiVendors = map[string]string{
	// --- Camera / NVR / surveillance vendors (see cameraVendors too) ---
	"C0566C": "Hikvision",
	"4CBD8F": "Hikvision",
	"BCAD28": "Hikvision",
	"44A642": "Hikvision",
	"C074AD": "Dahua",
	"3CEF8C": "Dahua",
	"90A6F9": "Dahua",
	"00408C": "Axis Communications",
	"ACCC8E": "Axis Communications",
	"B8A44F": "Axis Communications",
	"EC7140": "Reolink",
	"8C1A6A": "Amcrest",
	"2CAA8E": "Wyze",
	"7C78B2": "Wyze",
	"18B430": "Nest (Google)",
	"641666": "Nest (Google)",
	"B07FB9": "Netgear (Arlo)",
	"002713": "Foscam",
	"001A9F": "Foscam",
	"F0B429": "Ring (Amazon)",
	"74C246": "Amazon",
	"FCA667": "Amazon",
	"44650D": "Amazon",

	// --- Networking gear ---
	"FCECDA": "Ubiquiti",
	"788A20": "Ubiquiti",
	"002722": "Ubiquiti",
	"B4FBE4": "Ubiquiti",
	"001018": "Broadcom",
	"000C29": "VMware",
	"005056": "VMware",
	"0050F2": "Microsoft",
	"001D0F": "TP-Link",
	"50C7BF": "TP-Link",
	"14CC20": "TP-Link",
	"B0487A": "TP-Link",
	"001560": "Cisco",
	"00000C": "Cisco",
	"F4F5E8": "Google",
	"D4F547": "Google",

	// --- Common consumer device makers ---
	"3C0754": "Apple",
	"F0DBE2": "Apple",
	"A4B197": "Apple",
	"ACBC32": "Apple",
	"DCA632": "Raspberry Pi",
	"B827EB": "Raspberry Pi",
	"E45F01": "Raspberry Pi",
	"001132": "Synology",
	"0011D8": "Asus",
	"2C56DC": "Asus",
	"507B9D": "Samsung",
	"F0728C": "Samsung",
	"8CE748": "Intel",
	"A0C589": "Intel",
}

// normalizeOUI extracts the uppercase 6-hex-digit OUI prefix from a MAC
// address in any common form ("aa:bb:cc:dd:ee:ff", "aa-bb-...", "aabb...").
// Returns "" if fewer than 6 hex digits are present.
func normalizeOUI(mac string) string {
	var b strings.Builder
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r - 32) // to uppercase
		case r >= 'A' && r <= 'F':
			b.WriteRune(r)
		}
		if b.Len() == 6 {
			return b.String()
		}
	}
	if b.Len() == 6 {
		return b.String()
	}
	return ""
}

// LookupVendor returns the vendor name for a MAC address, or "" if the OUI
// prefix is not in the curated table.
func LookupVendor(mac string) string {
	oui := normalizeOUI(mac)
	if oui == "" {
		return ""
	}
	return ouiVendors[oui]
}
