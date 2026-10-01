package netscan

import (
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeOUI(t *testing.T) {
	cases := map[string]string{
		"c0:56:6c:11:22:33": "C0566C",
		"C0-56-6C-11-22-33": "C0566C",
		"c0566c112233":      "C0566C",
		"C0:56":             "", // too short
		"":                  "",
	}
	for in, want := range cases {
		if got := normalizeOUI(in); got != want {
			t.Errorf("normalizeOUI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLookupVendor(t *testing.T) {
	if got := LookupVendor("c0:56:6c:aa:bb:cc"); got != "Hikvision" {
		t.Errorf("Hikvision OUI lookup = %q", got)
	}
	if got := LookupVendor("de:ad:be:ef:00:01"); got != "" {
		t.Errorf("unknown OUI should be empty, got %q", got)
	}
}

func TestClassifyCamera(t *testing.T) {
	// RTSP open -> flagged regardless of vendor.
	if flag, _ := classifyCamera("", []int{554}); !flag {
		t.Error("RTSP open should flag camera")
	}
	// Camera vendor + control port -> flagged.
	if flag, _ := classifyCamera("Dahua", []int{37777}); !flag {
		t.Error("Dahua + control port should flag camera")
	}
	// Camera vendor alone -> not hard-flagged, but reason present.
	flag, reasons := classifyCamera("Wyze", nil)
	if flag {
		t.Error("vendor alone should not hard-flag")
	}
	if len(reasons) == 0 {
		t.Error("vendor match should produce a reason")
	}
	// Non-camera, no ports -> not flagged.
	if flag, _ := classifyCamera("Apple", nil); flag {
		t.Error("Apple with no ports should not flag")
	}
}

func TestHosts(t *testing.T) {
	got := Hosts("192.168.1.0/30", 0)
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Hosts(/30) = %v, want %v", got, want)
	}
	// Oversized block is refused.
	if h := Hosts("10.0.0.0/8", 0); h != nil {
		t.Errorf("huge block should return nil, got %d hosts", len(h))
	}
	// MaxHosts cap respected.
	if h := Hosts("192.168.0.0/24", 5); len(h) != 5 {
		t.Errorf("maxHosts cap = %d, want 5", len(h))
	}
}

type stubResolver struct {
	m map[string][]string
}

func (s stubResolver) LookupAddr(ip string) ([]string, error) {
	if v, ok := s.m[ip]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}

func TestEnrich(t *testing.T) {
	devs := []Device{
		{IP: "192.168.1.10", MAC: "c0:56:6c:aa:bb:cc"}, // Hikvision
		{IP: "192.168.1.20", MAC: "3c:07:54:aa:bb:cc"}, // Apple
	}
	ports := map[string][]int{
		"192.168.1.10": {80, 554},
	}
	res := stubResolver{m: map[string][]string{
		"192.168.1.20": {"johns-laptop.local."},
	}}
	out := Enrich(devs, ports, res)

	if out[0].Vendor != "Hikvision" || !out[0].LikelyCamera {
		t.Errorf("device 0 should be Hikvision camera: %+v", out[0])
	}
	if out[0].Hostname != "" {
		t.Errorf("device 0 hostname should be empty (resolver miss), got %q", out[0].Hostname)
	}
	if out[1].Vendor != "Apple" || out[1].LikelyCamera {
		t.Errorf("device 1 should be non-camera Apple: %+v", out[1])
	}
	if out[1].Hostname != "johns-laptop.local" {
		t.Errorf("device 1 hostname trim failed: %q", out[1].Hostname)
	}

	cams := Cameras(out)
	if len(cams) != 1 || cams[0].IP != "192.168.1.10" {
		t.Errorf("Cameras() = %+v", cams)
	}
}
