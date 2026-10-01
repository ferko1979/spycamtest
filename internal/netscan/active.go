package netscan

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Hosts returns the usable host IPs within a CIDR (excluding network and
// broadcast addresses for IPv4 /31-or-larger blocks). To keep active scans
// bounded and safe, it refuses blocks larger than maxHosts hosts and
// returns an empty slice in that case.
func Hosts(cidr string, maxHosts int) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil // IPv6 sweeps are intentionally unsupported here
	}

	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	// total addresses = 2^hostBits; guard against huge ranges.
	if hostBits > 16 {
		return nil
	}
	total := 1 << uint(hostBits)

	var out []string
	base := ipToUint32(ip4)
	for i := 0; i < total; i++ {
		addr := base + uint32(i)
		// Skip network/broadcast for blocks with >2 addresses.
		if total > 2 && (i == 0 || i == total-1) {
			continue
		}
		out = append(out, uint32ToIP(addr).String())
		if maxHosts > 0 && len(out) >= maxHosts {
			break
		}
	}
	return out
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// ProbeResult is the outcome of probing a single host.
type ProbeResult struct {
	IP        string
	OpenPorts []int
}

// SweepOptions configures an active TCP-connect sweep.
type SweepOptions struct {
	Ports       []int         // ports to probe per host
	Timeout     time.Duration // per-connection timeout
	Concurrency int           // max concurrent dials
	MaxHosts    int           // cap on hosts enumerated from the CIDR
}

func (o SweepOptions) withDefaults() SweepOptions {
	if len(o.Ports) == 0 {
		o.Ports = CameraPorts
	}
	if o.Timeout <= 0 {
		o.Timeout = 600 * time.Millisecond
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 64
	}
	if o.MaxHosts <= 0 {
		o.MaxHosts = 1024
	}
	return o
}

// Sweep performs an opt-in active TCP-connect probe across the hosts of the
// given CIDR. It only establishes and immediately closes TCP connections
// (no payloads sent), which is a standard reachability check. It honors the
// supplied context for cancellation. Only hosts with at least one open port
// are returned.
//
// This is active (it sends packets) and must be gated behind explicit user
// opt-in by the caller; it is not run as part of passive discovery.
func Sweep(ctx context.Context, cidr string, opts SweepOptions) []ProbeResult {
	opts = opts.withDefaults()
	hosts := Hosts(cidr, opts.MaxHosts)
	if len(hosts) == 0 {
		return nil
	}

	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	var wg sync.WaitGroup

	var mu sync.Mutex
	openByHost := map[string]map[int]bool{}

	worker := func() {
		defer wg.Done()
		d := net.Dialer{Timeout: opts.Timeout}
		for j := range jobs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.ip, strconv.Itoa(j.port)))
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				if openByHost[j.ip] == nil {
					openByHost[j.ip] = map[int]bool{}
				}
				openByHost[j.ip][j.port] = true
				mu.Unlock()
			}
		}
	}

	wg.Add(opts.Concurrency)
	for i := 0; i < opts.Concurrency; i++ {
		go worker()
	}

	go func() {
		defer close(jobs)
		for _, h := range hosts {
			for _, p := range opts.Ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{ip: h, port: p}:
				}
			}
		}
	}()

	wg.Wait()

	var results []ProbeResult
	for ip, ports := range openByHost {
		pl := make([]int, 0, len(ports))
		for p := range ports {
			pl = append(pl, p)
		}
		sort.Ints(pl)
		results = append(results, ProbeResult{IP: ip, OpenPorts: pl})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].IP < results[j].IP })
	return results
}
