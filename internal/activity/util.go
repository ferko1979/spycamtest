package activity

import "strconv"

// parseUint parses a base-10 unsigned integer, tolerating surrounding space.
func parseUint(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}
