package golang

// Mass-assignment defense: copy only allow-listed fields from client input.

// AllowFields returns a new map holding only the allowed keys that are present
// in src. src is never modified; a nil src yields an empty, non-nil map.
// Values are copied shallowly (nested maps and slices are shared with src).
func AllowFields(src map[string]any, allowed ...string) map[string]any {
	out := make(map[string]any, len(allowed))
	for _, key := range allowed {
		if val, ok := src[key]; ok {
			out[key] = val
		}
	}
	return out
}
