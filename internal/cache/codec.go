package cache

// JSON helpers, kept here so the cache package's value encoding is defined in one
// place. The repository already depends on goccy/go-json, so this is the same codec
// rather than a second one.

import "github.com/goccy/go-json"

func marshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// The values marshalled here are plain structs of strings and slices, so a
		// failure means the struct gained a field JSON cannot represent — a
		// programming error, not a runtime condition. Empty is the safest result:
		// the state reads back as absent rather than as something attacker-influenced.
		return ""
	}
	return string(b)
}

func unmarshalJSON(s string, v any) error {
	return json.Unmarshal([]byte(s), v)
}
