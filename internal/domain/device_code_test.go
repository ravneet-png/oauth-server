package domain

import (
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// User code generation and normalisation
// ----------------------------------------------------------------------------

// TestGenerateUserCodeShape: the display form is "XXXX-XXXX" over the base-20
// alphabet, with the hyphen only in the middle. The shape matters because a user
// reads this off a screen and types it on another device.
func TestGenerateUserCodeShape(t *testing.T) {
	t.Parallel()

	for i := 0; i < 200; i++ {
		code, err := GenerateUserCode()
		if err != nil {
			t.Fatalf("GenerateUserCode: %v", err)
		}
		if len(code) != DeviceUserCodeLength+1 {
			t.Fatalf("code %q has length %d, want %d", code, len(code), DeviceUserCodeLength+1)
		}
		if code[DeviceUserCodeLength/2] != '-' {
			t.Fatalf("code %q has no hyphen after %d characters", code, DeviceUserCodeLength/2)
		}
		for _, r := range code {
			if r == '-' {
				continue
			}
			if !strings.ContainsRune(DeviceUserCodeAlphabet, r) {
				t.Fatalf("code %q contains %q, outside the alphabet", code, r)
			}
		}
	}
}

// TestGenerateUserCodeCoversAlphabet: over many draws every symbol must appear.
// A generator that only ever emitted a subset would still pass a shape check while
// shrinking the effective keyspace; this is the cheap guard against that.
func TestGenerateUserCodeCoversAlphabet(t *testing.T) {
	t.Parallel()

	seen := make(map[rune]bool, len(DeviceUserCodeAlphabet))
	for i := 0; i < 2000 && len(seen) < len(DeviceUserCodeAlphabet); i++ {
		code, err := GenerateUserCode()
		if err != nil {
			t.Fatalf("GenerateUserCode: %v", err)
		}
		for _, r := range code {
			if r != '-' {
				seen[r] = true
			}
		}
	}
	if len(seen) != len(DeviceUserCodeAlphabet) {
		t.Fatalf("only %d of %d alphabet symbols were generated over 2000 draws",
			len(seen), len(DeviceUserCodeAlphabet))
	}
}

// TestGenerateUserCodeUniqueness: a small sample must not collide. This is not a
// proof of entropy, but a generator seeded once or derived from the clock would
// repeat inside a few thousand draws and fail here.
func TestGenerateUserCodeUniqueness(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		code, err := GenerateUserCode()
		if err != nil {
			t.Fatalf("GenerateUserCode: %v", err)
		}
		if seen[code] {
			t.Fatalf("GenerateUserCode repeated %q within 1000 draws", code)
		}
		seen[code] = true
	}
}

// NormalizeUserCode folds the spellings a person might type onto one stored form.
func TestNormalizeUserCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "already canonical", in: "WDJBMJHT", want: "WDJBMJHT"},
		{name: "display hyphen is dropped", in: "WDJB-MJHT", want: "WDJBMJHT"},
		{name: "lower case is folded up", in: "wdjb-mjht", want: "WDJBMJHT"},
		{name: "surrounding and inner spaces are dropped", in: "  wdjb mjht ", want: "WDJBMJHT"},
		{name: "characters outside the alphabet cannot be typed", in: "WDJB-MJHT!", want: "WDJBMJHT"},
		{name: "ambiguous glyphs are stripped rather than mapped", in: "WDJBI0MJHT", want: "WDJBMJHT"},
		{name: "empty stays empty", in: "", want: ""},
		{name: "only punctuation collapses to empty", in: "---- ---", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeUserCode(tt.in); got != tt.want {
				t.Errorf("NormalizeUserCode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeUserCodeRoundTrip: the stored form of a freshly generated code is
// exactly the significant characters, so a code shown to a user is found by the
// lookup that normalises what they type.
func TestNormalizeUserCodeRoundTrip(t *testing.T) {
	t.Parallel()

	for i := 0; i < 200; i++ {
		code, err := GenerateUserCode()
		if err != nil {
			t.Fatalf("GenerateUserCode: %v", err)
		}
		got := NormalizeUserCode(code)
		if len(got) != DeviceUserCodeLength {
			t.Fatalf("NormalizeUserCode(%q) = %q, want %d significant characters",
				code, got, DeviceUserCodeLength)
		}
		if strings.ContainsRune(got, '-') {
			t.Fatalf("NormalizeUserCode(%q) = %q kept the hyphen", code, got)
		}
	}
}

// ----------------------------------------------------------------------------
// Status predicates and lifetime
// ----------------------------------------------------------------------------

func TestDeviceCodeStatusPredicates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status string
		want   string
	}{
		{DeviceStatusPending, "pending"},
		{DeviceStatusApproved, "approved"},
		{DeviceStatusDenied, "denied"},
		{DeviceStatusConsumed, "consumed"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			t.Parallel()
			d := &DeviceCode{Status: tt.status}
			if got := d.IsPending(); got != (tt.want == "pending") {
				t.Errorf("IsPending() = %v for status %q", got, tt.status)
			}
			if got := d.IsApproved(); got != (tt.want == "approved") {
				t.Errorf("IsApproved() = %v for status %q", got, tt.status)
			}
			if got := d.IsDenied(); got != (tt.want == "denied") {
				t.Errorf("IsDenied() = %v for status %q", got, tt.status)
			}
			if got := d.IsConsumed(); got != (tt.want == "consumed") {
				t.Errorf("IsConsumed() = %v for status %q", got, tt.status)
			}
		})
	}
}

// TestDeviceCodeIsExpired: expiry is "not after now", so the boundary instant is
// already dead and an exactly-now redemption cannot slip through.
func TestDeviceCodeIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()
	d := &DeviceCode{ExpiresAt: now.Add(time.Minute)}

	if d.IsExpired(now) {
		t.Error("a code a minute in the future reports expired")
	}
	if !d.IsExpired(now.Add(time.Minute)) {
		t.Error("a code reports live at its exact expiry instant")
	}
	if !d.IsExpired(now.Add(2 * time.Minute)) {
		t.Error("a code reports live after it expired")
	}
}

func TestDeviceCodeOwnedBy(t *testing.T) {
	t.Parallel()

	d := &DeviceCode{ClientID: "client-a"}
	if !d.OwnedBy("client-a") {
		t.Error("code does not recognise its issuing client")
	}
	if d.OwnedBy("client-b") {
		t.Error("code claims to belong to a different client")
	}
}
