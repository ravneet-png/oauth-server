package domain

// A single MFA recovery code. Each is individually hashed and individually
// consumable so that concurrent use cannot burn two grants from one code.

import "time"

// MFABackupCode is one recovery code belonging to a user.
//
// This exists as a table rather than a TEXT[] on the user row for three
// separate reasons, each of which is a correctness problem rather than a
// preference:
//
//  1. Consuming one code from an array requires read-modify-write. Two
//     concurrent submissions both read the same array, both rewrite it, and one
//     code authorises two grants. A row per code makes the consume a single
//     conditional UPDATE, so the database resolves the race.
//
//  2. With an array there is no record of which code was used, so the audit
//     trail cannot answer "was this the code the attacker burned".
//
//  3. Per-code rate limiting is impossible with an array: the limiter needs a
//     stable identifier for each code, and an array element does not have one.
//
// Codes are 128 bits of CSPRNG output, so they are hashed with SHA-256 rather
// than a password KDF. A KDF costs ~100ms of CPU per attempt and buys nothing
// against a value with no guessing resistance to protect. This is the opposite
// of the password decision, and for the same reason: the KDF is there to make
// enumeration expensive, and there is nothing to enumerate.
type MFABackupCode struct {
	// CodeHash, not the code. A plaintext code in the table would make a
	// database read equivalent to a full MFA bypass.
	CodeHash string
	UserID   string

	// UsedAt is the single-use marker. NULL means unused. There is no Used bool,
	// for the same reason as AuthCode.UsedAt.
	UsedAt *time.Time

	CreatedAt time.Time
}

// IsUsed reports whether the code has been consumed.
func (c *MFABackupCode) IsUsed() bool {
	return c.UsedAt != nil
}

// IsUsable reports whether the code may still be redeemed.
//
// For pre-flight and display only. The authoritative consume is the conditional
// UPDATE guarded on used_at IS NULL, because a check-then-act pair would
// reintroduce the race this table exists to remove.
func (c *MFABackupCode) IsUsable() bool {
	return c.UsedAt == nil
}

// BelongsTo reports whether this code was issued to userID. Checked before
// consumption: a backup code presented against the wrong account must fail
// without being burned, or a code becomes a denial-of-service target where an
// attacker burns other people's codes by guessing their account.
func (c *MFABackupCode) BelongsTo(userID string) bool {
	return c.UserID == userID
}
