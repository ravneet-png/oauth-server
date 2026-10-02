// Package migrations embeds the SQL migration files so the server binary is
// self-contained.
//
// The embed directive can only reach files in this directory or below, which is
// why this is a package rather than a variable in internal/storage: the SQL
// lives at the repository root under migrations/, and a //go:embed in
// internal/storage cannot reach a parent directory. Keeping the embed next to
// the SQL also means there is exactly one place that knows the layout, and
// adding a migration cannot require editing a second file.
package migrations

import "embed"

// FS holds every .sql file in this directory, up and down.
//
// Embedding both directions matters as much as embedding up: a down file that
// is missing from the binary turns `migrate down` into a runtime failure in the
// one situation it is needed, which is a broken release being rolled back.
//
//go:embed *.sql
var FS embed.FS
