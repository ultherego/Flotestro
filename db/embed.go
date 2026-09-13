// Package db embeds the migrations in the control plane binary.
// The migrations directory remains the only source of truth for the schema.
package db

import "embed"

//go:embed migrations/*.sql
var Migrations embed.FS
