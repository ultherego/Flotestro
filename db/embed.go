// Package db osadza migracje w binarce control plane.
// Katalog migrations pozostaje jedynym zrodlem prawdy dla schematu.
package db

import "embed"

//go:embed migrations/*.sql
var Migrations embed.FS
