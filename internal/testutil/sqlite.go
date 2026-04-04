// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package testutil

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// sqliteOpen returns a pure-Go SQLite GORM dialector for the given file path.
// Using github.com/glebarez/sqlite avoids CGO so tests run in any environment.
func sqliteOpen(path string) gorm.Dialector {
	return sqlite.Open(path)
}
