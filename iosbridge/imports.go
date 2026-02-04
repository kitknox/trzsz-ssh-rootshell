/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.
*/

package iosbridge

// This file ensures gomobile bind dependencies are included in go.mod
// The blank import is needed for gobind to work correctly.

import (
	_ "golang.org/x/mobile/bind/seq"
)
