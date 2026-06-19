//go:build tools

package vaultblob

import (
	_ "github.com/user/vaultblob-go-bin/darwin_amd64"
	_ "github.com/user/vaultblob-go-bin/darwin_arm64"
	_ "github.com/user/vaultblob-go-bin/linux_amd64"
	_ "github.com/user/vaultblob-go-bin/linux_arm64"
	_ "github.com/user/vaultblob-go-bin/windows_amd64"
)
