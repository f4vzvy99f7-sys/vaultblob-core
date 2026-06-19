module github.com/user/vaultblob-go

go 1.26

require (
	github.com/ebitengine/purego v0.10.1
	github.com/user/vaultblob-go-bin/darwin_amd64 v0.1.0
	github.com/user/vaultblob-go-bin/darwin_arm64 v0.1.0
	github.com/user/vaultblob-go-bin/linux_amd64 v0.1.0
	github.com/user/vaultblob-go-bin/linux_arm64 v0.1.0
	github.com/user/vaultblob-go-bin/windows_amd64 v0.1.0
)

replace (
	github.com/user/vaultblob-go-bin/darwin_amd64 => ../bin/darwin_amd64
	github.com/user/vaultblob-go-bin/darwin_arm64 => ../bin/darwin_arm64
	github.com/user/vaultblob-go-bin/linux_amd64 => ../bin/linux_amd64
	github.com/user/vaultblob-go-bin/linux_arm64 => ../bin/linux_arm64
	github.com/user/vaultblob-go-bin/windows_amd64 => ../bin/windows_amd64
)
