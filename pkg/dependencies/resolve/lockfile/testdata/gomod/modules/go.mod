module example.com/app

go 1.23.0

toolchain go1.24.4

godebug default=go1.21

require github.com/spf13/cobra v1.10.2

require (
	github.com/google/go-cmp v0.7.0
	gopkg.in/yaml.v3 v3.0.1
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/russross/blackfriday v1.6.0
	github.com/inconshreveable/mousetrap v1.1.0 // indirect; needed on windows
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/tools v0.36.0
)

exclude golang.org/x/net v0.1.0

retract (
	v1.0.1 // published by mistake
	[v1.1.0, v1.1.5]
)

tool golang.org/x/tools/cmd/stringer
