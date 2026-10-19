module example.com/app

go 1.22

require (
	example.com/lib v0.0.0-00010101000000-000000000000
	github.com/old/name v1.4.0
	github.com/pinned/mod v1.0.0
	github.com/unpinned/mod v2.0.0+incompatible // indirect
	"github.com/quoted/mod" v0.3.0
)

replace example.com/lib => ../lib

replace (
	github.com/old/name => github.com/new/name v1.5.0
	github.com/pinned/mod v1.0.0 => github.com/pinned/mod v1.0.1
	github.com/unpinned/mod v1.0.0 => github.com/fork/mod v1.0.0
)
