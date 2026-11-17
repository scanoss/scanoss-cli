module example.com/app

go 1.22

require example.com/a v0.0.0

require (
	example.com/b v0.0.0 // indirect
	example.com/c v0.0.0 // indirect
)

replace (
	example.com/a => ./a
	example.com/b => ./b
	example.com/c => ./c
)
