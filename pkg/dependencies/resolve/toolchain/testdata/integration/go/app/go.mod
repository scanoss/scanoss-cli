module example.com/app

go 1.22

require (
	example.com/local v0.0.0
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.12.1
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

replace example.com/local => ./local
