module github.com/go-i2p/go-noise

go 1.26.3

require (
	github.com/go-i2p/common v0.1.60000-0.20260612012818-ffa84716e922
	github.com/go-i2p/crypto v0.1.60000-0.20260612012729-bcf561943886
	github.com/go-i2p/logger v0.1.60000-0.20260612012503-bec4044a2b0d
	github.com/go-i2p/noise v0.1.6
	github.com/go-i2p/path v0.1.6
	github.com/go-i2p/pool v0.1.6
	github.com/samber/oops v1.22.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.53.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/go-i2p/elgamal v0.1.59999 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	go.step.sm/crypto v0.84.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

//replace github.com/go-i2p/crypto => ../crypto

//replace github.com/go-i2p/noise => ../noise

//replace github.com/go-i2p/common => ../common
