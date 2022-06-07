test:
	go test -v -timeout 30s \
	github.com/mfbarnable/auth_middleware/pkg/auth/password \
	github.com/mfbarnable/auth_middleware/pkg/auth/pki \
	-count=1 

build:
	go build github.com/mfbarnable/auth_middleware/pkg/auth/password
# go build -tags=jsoniter .
