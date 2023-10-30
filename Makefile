all:
	protoc --go_out=. --go-grpc_out=. ./pkg/proto/service.proto
	go build -ldflags="-extldflags=-static" ./cmd/rstrace.go

docker:
	docker build . -t dd-cws-wrapper
