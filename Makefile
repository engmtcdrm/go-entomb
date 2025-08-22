.PHONY: build run test testv

build:
	echo "Size before build:"; ls -la |grep mellon; ls -lh |grep mellon; echo "\n\nSize after build:"; go build --ldflags "-s -w"; strip mellon; ls -la |grep mellon; ls -lh |grep mellon

run:
	go run examples/simple/main.go

test:
	go test -timeout 30s ./...

testv:
	go test -timeout 30s -v ./...
