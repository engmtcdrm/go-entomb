.PHONY: build run test testv

build:
	@echo "Size before build:"; \
	ls -la examples/simple |grep simple; \
	ls -lh examples/simple |grep simple; \
	echo "\nSize after build:"; \
	cd examples/simple; \
	go build --ldflags "-s -w" -o simple; \
	ls -la |grep simple; \
	ls -lh |grep simple; \
	cd ..

run:
	@cd examples; \
	go run main.go; \
	cd ..

test:
	@go test -timeout 30s ./...

testv:
	@go test -timeout 30s -v ./...
