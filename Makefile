.PHONY: build run test testv

build:
	@echo "Size before build:"; \
	ls -la examples |grep examples; \
	ls -lh examples |grep examples; \
	echo "\nSize after build:"; \
	cd examples; \
	go build --ldflags "-s -w" -o examples; \
	ls -la |grep examples; \
	ls -lh |grep examples; \
	cd ..

run:
	@cd examples; \
	go run main.go; \
	cd ..

test:
	@go test -timeout 30s ./...

testv:
	@go test -timeout 30s -v ./...

testcover:
	@go test -coverprofile=coverage.out && go tool cover -html=coverage.out -o coverage.html
