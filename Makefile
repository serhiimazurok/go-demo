.PHONY: build
build:
	go build -v ./cmd/apiserver

.PHONY: test
test:
	go test -v -race -timeout 30s ./...

.PHONY: migrate
migrate:
	migrate -path migrations -database "postgres://localhost/demo?sslmode=disable&user=user&password=password" up

.DEFAULT_GOAL := build