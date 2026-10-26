.PHONY: all build build-all test vet test-interop

all: build

# No C runtime or installed SMB libraries are needed by the resulting binary.
build:
	CGO_ENABLED=0 go build -trimpath -o gosmb .

build-all:
	./build.sh

test:
	go test -race ./...

vet:
	go vet ./...

# Optional independent Samba matrix; requires Docker, Python 3, and image access.
test-interop:
	python3 tests/interop/run.py
