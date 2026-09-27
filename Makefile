APP     := homeproxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build clean test install

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(APP) ./cmd/homeproxy

clean:
	rm -rf bin/ dist/

test:
	go test ./

install: build
	install -Dm755 bin/$(APP) /usr/local/bin/$(APP)
	install -Dm644 configs/config.example.yaml /etc/homeproxy/config.yaml
	install -Dm644 deploy/homeproxy.service /etc/systemd/system/homeproxy.service
	@echo "Edit /etc/homeproxy/config.yaml then: systemctl enable --now homeproxy"
