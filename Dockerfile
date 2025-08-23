FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN apk add --no-cache clang llvm linux-headers libbpf-dev
RUN GOBIN=/usr/local/bin go install github.com/cilium/ebpf/cmd/bpf2go@latest
RUN case "$(go env GOARCH)" in \
      amd64)  TARGET=__TARGET_ARCH_x86 ;; \
      arm64)  TARGET=__TARGET_ARCH_arm64 ;; \
      *) echo "unsupported GOARCH: $(go env GOARCH)"; exit 1 ;; \
    esac && \
    bpf2go -cc clang -go-package=main bpf exec_tracker.c -- -O2 -g -D$TARGET
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/kernelruler .

FROM alpine:latest
COPY --from=build /out/kernelruler /usr/local/bin/kernelruler
ENTRYPOINT ["/usr/local/bin/kernelruler"]
