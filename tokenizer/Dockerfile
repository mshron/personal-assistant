FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git
RUN git clone --depth 1 https://github.com/superfly/tokenizer.git /src
WORKDIR /src
RUN go build -o /tokenizer ./cmd/tokenizer

FROM alpine:latest
COPY --from=builder /tokenizer /usr/local/bin/tokenizer
EXPOSE 8080
CMD ["tokenizer"]
