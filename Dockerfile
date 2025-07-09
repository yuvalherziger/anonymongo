# @/Dockerfile
FROM golang:1.24-alpine AS builder
ARG ANONYMONGO_VERSION=dev
ENV ANONYMONGO_VERSION=${ANONYMONGO_VERSION}
RUN apk add --no-cache make
WORKDIR /app
COPY Makefile ./
COPY go.mod go.sum ./
RUN go mod download
COPY src/ ./src
RUN make build

FROM alpine:latest
RUN addgroup -S cligroup && adduser -S cliuser -G cligroup
COPY --from=builder /app/dist/anonymongo /usr/local/bin/anonymongo
RUN mkdir /data && chown cliuser:cligroup /data
WORKDIR /data
USER cliuser
ENTRYPOINT ["anonymongo"]
CMD ["--help"]
