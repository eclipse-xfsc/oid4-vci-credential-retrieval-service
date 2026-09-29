FROM golang:1.24.2-alpine3.20 AS build

WORKDIR /app

# CA-Zertifikate aktualisieren/installieren
RUN apk update && \
    apk add --no-cache ca-certificates && \
    update-ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux \
    go build -ldflags="-s -w" -o /server


FROM scratch AS run

# CA Trust Store für HTTPS Requests
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=build /server /server
COPY --from=build /app/.env /.env

CMD ["/server"]