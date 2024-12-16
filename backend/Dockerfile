FROM golang:1.23-alpine

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
RUN apk add --no-cache tzdata

COPY .env .env

COPY . .
ENV VIEWS_DIR=/app/delivery/templates
ENV TZ=UTC

RUN go build -o /app/delivery/main /app/delivery/main.go

EXPOSE 8080

ENV GIN_MODE=release

CMD ["/app/delivery/main"]
