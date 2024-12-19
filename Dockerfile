FROM golang:1.22.5-alpine

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o server ./cmd/main.go

EXPOSE 8080

CMD ["./server"]
