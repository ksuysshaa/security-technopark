FROM golang:1.24-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o security-technopark ./cmd

EXPOSE 8080

ENTRYPOINT ["./security-technopark"]
