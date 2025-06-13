FROM golang:1.24.0

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o auth_service .

EXPOSE 8001

CMD ["./auth_service"] 