FROM golang:1.24.0

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o backend .

EXPOSE 8000

CMD ["./backend"] 