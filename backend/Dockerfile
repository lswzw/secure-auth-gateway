# 构建阶段
FROM golang:1.24.0-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的构建工具
RUN apk add --no-cache git

# 复制所有源代码
COPY . .

# 构建应用
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# 运行阶段
FROM alpine:latest

# 安装必要的运行时依赖
RUN apk --no-cache add ca-certificates tzdata

# 设置工作目录
WORKDIR /app

# 创建必要的目录
RUN mkdir -p /app/logs /app/keys

# 从构建阶段复制编译好的应用
COPY --from=builder /app/main .

# 设置环境变量
ENV TZ=Asia/Shanghai \
    PORT=8000 \
    KEY_PATH=/app/keys

# 设置目录权限
RUN chmod 700 /app/keys

# 暴露端口
EXPOSE 8000

# 运行应用
CMD ["./main"] 