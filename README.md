# 安全通信业务网关（名称解析：ModuGate）

ModuGate 是一款基于 Go 开发的模块化安全通信网关。它采用插件化架构，支持灵活扩展，适用于企业级通信、物联网边缘接入、API 安全代理等多种场景。通过 ModuGate，用户可以快速构建高安全性、高性能的通信通道，并根据需求动态加载功能模块。

名称解析：ModuGate
🔤 拆解：
Modu = 来自英文单词 "Modular"（模块化的）
Gate = 英文单词 "Gateway"（网关） 的简写
合起来就是：
ModuGate = Modular + Gateway
一个模块化的网关系统。

![项目 Logo](frontend/public/logo.svg)

## 项目概述

本项目实现了一个基于RSA和AES的加密通信系统，包含以下组件：

1. 前端（Vue.js + Vite）
2. 后端服务（Go）

## 系统架构

```
+-------------+     +-------------+
|   前端      |     |   后端      |
|  Vue.js     |<--->|  Go         |
+-------------+     +-------------+
```

## 项目结构

```
.
├── frontend/                # 前端项目目录
│   ├── src/                # 源代码
│   ├── public/             # 静态资源
│   ├── package.json        # 项目依赖配置
│   ├── vite.config.js      # Vite 配置
│   ├── nginx.conf          # Nginx 配置
│   └── Dockerfile          # 前端 Docker 配置
│
├── backend/                # 后端项目目录
│   ├── crypto_service/     # 加密服务模块
│   ├── keys/              # 密钥存储目录
│   ├── main.go            # 主程序入口
│   ├── go.mod             # Go 模块配置
│   └── Dockerfile         # 后端 Docker 配置
│
├── docker-compose.yml     # Docker 编排配置
├── API.md                 # API 文档
└── README.md             # 项目说明文档
```

## 请求链路图

```
+----------------+     +----------------+
|    Frontend    |     |    Backend     |
|   (Vue3)       |     |   Service      |
+----------------+     +----------------+
        |                      |
        |  1. GET /api/public-key  |
        |---------------------->|
        |                      |
        |  2. 返回RSA公钥      |
        |<---------------------|
        |                      |
        |  3. 生成AES密钥      |
        |  加密用户名密码      |
        |                      |
        |  4. POST /api/login   |
        |  X-Encrypted-Key     |
        |---------------------->|
        |                      |
        |  5. 解密AES密钥      |
        |  验证用户信息        |
        |                      |
        |  6. 返回登录结果     |
        |<---------------------|
        |                      |
        |  7. POST /api/encrypt |
        |  X-Encrypted-Key     |
        |---------------------->|
        |                      |
        |  8. 解密并处理数据   |
        |                      |
        |  9. 返回处理结果     |
        |<---------------------|
        |                      |
        |  10. GET /api/health  |
        |---------------------->|
        |                      |
        |  11. 返回服务状态    |
        |<---------------------|
        |                      |
```
## 技术栈

### 前端
- Vue.js 3
- Vite
- Axios
- CryptoJS

### 后端
- Go 1.21+
- Gin Web框架
- RSA-2048
- AES-128-CBC

## 安全特性

1. 端到端加密
   - 使用RSA-2048进行密钥交换
   - 使用AES-128-CBC进行数据加密
   - 所有通信都经过加密

2. 安全防护
   - 请求频率限制
   - CORS安全配置
   - 基于RSA和AES的认证机制

3. 密钥管理
   - 自动密钥轮换
   - 安全的密钥存储
   - 密钥使用审计

## 认证流程

1. 前端获取RSA公钥
2. 生成随机AES密钥
3. 使用RSA公钥加密AES密钥
4. 使用AES密钥加密用户名和密码
5. 将加密后的AES密钥和登录信息发送到后端
6. 后端使用RSA私钥解密AES密钥
7. 使用解密后的AES密钥解密登录信息
8. 验证用户名和密码

## 快速开始

### 使用Docker Compose

1. 启动服务：
```bash
docker-compose up -d
```

2. 访问地址：
```bash
http://localhost:80
```

## 开发指南

### 环境要求

- Node.js 18+
- Go 1.21+
- Docker & Docker Compose

### 开发环境设置

1. 前端开发：
```bash
cd frontend
npm install
npm run dev
```

2. 后端开发：
```bash
cd backend
go mod download
go run main.go
```