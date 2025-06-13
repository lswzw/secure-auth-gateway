# 非对称加解密服务

## 项目概述
本项目是一个基于非对称加密的认证系统，包含以下组件：
- 认证服务（Auth Service）：负责密钥管理和分发
- 后端服务（Backend Service）：处理业务逻辑、用户认证和数据加解密
- 前端界面（Frontend）：基于 Vue3 的用户界面

## 系统架构
```
+-------------+     +----------------+     +----------------+
|   Frontend  | --> | Backend Service| --> | Auth Service   |
|  (Vue3)     |     |    (Gin)       |     |    (Gin)       |
+-------------+     +----------------+     +----------------+
```

## 请求链路
```
+----------------+     +----------------+     +----------------+
|    Frontend    |     |    Backend     |     |    Auth        |
|   (Vue3)       |     |   Service      |     |   Service      |
+----------------+     +----------------+     +----------------+
        |                      |                     |
        |  1. 获取公钥         |                     |
        |---------------------->                     |
        |                      |                     |
        |                      |  2. 请求公钥        |
        |                      |-------------------->|
        |                      |                     |
        |                      |  3. 返回公钥        |
        |                      |<--------------------|
        |                      |                     |
        |  4. 返回公钥         |                     |
        |<---------------------|                     |
        |                      |                     |
        |  5. 加密用户凭据     |                     |
        |   (username/password)|                     |
        |                      |                     |
        |  6. 发送加密数据     |                     |
        |---------------------->                     |
        |                      |                     |
        |                      |  7. 解密数据        |
        |                      |                     |
        |                      |  8. 验证用户信息    |
        |                      |                     |
        |  9. 返回JWT令牌      |                     |
        |<---------------------|                     |
        |                      |                     |
        |  10. 存储令牌        |                     |
        |  用于后续请求        |                     |
        |                      |                     |
```

### 详细流程说明

1. **初始化阶段**
   - 前端启动时请求后端获取 RSA 公钥
   - 后端从认证服务获取公钥并返回给前端
   | 前端保存公钥用于后续加密

2. **登录请求阶段**
   - 用户输入用户名和密码
   - 前端使用 RSA 公钥加密用户凭据
   - 加密数据通过 HTTPS 发送到后端

3. **认证处理阶段**
   - 后端接收加密数据
   - 后端使用私钥解密数据（私钥由认证服务分发）
   - 验证用户凭据的有效性

4. **响应处理阶段**
   - 后端验证用户信息
   - 生成 JWT 令牌
   - 返回登录结果给前端

5. **会话管理阶段**
   - 前端存储 JWT 令牌
   - 后续请求携带令牌
   - 后端验证令牌有效性
   - 维护用户会话状态

### 安全特性
- 所有通信使用 HTTPS 加密
- 用户凭据使用 RSA 非对称加密
- 私钥仅在后端使用，不暴露给前端
- 使用 JWT 进行身份验证
- 实现请求速率限制
- 支持密钥定期轮换

## 快速开始

### 环境要求
- Go 1.24.0 或更高版本
- Node.js 18 或更高版本
- Docker 和 Docker Compose（可选）

### 方法一：使用 Docker（推荐）
1. 确保已安装 Docker 和 Docker Compose
2. 在项目根目录运行：
   ```bash
   docker-compose up
   ```
3. 访问 http://localhost:5173

### 方法二：手动启动
1. 启动认证服务：
   ```bash
   cd auth_service
   go run main.go
   ```

2. 启动后端服务：
   ```bash
   cd backend
   go run main.go
   ```

3. 启动前端服务：
   ```bash
   cd frontend/vue-project
   npm install
   npm run dev
   ```

4. 访问 http://localhost:5173

### 方法三：使用启动脚本
1. 给启动脚本添加执行权限：
   ```bash
   chmod +x start.sh
   ```

2. 运行启动脚本：
   ```bash
   ./start.sh
   ```

3. 访问 http://localhost:5173

## 主要功能
1. 用户认证
   - 使用 RSA 非对称加密保护用户凭据
   - 支持 JWT 令牌认证
   - 默认用户名：admin
   - 默认密码：password

2. 密钥管理
   - 自动生成 RSA 密钥对
   - 安全的密钥存储
   - 定期密钥轮换

3. 安全特性
   - 请求速率限制
   - 错误处理
   - 日志记录
   - 健康检查

## 项目结构
```
.
├── auth_service/          # 认证服务
│   ├── main.go           # 主程序
│   ├── rsa_service.go    # RSA 服务
│   └── Dockerfile        # Docker 配置
├── backend/              # 后端服务
│   ├── main.go          # 主程序
│   └── Dockerfile       # Docker 配置
├── frontend/             # 前端项目
│   └── vue-project/     # Vue3 项目
│       ├── src/         # 源代码
│       └── Dockerfile   # Docker 配置
├── docker-compose.yml    # Docker Compose 配置
├── start.sh             # 启动脚本
└── README.md            # 项目文档
```

## API 文档
详细的 API 文档请参考 [API.md](API.md)

## 注意事项
1. 首次运行时会自动生成 RSA 密钥对
2. 生产环境部署时请修改默认密码
3. 确保所有服务端口未被占用
4. 建议使用 Docker 方式部署以确保环境一致性

## 开源协议

本项目采用 MIT 协议开源。详情请查看 [LICENSE](LICENSE) 文件。

## 测试

### 运行测试
1. 认证服务测试：
   ```bash
   cd auth_service
   go test -v
   ```

2. 后端服务测试：
   ```bash
   cd backend
   go test -v
   ```

3. 前端测试：
   ```bash
   cd frontend/vue-project
   npm run test
   ```

### 测试覆盖率
1. Go 服务测试覆盖率：
   ```bash
   cd auth_service
   go test -cover
   
   cd ../backend
   go test -cover
   ```

2. 前端测试覆盖率：
   ```bash
   cd frontend/vue-project
   npm run test:coverage
   ```

### 测试内容
1. 认证服务测试
   - RSA 密钥对生成
   - 数据加密解密
   - 公钥获取
   - 密钥轮换

2. 后端服务测试
   - 健康检查接口
   - 登录接口
   - 请求限流
   - 错误处理

3. 前端测试
   - 登录表单验证
   - 公钥获取
   - 数据加密
   - 登录响应处理

```
MIT License

Copyright (c) 2024 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
``` 