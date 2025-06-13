# API 文档

## 后端服务 API

### 证书管理

#### 获取公钥
- **URL**: `/api/public-key`
- **方法**: `GET`
- **描述**: 获取RSA公钥
- **响应**:
  ```json
  {
    "code": 0,
    "data": {
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "expires_at": "2024-03-16T00:00:00Z"
    },
    "message": "success",
    "timestamp": "2024-03-15T12:00:00Z"
  }
  ```

#### 加密数据
- **URL**: `/api/encrypt`
- **方法**: `POST`
- **描述**: 使用RSA公钥加密数据
- **请求头**:
  - `Authorization`: Bearer {token}
  - `X-Encrypted-Key`: 加密后的AES密钥
- **请求体**:
  ```json
  {
    "message": "要加密的数据"
  }
  ```
- **响应**:
  ```json
  {
    "code": 0,
    "data": {
      "decrypted_key": "解密后的AES密钥",
      "encrypted_data": "加密后的数据",
      "decrypted_data": "解密后的数据"
    },
    "message": "success",
    "timestamp": "2024-03-15T12:00:00Z"
  }
  ```

### 用户认证

#### 登录
- **URL**: `/api/login`
- **方法**: `POST`
- **描述**: 用户登录
- **请求头**:
  - `X-Encrypted-Key`: 加密后的AES密钥
- **请求体**:
  ```json
  {
    "username": "加密后的用户名",
    "password": "加密后的密码"
  }
  ```
- **响应**:
  ```json
  {
    "code": 0,
    "data": {
      "status": "success",
      "message": "登录成功"
    },
    "message": "success",
    "timestamp": "2024-03-15T12:00:00Z"
  }
  ```

### 健康检查
- **URL**: `/api/health`
- **方法**: `GET`
- **描述**: 检查服务健康状态
- **响应**:
  ```json
  {
    "code": 0,
    "data": {
      "status": "healthy"
    },
    "message": "success",
    "timestamp": "2024-03-15T12:00:00Z"
  }
  ```

## 错误处理

所有API在发生错误时都会返回以下格式的响应：

```json
{
  "code": 错误码,
  "data": null,
  "message": "错误描述",
  "timestamp": "2024-03-15T12:00:00Z"
}
```

### 错误码说明

- 1000: 系统错误
- 1001: 参数错误
- 1002: 认证失败
- 1003: 授权失败
- 1004: 资源不存在
- 1005: 请求频率超限
- 1006: 服务不可用
- 1007: 加密失败
- 1008: 解密失败

## 安全说明

1. 所有API请求都需要使用HTTPS
2. 需要JWT认证的接口必须在请求头中携带有效的令牌
3. 敏感数据使用RSA-2048加密
4. 实现了请求频率限制
5. 支持CORS安全配置
6. 密钥轮换机制
   - 系统每1分钟自动轮换一次RSA密钥对
   - 客户端在遇到400错误时自动重试获取新公钥
   - 最大重试次数为3次，每次重试间隔递增
   - 重试过程中会自动清除本地缓存的旧公钥
   - 密钥轮换失败时会记录错误日志并继续使用旧密钥

## 请求限制

- 登录：5次/分钟
- 加密操作：20次/分钟
- 健康检查：30次/分钟

## 响应格式

所有API响应都遵循以下格式：

```json
{
  "code": 0,           // 状态码，0表示成功
  "data": {},         // 响应数据
  "message": "",      // 响应消息
  "timestamp": ""     // 响应时间戳
}
```

## 版本控制

API版本通过URL路径控制，当前版本为v1。未来版本将使用新的路径，如`/api/v2/`。

## 更新日志

### v1.0.0 (2024-03-15)
- 初始版本发布
- 实现基本的加密解密功能
- 添加用户认证
- 实现健康检查 