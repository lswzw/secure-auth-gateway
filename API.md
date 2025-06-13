# 接口文档

## 认证服务 (auth_service)

### 1. 获取公钥
- **接口**: GET /public-key
- **说明**: 返回PEM格式的RSA公钥，用于前端加密。
- **响应示例**:
  ```json
  {
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
  }
  ```

### 2. 解密数据
- **接口**: POST /decrypt
- **说明**: 使用私钥解密前端加密的数据。
- **请求体**:
  ```json
  {
    "encrypted_data": "base64加密字符串"
  }
  ```
- **响应示例**:
  ```json
  {
    "decrypted_data": "明文数据"
  }
  ```

---

## 后端服务 (backend)

### 1. 登录
- **接口**: POST /login
- **说明**: 接收加密的用户名和密码，解密后校验登录。
- **请求体**:
  ```json
  {
    "encrypted_username": "base64加密字符串",
    "encrypted_password": "base64加密字符串"
  }
  ```
- **响应示例**:
  ```json
  {
    "status": "success",
    "message": "登录成功"
  }
  ```

---

## 健康检查接口

### 1. 认证服务健康检查
- **接口**: GET /health
- **说明**: 返回服务健康状态。
- **响应示例**:
  ```json
  {
    "status": "healthy"
  }
  ```

### 2. 后端服务健康检查
- **接口**: GET /health
- **说明**: 返回服务健康状态。
- **响应示例**:
  ```json
  {
    "status": "healthy"
  }
  ```

---

如需更多接口说明或有其他需求，请随时联系！ 