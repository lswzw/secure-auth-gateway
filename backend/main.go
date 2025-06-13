package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"backend/crypto_service"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DecryptRequest struct {
	EncryptedData []byte `json:"encrypted_data" binding:"required"`
}

type DecryptResponse struct {
	DecryptedData string `json:"decrypted_data"`
}

type EncryptRequest struct {
	Message string `json:"message" binding:"required"`
}

type EncryptResponse struct {
	DecryptedKey  string `json:"decrypted_key"`
	EncryptedData string `json:"encrypted_data"`
	DecryptedData string `json:"decrypted_data"`
}

// 配置
type Config struct {
	Port    string
	KeyPath string
}

var config = Config{
	Port:    getEnv("PORT", "8000"),
	KeyPath: getEnv("KEY_PATH", "./keys"),
}

// 创建限流器
var limiter = rate.NewLimiter(rate.Every(time.Second), 5) // 每秒5个请求

var (
	rsaService *crypto_service.RSAService
	jwtService *crypto_service.JWTService
)

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁，请稍后再试"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func init() {
	var err error
	// 初始化RSA服务
	rsaService, err = crypto_service.NewRSAService(config.KeyPath)
	if err != nil {
		log.Fatalf("初始化RSA服务失败: %v", err)
	}

	// 初始化JWT服务
	jwtService = crypto_service.NewJWTService(getEnv("JWT_SECRET", "your-secret-key"))
}

// 将短格式的RSA加密字符串转换回标准base64格式
func convertShortKeyToBase64(shortKey string) string {
	// 将短格式转换回标准base64
	standardKey := shortKey
	// 添加回base64填充
	padding := len(standardKey) % 4
	if padding > 0 {
		standardKey += strings.Repeat("=", 4-padding)
	}
	// 转换回标准base64字符
	standardKey = strings.ReplaceAll(standardKey, "-", "+")
	standardKey = strings.ReplaceAll(standardKey, "_", "/")
	return standardKey
}

// AES解密函数
func decryptAESData(encryptedData string, key []byte) (string, error) {
	log.Printf("\n=== 开始AES解密过程 ===")
	log.Printf("1. 收到的base64加密数据: %s", encryptedData)

	// 解码base64
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("解码base64失败: %v", err)
	}
	log.Printf("2. base64解码后的数据: %x", data)

	// 提取IV（前16字节）
	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	log.Printf("3. 分离IV和密文:")
	log.Printf("   - IV (前16字节): %x", iv)
	log.Printf("   - 密文 (剩余字节): %x", ciphertext)
	log.Printf("   - 使用的密钥: %x", key)

	// 创建AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建AES cipher失败: %v", err)
	}
	log.Printf("4. 成功创建AES cipher")

	// 创建CBC模式的解密器
	mode := cipher.NewCBCDecrypter(block, iv)
	log.Printf("5. 创建CBC模式解密器")

	// 解密
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	log.Printf("6. CBC模式解密后的数据: %x", plaintext)

	// 去除PKCS7填充
	padding := plaintext[len(plaintext)-1]
	log.Printf("7. 检测PKCS7填充:")
	log.Printf("   - 填充值: %x", padding)
	log.Printf("   - 填充长度: %d", padding)

	if padding > aes.BlockSize || padding == 0 {
		return "", fmt.Errorf("无效的填充大小: %d", padding)
	}

	// 验证填充
	for i := len(plaintext) - int(padding); i < len(plaintext); i++ {
		if plaintext[i] != padding {
			return "", fmt.Errorf("无效的填充")
		}
	}
	log.Printf("8. 填充验证通过")

	// 移除填充
	plaintext = plaintext[:len(plaintext)-int(padding)]
	log.Printf("9. 移除填充后的数据: %x", plaintext)

	// 转换为字符串
	result := string(plaintext)
	log.Printf("10. 最终解密结果: %s", result)
	log.Printf("=== AES解密过程完成 ===\n")

	return result, nil
}

// authMiddleware JWT认证中间件
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证token"})
			c.Abort()
			return
		}

		// 从Bearer token中提取token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token格式"})
			c.Abort()
			return
		}

		claims, err := jwtService.ValidateToken(tokenParts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token"})
			c.Abort()
			return
		}

		// 将用户信息存储到上下文中
		c.Set("username", claims.Username)
		c.Next()
	}
}

// 处理登录请求
func handleLogin(c *gin.Context) {
	// 获取RSA加密的AES密钥
	encryptedKey := c.GetHeader("X-Encrypted-Key")
	if encryptedKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少加密密钥"})
		return
	}

	// 转换密钥格式
	standardKey := convertShortKeyToBase64(encryptedKey)

	// 解码base64
	encryptedKeyBytes, err := base64.StdEncoding.DecodeString(standardKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的密钥格式"})
		return
	}

	// 使用RSA私钥解密AES密钥
	decryptedKey, err := rsaService.DecryptWithPrivateKey(string(encryptedKeyBytes))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "解密失败"})
		return
	}

	// 解析请求体
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据"})
		return
	}

	// 解密用户名和密码
	username, err := decryptAESData(req.Username, []byte(decryptedKey))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "解密用户名失败"})
		return
	}

	password, err := decryptAESData(req.Password, []byte(decryptedKey))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "解密密码失败"})
		return
	}

	// 验证用户名和密码
	if username == "admin" && password == "password" {
		// 生成JWT token
		token, err := jwtService.GenerateToken(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成token失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": "登录成功",
			"token":   token,
		})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "用户名或密码错误",
		})
	}
}

// 处理加密请求
func handleEncrypt(c *gin.Context) {
	// 获取RSA加密的AES密钥
	encryptedKey := c.GetHeader("X-Encrypted-Key")
	if encryptedKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少加密密钥"})
		return
	}

	// 转换短格式密钥为标准base64
	encryptedKey = convertShortKeyToBase64(encryptedKey)

	// 解密AES密钥
	keyBytes, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的密钥格式"})
		return
	}

	// 使用RSA私钥解密
	decryptedKey, err := rsaService.DecryptWithPrivateKey(string(keyBytes))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "解密失败"})
		return
	}

	var req EncryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据"})
		return
	}

	// 使用AES密钥解密数据
	decryptedData, err := decryptAESData(req.Message, []byte(decryptedKey))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "解密数据失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"decrypted_key":  decryptedKey,
		"encrypted_data": req.Message,
		"decrypted_data": decryptedData,
	})
}

func main() {
	// 创建Gin路由
	r := gin.Default()

	// 配置CORS
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Encrypted-Key, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// 添加限流中间件
	r.Use(rateLimitMiddleware())

	// 创建API路由组
	api := r.Group("/api")
	{
		// 健康检查接口
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "healthy"})
		})

		// 公钥获取接口
		api.GET("/public-key", func(c *gin.Context) {
			publicKey, err := rsaService.GetPublicKeyPEM()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "获取公钥失败"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"public_key": publicKey,
			})
		})

		// 登录接口
		api.POST("/login", handleLogin)

		// 需要认证的接口
		authorized := api.Group("/")
		authorized.Use(authMiddleware())
		{
			// 加密接口
			authorized.POST("/encrypt", handleEncrypt)

			// 私钥获取接口
			authorized.GET("/private-key", func(c *gin.Context) {
				privateKey, err := rsaService.GetPrivateKeyPEM()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "获取私钥失败"})
					return
				}

				c.JSON(http.StatusOK, gin.H{
					"private_key": privateKey,
				})
			})
		}
	}

	// 启动服务器
	log.Printf("服务器启动在端口 %s", config.Port)
	if err := r.Run(":" + config.Port); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}
