package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type LoginRequest struct {
	EncryptedUsername string `json:"encrypted_username" binding:"required"`
	EncryptedPassword string `json:"encrypted_password" binding:"required"`
}

type DecryptRequest struct {
	EncryptedData string `json:"encrypted_data" binding:"required"`
}

type DecryptResponse struct {
	DecryptedData string `json:"decrypted_data"`
}

// 配置
type Config struct {
	AuthServiceURL string
	Port           string
	ServiceToken   string
}

var config = Config{
	AuthServiceURL: getEnv("AUTH_SERVICE_URL", "http://localhost:8001"),
	Port:           getEnv("PORT", "8000"),
	ServiceToken:   getEnv("SERVICE_TOKEN", "your-secure-token"),
}

// 创建限流器
var limiter = rate.NewLimiter(rate.Every(time.Second), 5) // 每秒5个请求

var (
	privateKey     *rsa.PrivateKey
	privateKeyLock sync.RWMutex
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

func fetchPrivateKey() error {
	req, err := http.NewRequest("GET", config.AuthServiceURL+"/private-key", nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("X-Service-Token", config.ServiceToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("获取私钥失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取私钥失败，状态码: %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("解析私钥失败: %v", err)
	}

	// 解析私钥
	block, _ := pem.Decode([]byte(result["private_key"]))
	if block == nil {
		return fmt.Errorf("解析私钥PEM失败")
	}

	newPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析私钥失败: %v", err)
	}

	privateKeyLock.Lock()
	privateKey = newPrivateKey
	privateKeyLock.Unlock()

	return nil
}

func startKeyUpdate() {
	ticker := time.NewTicker(1 * time.Hour) // 每小时检查一次
	defer ticker.Stop()

	for range ticker.C {
		if err := fetchPrivateKey(); err != nil {
			log.Printf("更新私钥失败: %v", err)
		} else {
			log.Println("私钥更新成功")
		}
	}
}

func init() {
	// 创建日志文件
	logFile, err := os.OpenFile("backend.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("创建日志文件失败: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// 获取初始私钥
	if err := fetchPrivateKey(); err != nil {
		log.Fatalf("获取初始私钥失败: %v", err)
	}

	// 启动密钥更新定时器
	go startKeyUpdate()
}

func decryptData(encryptedData string) (string, error) {
	privateKeyLock.RLock()
	defer privateKeyLock.RUnlock()

	// 使用本地私钥解密
	block, _ := pem.Decode([]byte(encryptedData))
	if block == nil {
		return "", fmt.Errorf("解析加密数据PEM失败")
	}

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, block.Bytes)
	if err != nil {
		return "", fmt.Errorf("解密失败: %v", err)
	}

	return string(decrypted), nil
}

func main() {
	// 创建日志文件
	logFile, err := os.OpenFile("backend.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("创建日志文件失败: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// 创建Gin路由
	r := gin.Default()

	// 配置CORS
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// 添加限流中间件
	r.Use(rateLimitMiddleware())

	// 健康检查接口
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// 公钥获取接口
	r.GET("/public-key", func(c *gin.Context) {
		req, err := http.NewRequest("GET", config.AuthServiceURL+"/public-key", nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建请求失败"})
			return
		}
		req.Header.Set("X-Service-Token", config.ServiceToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取公钥失败"})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取公钥失败"})
			return
		}

		var result map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "解析公钥失败"})
			return
		}

		c.JSON(http.StatusOK, result)
	})

	// 登录接口
	r.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("无效的登录请求数据: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据"})
			return
		}

		// 使用本地私钥解密用户名和密码
		username, err := decryptData(req.EncryptedUsername)
		if err != nil {
			log.Printf("解密用户名失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "解密用户名失败"})
			return
		}

		password, err := decryptData(req.EncryptedPassword)
		if err != nil {
			log.Printf("解密密码失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "解密密码失败"})
			return
		}

		// 验证用户名和密码
		if username == "admin" && password == "password" {
			log.Printf("用户 %s 登录成功", username)
			c.JSON(http.StatusOK, gin.H{
				"status":  "success",
				"message": "登录成功",
			})
		} else {
			log.Printf("用户 %s 登录失败", username)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "用户名或密码错误",
			})
		}
	})

	// 启动服务器
	addr := fmt.Sprintf(":%s", config.Port)
	log.Printf("后端服务启动在 %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}
