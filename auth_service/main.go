package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// 配置
type Config struct {
	Port            string
	KeyRotationDays int
	ServiceToken    string
}

var config = Config{
	Port:            getEnv("PORT", "8001"),
	KeyRotationDays: 30,                                           // 密钥30天轮换一次
	ServiceToken:    getEnv("SERVICE_TOKEN", "your-secure-token"), // 服务间认证token
}

// 创建限流器
var limiter = rate.NewLimiter(rate.Every(time.Second), 5) // 每秒5个请求

// 密钥管理
type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CreatedAt  time.Time
}

var (
	keyPair     *KeyPair
	keyPairLock sync.RWMutex
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

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-Service-Token")
		if token != config.ServiceToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权的访问"})
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

func generateKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成RSA密钥对失败: %v", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
	}, nil
}

func saveKeyPair(kp *KeyPair) error {
	// 保存私钥到文件
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(kp.PrivateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile("private.pem", privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("保存私钥失败: %v", err)
	}

	// 保存公钥到文件
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return fmt.Errorf("序列化公钥失败: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile("public.pem", publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("保存公钥失败: %v", err)
	}

	return nil
}

func init() {
	// 创建日志文件
	logFile, err := os.OpenFile("auth_service.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("创建日志文件失败: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// 生成初始密钥对
	keyPair, err = generateKeyPair()
	if err != nil {
		log.Fatalf("生成初始密钥对失败: %v", err)
	}

	if err := saveKeyPair(keyPair); err != nil {
		log.Fatalf("保存初始密钥对失败: %v", err)
	}

	log.Println("初始RSA密钥对生成并保存成功")

	// 启动密钥轮换定时器
	go startKeyRotation()
}

func startKeyRotation() {
	ticker := time.NewTicker(24 * time.Hour) // 每天检查一次
	defer ticker.Stop()

	for range ticker.C {
		keyPairLock.RLock()
		age := time.Since(keyPair.CreatedAt)
		keyPairLock.RUnlock()

		if age > time.Duration(config.KeyRotationDays)*24*time.Hour {
			log.Println("开始密钥轮换")
			newKeyPair, err := generateKeyPair()
			if err != nil {
				log.Printf("生成新密钥对失败: %v", err)
				continue
			}

			if err := saveKeyPair(newKeyPair); err != nil {
				log.Printf("保存新密钥对失败: %v", err)
				continue
			}

			keyPairLock.Lock()
			keyPair = newKeyPair
			keyPairLock.Unlock()

			log.Println("密钥轮换完成")
		}
	}
}

func main() {
	// 创建日志文件
	logFile, err := os.OpenFile("auth_service.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("创建日志文件失败: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// 创建密钥存储目录
	keyPath := filepath.Join(os.Getenv("HOME"), ".rsa-keys")
	if err := os.MkdirAll(keyPath, 0700); err != nil {
		log.Fatalf("创建密钥目录失败: %v", err)
	}

	// 创建Gin路由
	r := gin.Default()

	// 配置CORS
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Service-Token")
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
		keyPairLock.RLock()
		defer keyPairLock.RUnlock()

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(keyPair.PublicKey)
		if err != nil {
			log.Printf("序列化公钥失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "获取公钥失败"})
			return
		}
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})
		c.JSON(http.StatusOK, gin.H{"public_key": string(publicKeyPEM)})
	})

	// 私钥获取接口（需要认证）
	r.GET("/private-key", authMiddleware(), func(c *gin.Context) {
		keyPairLock.RLock()
		defer keyPairLock.RUnlock()

		privateKeyBytes := x509.MarshalPKCS1PrivateKey(keyPair.PrivateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		c.JSON(http.StatusOK, gin.H{"private_key": string(privateKeyPEM)})
	})

	// 启动服务器
	addr := fmt.Sprintf(":%s", config.Port)
	log.Printf("认证服务启动在 %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}
