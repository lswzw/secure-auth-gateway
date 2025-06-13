package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHealthCheck(t *testing.T) {
	// 创建测试路由
	r := setupTestRouter()

	// 创建测试请求
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，实际得到 %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("期望状态 'healthy'，实际得到 '%s'", response["status"])
	}
}

func TestPublicKeyEndpoint(t *testing.T) {
	// 创建测试路由
	r := setupTestRouter()

	// 创建测试请求
	req := httptest.NewRequest("GET", "/public-key", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，实际得到 %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}

	if response["public_key"] == "" {
		t.Error("公钥为空")
	}
}

func TestLoginEndpoint(t *testing.T) {
	// 创建测试路由
	r := setupTestRouter()

	// 生成测试密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥对失败: %v", err)
	}

	// 加密测试数据
	encryptedUsername, err := encryptTestData("admin", &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("加密用户名失败: %v", err)
	}

	encryptedPassword, err := encryptTestData("password", &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("加密密码失败: %v", err)
	}

	// 创建登录请求
	loginData := LoginRequest{
		EncryptedUsername: encryptedUsername,
		EncryptedPassword: encryptedPassword,
	}
	jsonData, err := json.Marshal(loginData)
	if err != nil {
		t.Fatalf("序列化登录数据失败: %v", err)
	}

	// 发送登录请求
	req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，实际得到 %d", http.StatusOK, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}

	if response["status"] != "success" {
		t.Errorf("期望状态 'success'，实际得到 '%s'", response["status"])
	}
}

func TestRateLimiting(t *testing.T) {
	// 创建测试路由
	r := setupTestRouter()

	// 发送超过限制的请求
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if i < 5 {
			if w.Code != http.StatusOK {
				t.Errorf("请求 %d: 期望状态码 %d，实际得到 %d", i, http.StatusOK, w.Code)
			}
		} else {
			if w.Code != http.StatusTooManyRequests {
				t.Errorf("请求 %d: 期望状态码 %d，实际得到 %d", i, http.StatusTooManyRequests, w.Code)
			}
		}
	}
}

func TestKeyUpdate(t *testing.T) {
	// 创建测试路由
	r := setupTestRouter()

	// 模拟密钥更新
	if err := fetchPrivateKey(); err != nil {
		t.Fatalf("更新私钥失败: %v", err)
	}

	// 验证私钥已更新
	privateKeyLock.RLock()
	if privateKey == nil {
		t.Error("私钥未更新")
	}
	privateKeyLock.RUnlock()
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.Use(rateLimitMiddleware())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

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

		var result map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "解析公钥失败"})
			return
		}

		c.JSON(http.StatusOK, result)
	})

	r.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据"})
			return
		}

		username, err := decryptData(req.EncryptedUsername)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "解密用户名失败"})
			return
		}

		password, err := decryptData(req.EncryptedPassword)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "解密密码失败"})
			return
		}

		if username == "admin" && password == "password" {
			c.JSON(http.StatusOK, gin.H{
				"status":  "success",
				"message": "登录成功",
			})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "用户名或密码错误",
			})
		}
	})

	return r
}

func encryptTestData(data string, publicKey *rsa.PublicKey) (string, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(data))
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "RSA ENCRYPTED DATA",
		Bytes: encrypted,
	}

	return string(pem.EncodeToMemory(block)), nil
}
