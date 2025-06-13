package crypto_service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type RSAService struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	keyPath        string
	privateKeyLock sync.RWMutex
}

// NewRSAService 创建新的RSA服务实例
func NewRSAService(keyPath string) (*RSAService, error) {
	service := &RSAService{
		keyPath: keyPath,
	}

	// 尝试加载现有密钥
	if err := service.loadKeys(); err != nil {
		// 如果加载失败，生成新的密钥对
		if err := service.generateKeyPair(); err != nil {
			return nil, err
		}
		// 保存新生成的密钥
		if err := service.saveKeys(); err != nil {
			return nil, err
		}
	}

	// 启动密钥轮换
	go service.startKeyRotation()

	return service, nil
}

// loadKeys 从文件加载密钥
func (s *RSAService) loadKeys() error {
	// 读取私钥
	privateKeyBytes, err := os.ReadFile(filepath.Join(s.keyPath, "private.pem"))
	if err != nil {
		return err
	}

	// 解析私钥
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return errors.New("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	s.privateKeyLock.Lock()
	s.privateKey = privateKey
	s.publicKey = &privateKey.PublicKey
	s.privateKeyLock.Unlock()
	return nil
}

// saveKeys 保存密钥到文件
func (s *RSAService) saveKeys() error {
	// 确保目录存在
	if err := os.MkdirAll(s.keyPath, 0700); err != nil {
		return err
	}

	s.privateKeyLock.RLock()
	// 保存私钥
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(s.privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile(filepath.Join(s.keyPath, "private.pem"), privateKeyPEM, 0600); err != nil {
		s.privateKeyLock.RUnlock()
		return err
	}

	// 保存公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		s.privateKeyLock.RUnlock()
		return err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	s.privateKeyLock.RUnlock()

	if err := os.WriteFile(filepath.Join(s.keyPath, "public.pem"), publicKeyPEM, 0644); err != nil {
		return err
	}

	return nil
}

// generateKeyPair 生成新的RSA密钥对
func (s *RSAService) generateKeyPair() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	s.privateKeyLock.Lock()
	s.privateKey = privateKey
	s.publicKey = &privateKey.PublicKey
	s.privateKeyLock.Unlock()
	return nil
}

// startKeyRotation 启动密钥轮换定时器
func (s *RSAService) startKeyRotation() {
	ticker := time.NewTicker(24 * time.Hour) // 每24小时更新一次
	defer ticker.Stop()

	for range ticker.C {
		if err := s.generateKeyPair(); err != nil {
			// 记录错误但继续运行
			continue
		}
		if err := s.saveKeys(); err != nil {
			// 记录错误但继续运行
			continue
		}
	}
}

// GetPublicKeyPEM 获取PEM格式的公钥
func (s *RSAService) GetPublicKeyPEM() (string, error) {
	s.privateKeyLock.RLock()
	defer s.privateKeyLock.RUnlock()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

// GetPrivateKeyPEM 获取PEM格式的私钥
func (s *RSAService) GetPrivateKeyPEM() (string, error) {
	s.privateKeyLock.RLock()
	defer s.privateKeyLock.RUnlock()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(s.privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

// EncryptWithPublicKey 使用公钥加密
func (s *RSAService) EncryptWithPublicKey(message string) (string, error) {
	s.privateKeyLock.RLock()
	defer s.privateKeyLock.RUnlock()

	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, s.publicKey, []byte(message))
	if err != nil {
		return "", err
	}
	return string(encryptedBytes), nil
}

// DecryptWithPrivateKey 使用私钥解密
func (s *RSAService) DecryptWithPrivateKey(encryptedMessage string) (string, error) {
	s.privateKeyLock.RLock()
	defer s.privateKeyLock.RUnlock()

	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, s.privateKey, []byte(encryptedMessage))
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}
