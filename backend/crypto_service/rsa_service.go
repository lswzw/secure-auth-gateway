package crypto_service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

type RSAService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewRSAService 创建新的RSA服务实例
func NewRSAService() (*RSAService, error) {
	// 生成2048位的RSA密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &RSAService{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// GetPublicKeyPEM 获取PEM格式的公钥
func (s *RSAService) GetPublicKeyPEM() (string, error) {
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

// EncryptWithPublicKey 使用公钥加密
func (s *RSAService) EncryptWithPublicKey(message string) (string, error) {
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, s.publicKey, []byte(message))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// DecryptWithPrivateKey 使用私钥解密
func (s *RSAService) DecryptWithPrivateKey(encryptedMessage string) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, s.privateKey, encryptedBytes)
	if err != nil {
		return "", err
	}

	return string(decryptedBytes), nil
}
