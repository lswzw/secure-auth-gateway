package config

import (
	"log"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

type whitelistConfig struct {
	Whitelist []string `yaml:"whitelist"`
}

var (
	whitelistMap = make(map[string]bool)
	once         sync.Once
)

// LoadWhitelist 只加载一次白名单
func LoadWhitelist() {
	once.Do(func() {
		// 获取可执行文件所在目录
		execPath, err := os.Executable()
		if err != nil {
			log.Printf("获取可执行文件路径失败: %v", err)
			return
		}
		execDir := filepath.Dir(execPath)

		// 尝试多个可能的配置文件路径
		possiblePaths := []string{
			filepath.Join(execDir, "config", "whitelist.yaml"),            // 相对于可执行文件
			filepath.Join(execDir, "backend", "config", "whitelist.yaml"), // 相对于可执行文件的backend目录
			"backend/config/whitelist.yaml",                               // 相对于当前工作目录
			"config/whitelist.yaml",                                       // 相对于当前工作目录
		}

		var file []byte
		for _, path := range possiblePaths {
			file, err = os.ReadFile(path)
			if err == nil {
				log.Printf("成功加载白名单配置文件: %s", path)
				break
			}
		}

		if err != nil {
			log.Printf("加载白名单配置失败: %v", err)
			return
		}

		var cfg whitelistConfig
		if err := yaml.Unmarshal(file, &cfg); err != nil {
			log.Printf("解析白名单配置失败: %v", err)
			return
		}

		// 清空并重新加载白名单
		whitelistMap = make(map[string]bool)
		for _, path := range cfg.Whitelist {
			whitelistMap[path] = true
			log.Printf("添加白名单路径: %s", path)
		}
	})
}

// IsWhitelisted 检查路径是否在白名单
func IsWhitelisted(path string) bool {
	LoadWhitelist()
	isWhitelisted := whitelistMap[path]
	log.Printf("检查路径 %s 是否在白名单中: %v", path, isWhitelisted)
	return isWhitelisted
}
