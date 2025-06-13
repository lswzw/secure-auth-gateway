<template>
  <div class="login-container">
    <div v-if="!isLoggedIn" class="login-box">
      <h2>登录</h2>
      <form @submit.prevent="handleLogin">
        <div class="form-group">
          <label for="username">用户名</label>
          <input
            type="text"
            id="username"
            v-model="username"
            required
            placeholder="请输入用户名"
          />
        </div>
        <div class="form-group">
          <label for="password">密码</label>
          <input
            type="password"
            id="password"
            v-model="password"
            required
            placeholder="请输入密码"
          />
        </div>
        <button type="submit" :disabled="loading">
          {{ loading ? '登录中...' : '登录' }}
        </button>
      </form>
      <p v-if="error" class="error">{{ error }}</p>
    </div>
    <EncryptForm v-else />
  </div>
</template>

<script>
import { ref } from 'vue'
import JSEncrypt from 'jsencrypt'
import axios from 'axios'
import EncryptForm from './EncryptForm.vue'
import CryptoJS from 'crypto-js'

// 配置API基础URL
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api'

export default {
  name: 'Login',
  components: {
    EncryptForm
  },
  setup() {
    const username = ref('admin')
    const password = ref('password')
    const loading = ref(false)
    const error = ref('')
    const publicKey = ref('')
    const isLoggedIn = ref(false)

    // 生成随机密钥
    const generateRandomKey = () => {
      // 生成16位随机密钥
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
      let result = ''
      for (let i = 0; i < 16; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length))
      }
      return result
    }

    // AES 加密
    const encryptWithAES = (data, key) => {
      // 生成随机IV
      const iv = CryptoJS.lib.WordArray.random(16)
      
      // 直接使用2位密钥
      const keyWordArray = CryptoJS.enc.Utf8.parse(key)
      
      // 使用CBC模式加密
      const encrypted = CryptoJS.AES.encrypt(data, keyWordArray, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      })
      
      // 将IV和加密数据合并
      const combined = iv.concat(encrypted.ciphertext)
      
      // 转换为base64
      const base64Data = CryptoJS.enc.Base64.stringify(combined)
      console.log('加密后的base64数据:', base64Data)
      return base64Data
    }

    // RSA 加密并转换为短格式
    const encryptWithRSA = (data) => {
      try {
        const encrypt = new JSEncrypt()
        encrypt.setPublicKey(publicKey.value)
        const encrypted = encrypt.encrypt(data)
        if (!encrypted) {
          throw new Error('RSA加密失败')
        }
        // 将base64字符串转换为更短的格式
        const shortKey = encrypted.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
        console.log('RSA加密后的完整密钥:', encrypted)
        console.log('转换后的短密钥:', shortKey)
        return shortKey
      } catch (error) {
        console.error('RSA加密过程出错:', error)
        throw new Error('RSA加密失败')
      }
    }

    const getPublicKey = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/public-key`)
        publicKey.value = response.data.public_key
        console.log('获取到的公钥:', publicKey.value)
      } catch (err) {
        error.value = '获取公钥失败'
        console.error('获取公钥失败:', err)
      }
    }

    const handleLogin = async () => {
      loading.value = true
      error.value = ''

      try {
        // 先获取公钥
        await getPublicKey()
        
        if (!publicKey.value) {
          throw new Error('获取公钥失败')
        }

        // 保存公钥到localStorage
        localStorage.setItem('publicKey', publicKey.value)
        
        // 生成随机密钥
        const aesKey = generateRandomKey()
        console.log('生成的AES密钥:', aesKey)
        
        // 使用 AES 加密数据
        const encryptedUsername = encryptWithAES(username.value, aesKey)
        const encryptedPassword = encryptWithAES(password.value, aesKey)
        console.log('加密后的用户名:', encryptedUsername)
        console.log('加密后的密码:', encryptedPassword)
        
        // 使用 RSA 加密 AES 密钥
        const encryptedKey = encryptWithRSA(aesKey)
        console.log('加密后的AES密钥:', encryptedKey)

        const requestData = {
          username: encryptedUsername,
          password: encryptedPassword
        }
        console.log('请求数据:', requestData)
        console.log('请求头:', {
          'Content-Type': 'application/json',
          'X-Encrypted-Key': encryptedKey
        })

        const response = await axios.post(`${API_BASE_URL}/login`, requestData, {
          headers: {
            'Content-Type': 'application/json',
            'X-Encrypted-Key': encryptedKey
          }
        })

        // 检查响应状态
        if (response.status === 200 && response.data.status === 'success') {
          localStorage.setItem('isLoggedIn', 'true')
          isLoggedIn.value = true
        } else {
          throw new Error(response.data.error || '登录失败')
        }
      } catch (err) {
        error.value = err.message || '登录失败，请重试'
        console.error('登录错误:', err)
      } finally {
        loading.value = false
      }
    }

    return {
      username,
      password,
      loading,
      error,
      isLoggedIn,
      handleLogin
    }
  }
}
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  /* background: linear-gradient(135deg, #a8c0ff, #3f2b96); */ /* 渐变背景 */
  overflow: hidden; /* 防止滚动条出现 */
}

.login-box {
  background: rgba(255, 255, 255, 0.95); /* 半透明背景 */
  padding: 2.5rem 2rem; /* 增加内边距 */
  border-radius: 12px; /* 更大的圆角 */
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); /* 更明显的阴影 */
  width: 100%;
  max-width: 450px; /* 稍微增加最大宽度 */
  box-sizing: border-box; /* 确保内边距和边框包含在宽度内 */
  animation: fadeIn 0.5s ease-out; /* 添加淡入动画 */
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(-20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

h2 {
  text-align: center;
  color: #333;
  margin-bottom: 2rem; /* 增加底部间距 */
  font-size: 2rem; /* 增大标题字体 */
  font-weight: 600;
}

.form-group {
  margin-bottom: 1.5rem; /* 增加组间距 */
}

label {
  display: block;
  margin-bottom: 0.6rem; /* 调整标签底部间距 */
  color: #555; /* 调整标签颜色 */
  font-weight: 500;
}

input {
  width: 100%;
  padding: 0.9rem 1rem; /* 调整内边距 */
  border: 1px solid #ccc;
  border-radius: 6px; /* 调整圆角 */
  font-size: 1.1rem; /* 调整字体大小 */
  transition: border-color 0.3s ease, box-shadow 0.3s ease; /* 添加过渡效果 */
}

input:focus {
  border-color: #4CAF50; /* 焦点边框颜色 */
  box-shadow: 0 0 0 3px rgba(76, 175, 80, 0.2); /* 焦点阴影 */
  outline: none; /* 移除默认焦点轮廓 */
}

button {
  width: 100%;
  padding: 1rem; /* 调整内边距 */
  background-color: #4CAF50;
  color: white;
  border: none;
  border-radius: 6px; /* 调整圆角 */
  font-size: 1.2rem; /* 调整字体大小 */
  cursor: pointer;
  transition: background-color 0.3s ease, transform 0.2s ease; /* 添加过渡效果 */
  font-weight: 600;
  margin-top: 1rem; /* 按钮上方间距 */
}

button:hover {
  background-color: #45a049;
  transform: translateY(-2px); /* 悬停时轻微上移 */
}

button:active {
  background-color: #3e8e41;
  transform: translateY(0); /* 点击时恢复原位 */
}

button:disabled {
  background-color: #cccccc;
  cursor: not-allowed;
  opacity: 0.8;
}

.error {
  color: #e74c3c; /* 更明显的错误颜色 */
  text-align: center;
  margin-top: 1.5rem; /* 调整顶部间距 */
  font-size: 1rem;
  font-weight: 500;
}
</style> 