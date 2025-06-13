<template>
  <div class="encrypt-container">
    <div class="encrypt-box">
      <h2>加密数据</h2>
      <div class="form-group">
        <label for="message">输入内容</label>
        <input
          type="text"
          id="message"
          v-model="message"
          placeholder="请输入要加密的内容"
        />
      </div>
      <button @click="handleEncrypt" :disabled="loading">
        {{ loading ? '处理中...' : '发送请求' }}
      </button>
      <div class="result-window">
        <div v-if="encryptedResult" class="result-section">
          <strong>加密结果：</strong>
          <div class="result-content">
            <p><strong>解密后的AES密钥：</strong>{{ encryptedResult.decrypted_key }}</p>
            <p><strong>收到的加密数据：</strong>{{ encryptedResult.encrypted_data }}</p>
            <p><strong>解密后的数据：</strong>{{ encryptedResult.decrypted_data }}</p>
          </div>
        </div>
        <div class="info-item">
          <strong>当前使用的公钥：</strong>
          <p>{{ publicKey }}</p>
        </div>
      </div>
      <p v-if="error" class="error">{{ error }}</p>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, computed } from 'vue'
import axios from 'axios'
import JSEncrypt from 'jsencrypt'
import CryptoJS from 'crypto-js'

export default {
  name: 'EncryptForm',
  setup() {
    const message = ref('Hello World')
    const loading = ref(false)
    const error = ref('')
    const encryptedResult = ref(null)
    const publicKey = ref('')

    const displayEncryptedResult = computed(() => {
      if (!encryptedResult.value) return ''
      return encryptedResult.value
    })

    const getPublicKey = async () => {
      try {
        // 从localStorage获取公钥
        const savedPublicKey = localStorage.getItem('publicKey')
        if (savedPublicKey) {
          publicKey.value = savedPublicKey
          console.log('使用保存的公钥:', publicKey.value)
          return
        }

        // 如果没有保存的公钥，则从服务器获取
        const response = await axios.get(`${import.meta.env.VITE_API_BASE_URL}/public-key`)
        publicKey.value = response.data.public_key
        localStorage.setItem('publicKey', publicKey.value)
        console.log('获取到的公钥:', publicKey.value)
      } catch (err) {
        error.value = '获取公钥失败'
        console.error('获取公钥失败:', err)
      }
    }

    const handleEncrypt = async () => {
      loading.value = true
      error.value = ''

      try {
        // 获取token
        const token = sessionStorage.getItem('token')
        if (!token) {
          throw new Error('未登录或登录已过期')
        }

        // 生成随机密钥
        const aesKey = generateRandomKey()
        console.log('生成的AES密钥:', aesKey)
        
        // 使用 AES 加密数据
        const encryptedData = encryptWithAES(message.value, aesKey)
        console.log('加密后的数据:', encryptedData)
        
        // 使用 RSA 加密 AES 密钥
        const encryptedKey = encryptWithRSA(aesKey)
        console.log('加密后的AES密钥:', encryptedKey)

        const requestData = {
          message: encryptedData
        }
        console.log('请求数据:', requestData)
        console.log('请求头:', {
          'Content-Type': 'application/json',
          'X-Encrypted-Key': encryptedKey,
          'Authorization': `Bearer ${token}`
        })

        const response = await axios.post(`${import.meta.env.VITE_API_BASE_URL}/encrypt`, requestData, {
          headers: {
            'Content-Type': 'application/json',
            'X-Encrypted-Key': encryptedKey,
            'Authorization': `Bearer ${token}`
          }
        })

        console.log('服务器响应:', response.data)

        if (response.status === 200) {
          encryptedResult.value = {
            decrypted_key: response.data.decrypted_key,
            encrypted_data: response.data.encrypted_data,
            decrypted_data: response.data.decrypted_data
          }
          console.log('设置的结果数据:', encryptedResult.value)
        } else {
          throw new Error(response.data.error || '加密失败')
        }
      } catch (err) {
        error.value = err.message || '加密失败，请重试'
        console.error('加密错误:', err)
      } finally {
        loading.value = false
      }
    }

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

    onMounted(() => {
      getPublicKey()
    })

    return {
      message,
      loading,
      error,
      encryptedResult,
      displayEncryptedResult,
      handleEncrypt,
      publicKey
    }
  }
}
</script>

<style scoped>
.encrypt-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  padding: 2rem;
}

.encrypt-box {
  background: rgba(255, 255, 255, 0.95);
  padding: 2.5rem 2rem;
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
  width: 100%;
  max-width: 600px;
  box-sizing: border-box;
}

h2 {
  text-align: center;
  color: #333;
  margin-bottom: 2rem;
  font-size: 2rem;
  font-weight: 600;
}

.form-group {
  margin-bottom: 1.5rem;
}

label {
  display: block;
  margin-bottom: 0.6rem;
  color: #555;
  font-weight: 500;
}

input {
  width: 100%;
  padding: 0.9rem 1rem;
  border: 1px solid #ccc;
  border-radius: 6px;
  font-size: 1.1rem;
  transition: border-color 0.3s ease, box-shadow 0.3s ease;
}

input:focus {
  border-color: #4CAF50;
  box-shadow: 0 0 0 3px rgba(76, 175, 80, 0.2);
  outline: none;
}

button {
  width: 100%;
  padding: 1rem;
  background-color: #4CAF50;
  color: white;
  border: none;
  border-radius: 6px;
  font-size: 1.2rem;
  cursor: pointer;
  transition: background-color 0.3s ease, transform 0.2s ease;
  font-weight: 600;
  margin-top: 1rem;
}

button:hover {
  background-color: #45a049;
  transform: translateY(-2px);
}

button:active {
  background-color: #3e8e41;
  transform: translateY(0);
}

button:disabled {
  background-color: #cccccc;
  cursor: not-allowed;
  opacity: 0.8;
}

.result-window {
  margin: 1.5rem 0;
  padding: 1.5rem;
  background-color: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #dee2e6;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}

.info-item {
  margin-bottom: 1.5rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid #dee2e6;
}

.info-item:last-child {
  margin-bottom: 0;
  padding-bottom: 0;
  border-bottom: none;
}

.info-item strong {
  display: block;
  color: #333;
  margin-bottom: 0.5rem;
  font-size: 0.95rem;
  font-weight: 600;
}

.info-item p {
  margin: 0;
  color: #666;
  word-break: break-all;
  font-family: monospace;
  font-size: 0.9rem;
  line-height: 1.4;
  padding: 0.75rem;
  background-color: #fff;
  border-radius: 4px;
  border: 1px solid #e0e0e0;
}

.result-section {
  margin-top: 1rem;
}

.result-section strong {
  display: block;
  color: #333;
  margin-bottom: 0.5rem;
  font-size: 0.95rem;
  font-weight: 600;
}

.result-content {
  background-color: #fff;
  border-radius: 4px;
  border: 1px solid #e0e0e0;
  padding: 0.75rem;
}

.result-content p {
  margin: 0 0 0.5rem 0;
  color: #666;
  word-break: break-all;
  font-family: monospace;
  font-size: 0.9rem;
  line-height: 1.4;
}

.result-content p:last-child {
  margin-bottom: 0;
}

.result-content p strong {
  display: inline;
  color: #333;
  margin-right: 0.5rem;
  font-weight: 600;
}

.error {
  color: #e74c3c;
  text-align: center;
  margin-top: 1rem;
  font-size: 1rem;
  font-weight: 500;
  padding: 0.75rem;
  background-color: #fdf3f2;
  border-radius: 4px;
  border: 1px solid #fadbd8;
}
</style> 