<template>
  <div class="login-container">
    <div class="login-box">
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
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import JSEncrypt from 'jsencrypt'
import axios from 'axios'

export default {
  name: 'Login',
  setup() {
    const username = ref('admin')
    const password = ref('password')
    const loading = ref(false)
    const error = ref('')
    const publicKey = ref('')

    const getPublicKey = async () => {
      try {
        const response = await axios.get('http://localhost:8000/public-key')
        publicKey.value = response.data.public_key
      } catch (err) {
        error.value = '获取公钥失败'
        console.error('获取公钥失败:', err)
      }
    }

    const encryptData = (data) => {
      const encrypt = new JSEncrypt()
      encrypt.setPublicKey(publicKey.value)
      return encrypt.encrypt(data)
    }

    const handleLogin = async () => {
      if (!publicKey.value) {
        error.value = '系统未就绪，请稍后重试'
        return
      }

      loading.value = true
      error.value = ''

      try {
        const encryptedUsername = encryptData(username.value)
        const encryptedPassword = encryptData(password.value)

        const response = await axios.post('http://localhost:8000/login', {
          encrypted_username: encryptedUsername,
          encrypted_password: encryptedPassword
        })

        if (response.data.status === 'success') {
          alert('登录成功！')
          // 这里可以添加登录成功后的处理逻辑
        }
      } catch (err) {
        error.value = err.response?.data?.detail || '登录失败，请重试'
      } finally {
        loading.value = false
      }
    }

    onMounted(() => {
      getPublicKey()
    })

    return {
      username,
      password,
      loading,
      error,
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
  background-color: #f5f5f5;
}

.login-box {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-width: 400px;
}

h2 {
  text-align: center;
  color: #333;
  margin-bottom: 1.5rem;
}

.form-group {
  margin-bottom: 1rem;
}

label {
  display: block;
  margin-bottom: 0.5rem;
  color: #666;
}

input {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
}

button {
  width: 100%;
  padding: 0.75rem;
  background-color: #4CAF50;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  transition: background-color 0.3s;
}

button:hover {
  background-color: #45a049;
}

button:disabled {
  background-color: #cccccc;
  cursor: not-allowed;
}

.error {
  color: #ff4444;
  text-align: center;
  margin-top: 1rem;
}
</style> 