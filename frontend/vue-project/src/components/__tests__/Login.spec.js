import { mount } from '@vue/test-utils'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import Login from '../Login.vue'
import axios from 'axios'

// 模拟 axios
vi.mock('axios')

describe('Login.vue', () => {
  let wrapper

  beforeEach(() => {
    // 重置所有模拟
    vi.clearAllMocks()
    
    // 创建组件实例
    wrapper = mount(Login)
  })

  it('默认显示用户名和密码', () => {
    expect(wrapper.find('input[type="text"]').element.value).toBe('admin')
    expect(wrapper.find('input[type="password"]').element.value).toBe('password')
  })

  it('成功获取公钥', async () => {
    const mockPublicKey = '-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----'
    axios.get.mockResolvedValueOnce({ data: { public_key: mockPublicKey } })

    await wrapper.vm.getPublicKey()

    expect(axios.get).toHaveBeenCalledWith('http://localhost:8000/public-key')
    expect(wrapper.vm.publicKey).toBe(mockPublicKey)
    expect(wrapper.vm.error).toBe('')
  })

  it('获取公钥失败时显示错误', async () => {
    axios.get.mockRejectedValueOnce(new Error('获取公钥失败'))

    await wrapper.vm.getPublicKey()

    expect(wrapper.vm.error).toBe('获取公钥失败')
  })

  it('成功登录', async () => {
    // 设置公钥
    const mockPublicKey = '-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----'
    wrapper.vm.publicKey = mockPublicKey

    // 模拟加密后的数据
    const mockEncryptedUsername = 'encrypted_username'
    const mockEncryptedPassword = 'encrypted_password'

    // 模拟 JSEncrypt
    const mockJSEncrypt = {
      setPublicKey: vi.fn(),
      encrypt: vi.fn()
        .mockReturnValueOnce(mockEncryptedUsername)
        .mockReturnValueOnce(mockEncryptedPassword)
    }
    vi.stubGlobal('JSEncrypt', vi.fn(() => mockJSEncrypt))

    // 模拟登录响应
    axios.post.mockResolvedValueOnce({ data: { status: 'success' } })

    // 触发登录
    await wrapper.vm.handleLogin()

    // 验证请求
    expect(axios.post).toHaveBeenCalledWith('http://localhost:8000/login', {
      encrypted_username: mockEncryptedUsername,
      encrypted_password: mockEncryptedPassword
    })

    // 验证状态
    expect(wrapper.vm.loading).toBe(false)
    expect(wrapper.vm.error).toBe('')
  })

  it('登录失败时显示错误', async () => {
    // 设置公钥
    const mockPublicKey = '-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----'
    wrapper.vm.publicKey = mockPublicKey

    // 模拟加密后的数据
    const mockEncryptedUsername = 'encrypted_username'
    const mockEncryptedPassword = 'encrypted_password'

    // 模拟 JSEncrypt
    const mockJSEncrypt = {
      setPublicKey: vi.fn(),
      encrypt: vi.fn()
        .mockReturnValueOnce(mockEncryptedUsername)
        .mockReturnValueOnce(mockEncryptedPassword)
    }
    vi.stubGlobal('JSEncrypt', vi.fn(() => mockJSEncrypt))

    // 模拟登录失败
    axios.post.mockRejectedValueOnce({
      response: {
        data: {
          detail: '登录失败'
        }
      }
    })

    // 触发登录
    await wrapper.vm.handleLogin()

    // 验证错误信息
    expect(wrapper.vm.error).toBe('登录失败')
    expect(wrapper.vm.loading).toBe(false)
  })

  it('系统未就绪时显示错误', async () => {
    // 不设置公钥
    wrapper.vm.publicKey = ''

    // 触发登录
    await wrapper.vm.handleLogin()

    // 验证错误信息
    expect(wrapper.vm.error).toBe('系统未就绪，请稍后重试')
    expect(wrapper.vm.loading).toBe(false)
  })

  it('登录按钮在加载时禁用', async () => {
    wrapper.vm.loading = true
    await wrapper.vm.$nextTick()

    const button = wrapper.find('button')
    expect(button.attributes('disabled')).toBeDefined()
    expect(button.text()).toBe('登录中...')
  })
}) 