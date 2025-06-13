import { mount } from '@vue/test-utils'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import Login from '../Login.vue'
import { ElMessage } from 'element-plus'

// 模拟 Element Plus 的消息组件
vi.mock('element-plus', () => ({
  ElMessage: {
    error: vi.fn(),
    success: vi.fn()
  }
}))

describe('Login.vue', () => {
  let wrapper

  beforeEach(() => {
    wrapper = mount(Login)
  })

  it('默认用户名和密码正确', () => {
    expect(wrapper.vm.username).toBe('admin')
    expect(wrapper.vm.password).toBe('password')
  })

  it('登录表单验证', async () => {
    // 清空用户名和密码
    await wrapper.setData({ username: '', password: '' })
    
    // 触发登录
    await wrapper.vm.handleLogin()
    
    // 验证错误消息
    expect(ElMessage.error).toHaveBeenCalled()
  })

  it('成功获取公钥', async () => {
    // 模拟获取公钥的响应
    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ public_key: 'test_public_key' })
      })
    )

    await wrapper.vm.getPublicKey()
    expect(wrapper.vm.publicKey).toBe('test_public_key')
  })

  it('加密用户凭据', async () => {
    // 设置公钥
    await wrapper.setData({ publicKey: 'test_public_key' })
    
    // 加密数据
    const encrypted = await wrapper.vm.encryptCredentials()
    expect(encrypted).toBeDefined()
  })

  it('处理登录响应', async () => {
    // 模拟登录成功
    await wrapper.vm.handleLoginResponse({ token: 'test_token' })
    expect(ElMessage.success).toHaveBeenCalled()
    
    // 模拟登录失败
    await wrapper.vm.handleLoginResponse(null)
    expect(ElMessage.error).toHaveBeenCalled()
  })
}) 