/**
 * src/hooks/useApi.ts
 * Axios-based API client for ThreatForge backend
 */

import axios from 'axios'

// Base URL - uses Vite proxy, so /api/* goes to localhost:9000
const api = axios.create({
  baseURL: '/',
  timeout: 120000,  // 2 minutes - attacks take time
  headers: {
    'Content-Type': 'application/json'
  }
})

// API functions organized by module

export const cryptoApi = {
  listCiphers: () => api.get('/api/crypto/ciphers'),
  demoCaesar: (key: number = 13) => api.post(`/api/crypto/caesar/demo?key=${key}`),
  attackCaesar: (ciphertext: string) => api.post('/api/crypto/caesar/attack', { ciphertext }),
  demoVigenere: () => api.post('/api/crypto/vigenere/demo'),
  attackVigenere: (ciphertext: string) => api.post('/api/crypto/vigenere/attack', { ciphertext }),
  demoRSA: () => api.post('/api/crypto/rsa/demo'),
  demoRailFence: (rails: number = 3) => api.post(`/api/crypto/rail_fence/demo?rails=${rails}`)
}

export const reconApi = {
  listTargets: () => api.get('/api/recon/targets'),
  tcpScan: (host: string, portGroup: string = 'top_20') =>
    api.post('/api/recon/scan/tcp', { host, port_group: portGroup, timing: 'normal', method: 'connect' }),
  bannerGrab: (host: string, ports: number[]) =>
    api.post('/api/recon/banner', { host, ports }),
  osFingerprint: (host: string) =>
    api.post('/api/recon/os', { host }),
  stealthCompare: (host: string) =>
    api.post('/api/recon/stealth', { host, mode: 'compare' }),
  fullRecon: (host: string) =>
    api.post('/api/recon/full', { host })
}

export const dosApi = {
  status: () => api.get('/api/dos/status'),
  httpFlood: (target_url: string, rps: number = 50, duration: number = 20) =>
    api.post('/api/dos/http-flood', { target_url, requests_per_second: rps, duration_seconds: duration }),
  synFlood: (target_ip: string, port: number = 80, duration: number = 15) =>
    api.post('/api/dos/syn-flood', { target_ip, target_port: port, duration_seconds: duration, packets_per_second: 100 }),
  slowloris: (target_host: string, port: number = 80) =>
    api.post('/api/dos/slowloris', { target_host, target_port: port, max_connections: 50, duration_seconds: 30 }),
  credentialStuff: (target_url: string) =>
    api.post('/api/dos/credential-stuff', { target_url, login_path: '/login', attempts_per_second: 5, duration_seconds: 30 }),
  baseline: (target_url: string) =>
    api.post('/api/dos/baseline', { target_url, duration_seconds: 30, avg_requests_per_minute: 10 })
}

export const validateApi = {
  status: () => api.get('/api/validate/status'),
  httpFlood: (duration: number = 30, rate: number = 50) =>
    api.post('/api/validate/http-flood', { sentinel_url: 'http://localhost:8000', duration_seconds: duration, rate }),
  credentialStuff: (duration: number = 30) =>
    api.post('/api/validate/credential-stuff', { sentinel_url: 'http://localhost:8000', duration_seconds: duration, rate: 5 }),
  enumeration: (duration: number = 30) =>
    api.post('/api/validate/enumeration', { sentinel_url: 'http://localhost:8000', duration_seconds: duration, rate: 10 }),
  fullSuite: () =>
    api.post('/api/validate/full-suite', null, { params: { sentinel_url: 'http://localhost:8000', duration_each: 20 } }),
  getMatrix: () => api.get('/api/validate/matrix'),
  getSummary: () => api.get('/api/validate/summary'),
  benchmarkLatency: (attack_type: string = 'http_flood') =>
    api.post('/api/validate/benchmark/latency', { attack_type, rate: 50 }),
  benchmarkFPRate: () =>
    api.post('/api/validate/benchmark/fp-rate', null, { params: { duration: 60 } })
}

export default api
