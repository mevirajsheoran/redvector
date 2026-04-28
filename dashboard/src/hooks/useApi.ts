import axios from 'axios'

const http = axios.create({ baseURL: '/', timeout: 120000 })

// Vigil runs on Windows
const VIGIL = 'http://172.28.64.1:8000'

// Docker targets - using the ones that actually work
const HTTP_TARGET  = 'http://172.25.0.13'   // Python HTTP server port 80
const NGINX_TARGET = 'http://172.25.0.12'   // nginx port 80
const LAB_IP       = '172.25.0.13'          // Python HTTP server IP

export const cryptoApi = {
  demoCaesar:    (key = 13) => http.post(`/api/crypto/caesar/demo?key=${key}`),
  demoVigenere:  ()         => http.post('/api/crypto/vigenere/demo'),
  demoRailFence: (r = 3)    => http.post(`/api/crypto/rail_fence/demo?rails=${r}`),
  demoRSA:       ()         => http.post('/api/crypto/rsa/demo'),
}

export const reconApi = {
  tcpScan:  (host: string) =>
    http.post('/api/recon/scan/tcp', { host, port_group: 'top_20', timing: 'normal', method: 'connect' }),
  banner:   (host: string, ports: number[]) =>
    http.post('/api/recon/banner', { host, ports }),
  os:       (host: string) => http.post('/api/recon/os', { host }),
  stealth:  (host: string) => http.post('/api/recon/stealth', { host, mode: 'compare' }),
  full:     (host: string) => http.post('/api/recon/full', { host }),
}

export const dosApi = {
  // HTTP flood against Python HTTP server (port 80 OPEN)
  httpFlood: (url = HTTP_TARGET, rps = 50, dur = 20) =>
    http.post('/api/dos/http-flood', {
      target_url: url,
      requests_per_second: rps,
      duration_seconds: dur
    }),

  // Slowloris against Python HTTP server (port 80 OPEN)
  slowloris: (host = LAB_IP) =>
    http.post('/api/dos/slowloris', {
      target_host: host,
      target_port: 80,
      max_connections: 50,
      duration_seconds: 30
    }),

  // Credential stuffing against Vigil (always reachable)
  credStuff: (url = `${VIGIL}/v1/analyze`) =>
    http.post('/api/dos/credential-stuff', {
      target_url: VIGIL,
      login_path: '/v1/analyze',
      attempts_per_second: 5,
      duration_seconds: 30
    }),

  // Baseline normal traffic against Python HTTP server
  baseline: (url = HTTP_TARGET) =>
    http.post('/api/dos/baseline', {
      target_url: url,
      duration_seconds: 30,
      avg_requests_per_minute: 10
    }),
}

export const valApi = {
  status:      () => http.get('/api/validate/status'),
  httpFlood:   (dur = 30, rate = 100) =>
    http.post('/api/validate/http-flood', {
      sentinel_url: VIGIL,
      duration_seconds: dur,
      rate
    }),
  credStuff:   (dur = 30) =>
    http.post('/api/validate/credential-stuff', {
      sentinel_url: VIGIL,
      duration_seconds: dur,
      rate: 10
    }),
  enumeration: (dur = 30) =>
    http.post('/api/validate/enumeration', {
      sentinel_url: VIGIL,
      duration_seconds: dur,
      rate: 15
    }),
  fullSuite:   () =>
    http.post('/api/validate/full-suite', null, {
      params: { sentinel_url: VIGIL, duration_each: 30 }
    }),
}
