import axios from 'axios'

const http = axios.create({ baseURL: '/', timeout: 120_000 })

export const cryptoApi = {
  demoCaesar:    (key = 13) =>  http.post(`/api/crypto/caesar/demo?key=${key}`),
  demoVigenere:  ()         =>  http.post('/api/crypto/vigenere/demo'),
  demoRailFence: (r = 3)   =>  http.post(`/api/crypto/rail_fence/demo?rails=${r}`),
  demoRSA:       ()         =>  http.post('/api/crypto/rsa/demo'),
  ciphers:       ()         =>  http.get('/api/crypto/ciphers'),
}

export const reconApi = {
  tcpScan:  (host: string, pg = 'top_20') =>
    http.post('/api/recon/scan/tcp', { host, port_group: pg, timing: 'normal', method: 'connect' }),
  banner:   (host: string, ports: number[]) =>
    http.post('/api/recon/banner', { host, ports }),
  os:       (host: string) => http.post('/api/recon/os', { host }),
  stealth:  (host: string) => http.post('/api/recon/stealth', { host, mode: 'compare' }),
  full:     (host: string) => http.post('/api/recon/full', { host }),
}

export const dosApi = {
  status:   ()              => http.get('/api/dos/status'),
  httpFlood:(url: string, rps = 50, dur = 20) =>
    http.post('/api/dos/http-flood', { target_url: url, requests_per_second: rps, duration_seconds: dur }),
  slowloris:(host: string)  =>
    http.post('/api/dos/slowloris', { target_host: host, target_port: 80, max_connections: 50, duration_seconds: 30 }),
  credStuff:(url: string)   =>
    http.post('/api/dos/credential-stuff', { target_url: url, login_path: '/login', attempts_per_second: 5, duration_seconds: 30 }),
  baseline: (url: string)   =>
    http.post('/api/dos/baseline', { target_url: url, duration_seconds: 30, avg_requests_per_minute: 10 }),
}

export const valApi = {
  status:    () => http.get('/api/validate/status'),
  httpFlood: (dur = 20, rate = 50) =>
    http.post('/api/validate/http-flood', { sentinel_url: 'http://localhost:8000', duration_seconds: dur, rate }),
  credStuff: (dur = 20) =>
    http.post('/api/validate/credential-stuff', { sentinel_url: 'http://localhost:8000', duration_seconds: dur, rate: 5 }),
  enumeration:(dur = 20) =>
    http.post('/api/validate/enumeration', { sentinel_url: 'http://localhost:8000', duration_seconds: dur, rate: 10 }),
  fullSuite: () =>
    http.post('/api/validate/full-suite', null, {
      params: { sentinel_url: 'http://localhost:8000', duration_each: 20 }
    }),
  matrix:    () => http.get('/api/validate/matrix'),
}