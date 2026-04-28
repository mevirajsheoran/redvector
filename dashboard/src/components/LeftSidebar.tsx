import { useState } from 'react'
import { useStore } from '../store/appStore'
import { cryptoApi, reconApi, dosApi, valApi } from '../hooks/useApi'

interface Cmd { label: string; desc: string; color: string; fn: () => Promise<any> }
interface Group { name: string; icon: string; color: string; cmds: Cmd[] }

// Docker lab targets
const HTTP_TARGET  = 'http://172.25.0.13'  // Python HTTP (OPEN port 80)
const NGINX_TARGET = 'http://172.25.0.12'  // nginx (OPEN port 80)
const HTTP_IP      = '172.25.0.13'
const NGINX_IP     = '172.25.0.12'

export default function LeftSidebar() {
  const { addLine, setRunning, setResult, addVal } = useStore()
  const [open, setOpen] = useState('crypto')
  const [busy, setBusy] = useState(false)

  const run = async (label: string, fn: () => Promise<any>) => {
    if (busy) return
    setBusy(true)
    setRunning(true, label)
    addLine('EXEC', `Starting ${label}...`, 'system')
    try {
      const { data } = await fn()
      setResult(data)
      addLine('OK', `${label} completed`, 'success')

      // Parse and display key results
      if (data?.final_answer) {
        addLine('DATA', `Key: ${data.final_answer.key}  Conf: ${data.final_answer.confidence}  Score: ${data.final_answer.score}`, 'info')
      }
      if (data?.attack?.decrypted_value !== undefined) {
        addLine('RSA', `Cracked! Value: ${data.attack.decrypted_value} (${data.attack.time_taken_ms}ms)`, 'success')
      }
      if (data?.open_ports) {
        addLine('SCAN', `Open ports: [${data.open_ports.join(', ')}]  Duration: ${data.scan_duration_seconds}s`, 'info')
      }
      if (data?.actual_rps !== undefined) {
        addLine('FLOOD', `Rate: ${data.actual_rps} RPS  Sent: ${data.total_requests_sent}  Success: ${data.success_rate_pct}%`, 'attack')
      }
      if (data?.sentinel_connected !== undefined) {
        addLine('VIGIL', `Sentinel ${data.sentinel_connected ? 'ONLINE ✓' : 'OFFLINE ✗'}  Requests: ${data.current_stats?.total_requests || 0}`, data.sentinel_connected ? 'success' : 'error')
      }
      if (data?.sentinel_detected !== undefined) {
        addLine('VALID', `Detected: ${data.sentinel_detected ? 'YES ✓' : 'NO ✗'}  Blocks: ${data.blocks_triggered}  Block%: ${data.block_rate_pct}%`, data.sentinel_detected ? 'success' : 'warning')
      }
      if (data?.final_metrics) {
        addLine('SUITE', `Detection: ${data.final_metrics.detection_rate_pct}%  AvgBlock: ${data.final_metrics.avg_block_rate_pct}%  Latency: ${data.final_metrics.avg_detection_latency_s}s`, 'validation')
        addVal(data)
      }
      if (data?.peak_connections_established !== undefined) {
        addLine('SLOW', `Connections: ${data.peak_connections_established}  Attempts: ${data.stats?.connections_attempted}  Duration: ${data.duration_seconds}s`, 'attack')
      }
      if (data?.total_attempts !== undefined) {
        addLine('CRED', `Attempts: ${data.total_attempts}  Rate: ${data.actual_aps}/s  Duration: ${data.duration_seconds}s`, 'attack')
      }
    } catch (e: any) {
      const msg = e?.response?.data?.detail || e?.message || String(e)
      addLine('ERR', `${label} failed: ${msg}`, 'error')
    } finally {
      setBusy(false)
      setRunning(false)
    }
  }

  const groups: Group[] = [
    {
      name: 'crypto', icon: '🔐', color: '#bf5af2',
      cmds: [
        { label: 'caesar',    desc: 'Brute force 26 keys + freq',  color: '#bf5af2', fn: () => cryptoApi.demoCaesar(13) },
        { label: 'vigenere',  desc: 'Kasiski examination',         color: '#bf5af2', fn: () => cryptoApi.demoVigenere() },
        { label: 'railfence', desc: 'Rail fence reconstruction',   color: '#bf5af2', fn: () => cryptoApi.demoRailFence(3) },
        { label: 'rsa',       desc: 'Factor small primes',        color: '#bf5af2', fn: () => cryptoApi.demoRSA() },
      ],
    },
    {
      name: 'recon', icon: '🔍', color: '#00d4ff',
      cmds: [
        { label: 'scan-nginx',   desc: `Port scan ${NGINX_IP}`,    color: '#00d4ff', fn: () => reconApi.tcpScan(NGINX_IP) },
        { label: 'scan-http',    desc: `Port scan ${HTTP_IP}`,     color: '#00d4ff', fn: () => reconApi.tcpScan(HTTP_IP) },
        { label: 'banner-http',  desc: 'Banner grab port 80',      color: '#00d4ff', fn: () => reconApi.banner(HTTP_IP, [80, 22, 21]) },
        { label: 'os-detect',    desc: 'OS fingerprint nginx',     color: '#00d4ff', fn: () => reconApi.os(NGINX_IP) },
        { label: 'stealth',      desc: 'Normal vs slow compare',   color: '#00d4ff', fn: () => reconApi.stealth(HTTP_IP) },
        { label: 'full-recon',   desc: `Full pipeline ${HTTP_IP}`, color: '#00d4ff', fn: () => reconApi.full(HTTP_IP) },
      ],
    },
    {
      name: 'dos', icon: '💥', color: '#ff073a',
      cmds: [
        { label: 'http-flood',  desc: `50 RPS → ${HTTP_IP}:80`,   color: '#ff073a', fn: () => dosApi.httpFlood(HTTP_TARGET, 50, 20) },
        { label: 'http-flood-v',desc: `100 RPS → Vigil`,          color: '#ff073a', fn: () => dosApi.httpFlood('http://172.28.64.1:8000', 100, 20) },
        { label: 'slowloris',   desc: `50 conns → ${HTTP_IP}:80`, color: '#ff073a', fn: () => dosApi.slowloris(HTTP_IP) },
        { label: 'cred-stuff',  desc: `Login bruteforce → Vigil`, color: '#ff073a', fn: () => dosApi.credStuff() },
        { label: 'baseline',    desc: `Normal traffic → ${HTTP_IP}`, color: '#00cc33', fn: () => dosApi.baseline(HTTP_TARGET) },
      ],
    },
    {
      name: 'validate', icon: '✅', color: '#00ff41',
      cmds: [
        { label: 'status',     desc: 'Check Vigil connection',    color: '#00ff41', fn: () => valApi.status() },
        { label: 'flood-test', desc: '100 RPS × 30s vs Vigil',   color: '#00ff41', fn: () => valApi.httpFlood(30, 100) },
        { label: 'cred-test',  desc: 'Cred stuffing vs Vigil',   color: '#00ff41', fn: () => valApi.credStuff(30) },
        { label: 'enum-test',  desc: 'Enumeration vs Vigil',     color: '#00ff41', fn: () => valApi.enumeration(30) },
        { label: 'full-suite', desc: '▶ ALL 3 tests + CSV',      color: '#ffb800', fn: () => valApi.fullSuite() },
      ],
    },
  ]

  return (
    <div
      className="flex flex-col flex-shrink-0 overflow-hidden"
      style={{ width: 210, background: '#0a1018', borderRight: '1px solid #1a2744' }}
    >
      <div style={{ padding: '7px 12px', borderBottom: '1px solid #1a2744' }}>
        <span style={{ fontSize: 9, color: '#5a6f8a', letterSpacing: '0.1em' }}>ATTACK MODULES</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {groups.map(g => (
          <div key={g.name}>
            <button
              onClick={() => setOpen(open === g.name ? '' : g.name)}
              className="w-full flex items-center gap-2 text-left transition-colors"
              style={{
                padding: '6px 12px',
                background: open === g.name ? 'rgba(0,212,255,0.04)' : 'transparent',
                cursor: 'pointer', border: 'none',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,212,255,0.06)')}
              onMouseLeave={e => (e.currentTarget.style.background = open === g.name ? 'rgba(0,212,255,0.04)' : 'transparent')}
            >
              <span style={{ fontSize: 13 }}>{g.icon}</span>
              <span style={{ fontSize: 9, fontWeight: 700, color: g.color, letterSpacing: '0.08em' }}>
                {g.name.toUpperCase()}
              </span>
              <span style={{ marginLeft: 'auto', fontSize: 9, color: '#3a4f6a' }}>
                {open === g.name ? '▾' : '▸'}
              </span>
            </button>

            {open === g.name && (
              <div className="animate-slideup">
                {g.cmds.map(c => (
                  <button
                    key={c.label}
                    onClick={() => run(c.label, c.fn)}
                    disabled={busy}
                    className="cbtn w-full text-left"
                    style={{
                      padding: '4px 12px 4px 28px',
                      display: 'flex', alignItems: 'flex-start', gap: 8,
                      opacity: busy ? 0.35 : 1,
                      cursor: busy ? 'not-allowed' : 'pointer',
                      border: 'none', background: 'transparent',
                    }}
                  >
                    <span style={{ fontSize: 9, color: c.color, opacity: 0.5, marginTop: 2 }}>▸</span>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 10, color: c.color }}>{c.label}</div>
                      <div style={{ fontSize: 9, color: '#3a4f6a' }}>{c.desc}</div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      <div style={{ padding: '6px 12px', borderTop: '1px solid #1a2744' }}>
        <span style={{ fontSize: 9 }}>
          {busy
            ? <span style={{ color: '#ffb800' }} className="animate-pulse">⚡ RUNNING...</span>
            : <span style={{ color: '#3a4f6a' }}>{groups.reduce((a, g) => a + g.cmds.length, 0)} cmds ready</span>
          }
        </span>
      </div>
    </div>
  )
}
