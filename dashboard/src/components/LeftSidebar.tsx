import { useState } from 'react'
import { useStore } from '../store/appStore'
import { cryptoApi, reconApi, dosApi, valApi } from '../hooks/useApi'

interface Cmd { label: string; desc: string; color: string; fn: () => Promise<any> }
interface Group { name: string; icon: string; accent: string; cmds: Cmd[] }

const LAB   = '172.25.0.12'
const LABH  = `http://${LAB}`
const VIGL  = 'http://localhost:8000'

export default function LeftSidebar() {
  const { addLine, setRunning, setResult, addVal } = useStore()
  const [open,  setOpen]  = useState<string>('crypto')
  const [busy,  setBusy]  = useState(false)

  const run = async (label: string, fn: () => Promise<any>) => {
    if (busy) return
    setBusy(true); setRunning(true, label)
    addLine('EXEC', `Initializing ${label}…`, 'system')
    try {
      const { data } = await fn()
      setResult(data)
      addLine('OK', `${label} completed`, 'success')

      // extra readable lines
      if (data?.final_answer) {
        addLine('DATA', `Key: ${data.final_answer.key}  Conf: ${data.final_answer.confidence}  Score: ${data.final_answer.score}`, 'info')
      }
      if (data?.attack?.decrypted_value !== undefined) {
        addLine('RSA', `Cracked! Recovered value: ${data.attack.decrypted_value}  (${data.attack.time_taken_ms}ms)`, 'success')
      }
      if (data?.open_ports) {
        addLine('SCAN', `Open: [${data.open_ports.join(', ')}]  Scanned ${data.ports_scanned} ports  ${data.scan_duration_seconds}s`, 'info')
      }
      if (data?.actual_rps) {
        addLine('FLOOD', `Rate: ${data.actual_rps} RPS  Sent: ${data.total_requests_sent}  OK: ${data.success_rate_pct}%`, 'attack')
      }
      if (data?.sentinel_connected !== undefined) {
        addLine('VIGIL', `Sentinel ${data.sentinel_connected ? 'ONLINE ✓' : 'OFFLINE ✗'}  port 8000`, data.sentinel_connected ? 'success' : 'error')
      }
      if (data?.final_metrics) {
        addLine('VALID', `Detect: ${data.final_metrics.detection_rate_pct}%  BlockAvg: ${data.final_metrics.avg_block_rate_pct}%`, 'validation')
        addVal(data)
      }
    } catch (e: any) {
      addLine('ERR', `${label}: ${e.message}`, 'error')
    } finally {
      setBusy(false); setRunning(false)
    }
  }

  const groups: Group[] = [
    {
      name: 'crypto', icon: '🔐', accent: '#bf5af2',
      cmds: [
        { label:'caesar',    desc:'Brute all 26 keys + frequency',  color:'text-h-purple', fn:() => cryptoApi.demoCaesar(13) },
        { label:'vigenere',  desc:'Kasiski examination',             color:'text-h-purple', fn:() => cryptoApi.demoVigenere() },
        { label:'railfence', desc:'Rail fence reconstruction',       color:'text-h-purple', fn:() => cryptoApi.demoRailFence(3) },
        { label:'rsa',       desc:'Factor small primes',            color:'text-h-purple', fn:() => cryptoApi.demoRSA() },
      ]
    },
    {
      name: 'recon', icon: '🔍', accent: '#00d4ff',
      cmds: [
        { label:'tcp-scan',  desc:'Top-20 port scan',               color:'text-h-cyan',   fn:() => reconApi.tcpScan(LAB) },
        { label:'banner',    desc:'Service version grab',           color:'text-h-cyan',   fn:() => reconApi.banner(LAB, [80,443,22,8080]) },
        { label:'os-detect', desc:'TTL + window fingerprint',       color:'text-h-cyan',   fn:() => reconApi.os(LAB) },
        { label:'stealth',   desc:'Normal vs slow scan compare',    color:'text-h-cyan',   fn:() => reconApi.stealth(LAB) },
        { label:'full-recon',desc:'Complete pipeline',              color:'text-h-cyan',   fn:() => reconApi.full(LAB) },
      ]
    },
    {
      name: 'dos', icon: '💥', accent: '#ff073a',
      cmds: [
        { label:'http-flood', desc:'50 RPS × 20s GET flood',        color:'text-h-red',    fn:() => dosApi.httpFlood(LABH, 50, 20) },
        { label:'slowloris',  desc:'Connection exhaustion',          color:'text-h-red',    fn:() => dosApi.slowloris(LAB) },
        { label:'cred-stuff', desc:'Login brute simulation',        color:'text-h-red',    fn:() => dosApi.credStuff(LABH) },
        { label:'baseline',   desc:'Normal traffic generation',     color:'text-h-gdim',   fn:() => dosApi.baseline(LABH) },
      ]
    },
    {
      name: 'validate', icon: '✅', accent: '#00ff41',
      cmds: [
        { label:'status',     desc:'Check Sentinel status',         color:'text-h-green',  fn:() => valApi.status() },
        { label:'flood-test', desc:'Validate flood detection',      color:'text-h-green',  fn:() => valApi.httpFlood(20, 50) },
        { label:'cred-test',  desc:'Validate cred detection',       color:'text-h-green',  fn:() => valApi.credStuff(20) },
        { label:'enum-test',  desc:'Validate enum detection',       color:'text-h-green',  fn:() => valApi.enumeration(20) },
        { label:'full-suite', desc:'Run ALL 3 tests + CSV',         color:'text-h-yellow', fn:() => valApi.fullSuite() },
      ]
    },
  ]

  return (
    <div className="w-52 bg-h-panel border-r border-h-border flex flex-col flex-shrink-0 overflow-hidden">
      {/* header */}
      <div className="px-3 py-2 border-b border-h-border">
        <span className="text-3xs text-h-muted tracking-widest">ATTACK MODULES</span>
      </div>

      {/* groups */}
      <div className="flex-1 overflow-y-auto">
        {groups.map(g => (
          <div key={g.name}>
            {/* group header */}
            <button
              onClick={() => setOpen(open === g.name ? '' : g.name)}
              className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-h-surface transition-colors text-left"
            >
              <span className="text-xs">{g.icon}</span>
              <span className="text-2xs font-bold tracking-wider" style={{ color: g.accent }}>
                {g.name.toUpperCase()}
              </span>
              <span className="ml-auto text-3xs text-h-dark">
                {open === g.name ? '▾' : '▸'}
              </span>
            </button>

            {/* commands */}
            {open === g.name && (
              <div className="animate-slideup">
                {g.cmds.map(c => (
                  <button
                    key={c.label}
                    onClick={() => run(c.label, c.fn)}
                    disabled={busy}
                    className="cmd-btn w-full text-left px-3 py-1 pl-7 flex items-start gap-2 disabled:opacity-30 disabled:cursor-not-allowed"
                  >
                    <span className={`text-3xs mt-0.5 ${c.color} opacity-50`}>▸</span>
                    <div className="min-w-0">
                      <div className={`text-2xs ${c.color}`}>{c.label}</div>
                      <div className="text-3xs text-h-dark truncate">{c.desc}</div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* footer */}
      <div className="px-3 py-1.5 border-t border-h-border">
        <span className="text-3xs text-h-dark">
          {busy
            ? <span className="text-h-yellow animate-pulse">⚡ EXECUTING…</span>
            : `${groups.reduce((a, g) => a + g.cmds.length, 0)} commands ready`
          }
        </span>
      </div>
    </div>
  )
}