import { useEffect, useState } from 'react'
import { useStore } from '../store/appStore'

export default function RightSidebar({ net }: { net: number[] }) {
  const { sentinelUp, validations, running } = useStore()
  const [tick,   setTick]   = useState(0)
  const [scores, setScores] = useState({ vel: 0.12, ano: 0.08, pat: 0.15, ovr: 0.10 })

  /* clock tick */
  useEffect(() => {
    const t = setInterval(() => setTick(p => p + 1), 1000)
    return () => clearInterval(t)
  }, [])

  /* threat score drift */
  useEffect(() => {
    const t = setInterval(() => {
      if (running) {
        setScores({
          vel: clamp(scores.vel + rand(-0.05, 0.12)),
          ano: clamp(scores.ano + rand(-0.04, 0.10)),
          pat: clamp(scores.pat + rand(-0.03, 0.09)),
          ovr: clamp(scores.ovr + rand(-0.04, 0.11)),
        })
      } else {
        setScores(s => ({
          vel: clamp(s.vel + rand(-0.03, 0.03)),
          ano: clamp(s.ano + rand(-0.02, 0.02)),
          pat: clamp(s.pat + rand(-0.02, 0.02)),
          ovr: clamp(s.ovr + rand(-0.02, 0.02)),
        }))
      }
    }, 1800)
    return () => clearInterval(t)
  }, [running, scores])

  const now     = new Date()
  const upMs    = performance.now()
  const upSec   = Math.floor(upMs / 1000)
  const hh      = pad(Math.floor(upSec / 3600))
  const mm      = pad(Math.floor((upSec % 3600) / 60))
  const ss      = pad(upSec % 60)

  const meters = [
    { label:'VELOCITY', v: scores.vel, color:'#00ff41' },
    { label:'ANOMALY',  v: scores.ano, color:'#00d4ff' },
    { label:'PATTERN',  v: scores.pat, color:'#bf5af2' },
    { label:'OVERALL',  v: scores.ovr, color:'#ffb800' },
  ]

  return (
    <div className="w-52 bg-h-panel border-l border-h-border flex flex-col flex-shrink-0 overflow-hidden">
      <div className="px-3 py-2 border-b border-h-border">
        <span className="text-3xs text-h-muted tracking-widest">SYSTEM MONITOR</span>
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-2 space-y-3">

        {/* clock */}
        <div className="panel p-2 text-center">
          <div className="text-3xs text-h-muted mb-0.5">SYS TIME</div>
          <div className="font-display text-xl text-h-cyan glow-cyan tracking-widest leading-none">
            {now.toLocaleTimeString('en-US', { hour12: false })}
          </div>
          <div className="text-3xs text-h-dark mt-1">UP {hh}:{mm}:{ss}</div>
        </div>

        {/* network sparkline */}
        <div className="panel p-2">
          <div className="text-3xs text-h-muted mb-1.5">NETWORK I/O</div>
          <div className="flex items-end gap-px h-8">
            {net.map((v, i) => (
              <div
                key={i}
                className="flex-1 rounded-t-sm transition-all duration-300"
                style={{
                  height: `${Math.max(v, 4)}%`,
                  background: v > 70 ? '#ff073a' : v > 40 ? '#ffb800' : '#00d4ff',
                  opacity: 0.3 + (i / net.length) * 0.7,
                }}
              />
            ))}
          </div>
          <div className="flex justify-between text-3xs text-h-dark mt-1">
            <span>0</span>
            <span>{net[net.length - 1] ?? 0} kB/s</span>
          </div>
        </div>

        {/* sentinel */}
        <div className={`panel p-2 ${sentinelUp ? 'nb-green' : 'nb-red'}`}>
          <div className="text-3xs text-h-muted mb-1">SENTINEL / VIGIL</div>
          <div className="flex items-center gap-2">
            <span className={`dot ${sentinelUp ? 'dot-green' : 'dot-red'}`} />
            <span className={`text-2xs font-bold ${sentinelUp ? 'glow-green' : 'glow-red'}`}>
              {sentinelUp ? 'ACTIVE' : 'OFFLINE'}
            </span>
          </div>
          <div className="text-3xs text-h-dark mt-1">
            {sentinelUp ? 'Monitoring :8000' : 'Start Vigil first'}
          </div>
        </div>

        {/* threat meters */}
        <div className="panel p-2">
          <div className="text-3xs text-h-muted mb-2">THREAT ANALYSIS</div>
          <div className="space-y-1.5">
            {meters.map(m => (
              <div key={m.label}>
                <div className="flex justify-between text-3xs mb-0.5">
                  <span className="text-h-muted">{m.label}</span>
                  <span style={{ color: m.color }} className="font-bold">{m.v.toFixed(2)}</span>
                </div>
                <div className="prog-wrap">
                  <div
                    className="prog-bar"
                    style={{ width: `${m.v * 100}%`, background: m.color, boxShadow: `0 0 6px ${m.color}80` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* validations */}
        {validations.length > 0 && (
          <div className="panel p-2">
            <div className="text-3xs text-h-muted mb-1.5">VALIDATION LOG</div>
            <div className="space-y-1">
              {validations.slice(-6).map((v: any, i: number) => {
                const ok = v?.sentinel_detected ?? (v?.final_metrics?.detection_rate_pct > 50)
                return (
                  <div key={i} className="flex items-center gap-1.5 text-3xs">
                    <span className={ok ? 'glow-green' : 'glow-red'}>{ok ? '✓' : '✗'}</span>
                    <span className="text-h-text flex-1 truncate">{v?.attack_type ?? 'suite'}</span>
                    <span className="text-h-muted">{v?.block_rate_pct ?? 0}%</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* module status */}
        <div className="panel p-2">
          <div className="text-3xs text-h-muted mb-1.5">MODULES</div>
          {([
            ['CRYPTO',   '#bf5af2', 'online'],
            ['RECON',    '#00d4ff', 'online'],
            ['DOS',      '#ff073a', 'online'],
            ['VALIDATE', '#00ff41', sentinelUp ? 'online' : 'warning'],
          ] as [string, string, string][]).map(([name, col, st]) => (
            <div key={name} className="flex items-center gap-2 text-3xs py-0.5">
              <span className={`dot dot-${st === 'online' ? 'green' : st === 'warning' ? 'yellow' : 'red'}`}
                style={{ width: 4, height: 4 }}
              />
              <span style={{ color: col }}>{name}</span>
              <span className="text-h-dark ml-auto">LOADED</span>
            </div>
          ))}
        </div>

      </div>
    </div>
  )
}

function rand(a: number, b: number) { return a + Math.random() * (b - a) }
function clamp(v: number, lo = 0.02, hi = 0.95) { return Math.min(hi, Math.max(lo, v)) }
function pad(n: number) { return n.toString().padStart(2, '0') }