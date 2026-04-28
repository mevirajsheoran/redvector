import { useEffect, useState } from 'react'
import { useStore } from '../store/appStore'

function pad(n: number) { return n.toString().padStart(2, '0') }
function rand(a: number, b: number) { return a + Math.random() * (b - a) }
function clamp(v: number, lo = 0.02, hi = 0.95) { return Math.min(hi, Math.max(lo, v)) }

export default function RightSidebar({ net }: { net: number[] }) {
  const { sentUp, vals, running } = useStore()
  const [now,    setNow]    = useState(new Date())
  const [scores, setScores] = useState({ vel:0.12, ano:0.08, pat:0.15, ovr:0.10 })

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    const t = setInterval(() => {
      setScores(s => ({
        vel: clamp(s.vel + rand(running ? -0.04 : -0.02, running ? 0.12 : 0.02)),
        ano: clamp(s.ano + rand(running ? -0.03 : -0.01, running ? 0.10 : 0.01)),
        pat: clamp(s.pat + rand(running ? -0.03 : -0.02, running ? 0.09 : 0.02)),
        ovr: clamp(s.ovr + rand(running ? -0.03 : -0.01, running ? 0.10 : 0.01)),
      }))
    }, 1800)
    return () => clearInterval(t)
  }, [running])

  const upSec = Math.floor(performance.now() / 1000)
  const hh = pad(Math.floor(upSec / 3600))
  const mm = pad(Math.floor((upSec % 3600) / 60))
  const ss = pad(upSec % 60)

  const meters = [
    { label: 'VELOCITY', v: scores.vel, color: '#00ff41' },
    { label: 'ANOMALY',  v: scores.ano, color: '#00d4ff' },
    { label: 'PATTERN',  v: scores.pat, color: '#bf5af2' },
    { label: 'OVERALL',  v: scores.ovr, color: '#ffb800' },
  ]

  const panelStyle = {
    background: 'linear-gradient(180deg,#0d1520,#0a1018)',
    border: '1px solid #1a2744',
    borderRadius: 3,
    padding: 8,
    position: 'relative' as const,
  }

  return (
    <div
      className="flex flex-col flex-shrink-0 overflow-hidden"
      style={{ width: 210, background: '#0a1018', borderLeft: '1px solid #1a2744' }}
    >
      {/* header */}
      <div style={{ padding: '7px 12px', borderBottom: '1px solid #1a2744' }}>
        <span style={{ fontSize: 9, color: '#5a6f8a', letterSpacing: '0.1em' }}>SYSTEM MONITOR</span>
      </div>

      <div className="flex-1 overflow-y-auto" style={{ padding: 8, gap: 10, display: 'flex', flexDirection: 'column' }}>

        {/* clock */}
        <div style={{ ...panelStyle, textAlign: 'center' }}>
          <div style={{ fontSize: 9, color: '#5a6f8a', marginBottom: 2 }}>SYS TIME</div>
          <div className="g-cyan font-display" style={{ fontSize: 22, letterSpacing: '0.15em', lineHeight: 1.1 }}>
            {now.toLocaleTimeString('en-US', { hour12: false })}
          </div>
          <div style={{ fontSize: 9, color: '#3a4f6a', marginTop: 3 }}>UP {hh}:{mm}:{ss}</div>
        </div>

        {/* network chart */}
        <div style={panelStyle}>
          <div style={{ fontSize: 9, color: '#5a6f8a', marginBottom: 6 }}>NETWORK I/O</div>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 1, height: 32 }}>
            {net.map((v, i) => (
              <div
                key={i}
                style={{
                  flex: 1,
                  borderRadius: '1px 1px 0 0',
                  height: `${Math.max(v, 4)}%`,
                  background: v > 70 ? '#ff073a' : v > 40 ? '#ffb800' : '#00d4ff',
                  opacity: 0.3 + (i / net.length) * 0.7,
                  transition: 'height 0.3s ease',
                }}
              />
            ))}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: '#3a4f6a', marginTop: 3 }}>
            <span>0</span>
            <span>{net[net.length - 1] ?? 0} kB/s</span>
          </div>
        </div>

        {/* sentinel status */}
        <div style={{
          ...panelStyle,
          border: sentUp ? '1px solid rgba(0,255,65,0.4)' : '1px solid rgba(255,7,58,0.4)',
          boxShadow: sentUp ? '0 0 8px rgba(0,255,65,0.15)' : '0 0 8px rgba(255,7,58,0.15)',
        }}>
          <div style={{ fontSize: 9, color: '#5a6f8a', marginBottom: 4 }}>SENTINEL / VIGIL</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className={`dot ${sentUp ? 'dot-on' : 'dot-off'}`} />
            <span
              className={sentUp ? 'g-green' : 'g-red'}
              style={{ fontSize: 11, fontWeight: 700 }}
            >
              {sentUp ? 'ACTIVE' : 'OFFLINE'}
            </span>
          </div>
          <div style={{ fontSize: 9, color: '#3a4f6a', marginTop: 3 }}>
            {sentUp ? 'Monitoring :8000' : 'Start Vigil first'}
          </div>
        </div>

        {/* threat meters */}
        <div style={panelStyle}>
          <div style={{ fontSize: 9, color: '#5a6f8a', marginBottom: 8 }}>THREAT ANALYSIS</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {meters.map(m => (
              <div key={m.label}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, marginBottom: 2 }}>
                  <span style={{ color: '#5a6f8a' }}>{m.label}</span>
                  <span style={{ color: m.color, fontWeight: 700 }}>{m.v.toFixed(2)}</span>
                </div>
                <div className="prog">
                  <div
                    className="prog-bar"
                    style={{
                      width: `${m.v * 100}%`,
                      background: m.color,
                      boxShadow: `0 0 6px ${m.color}80`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* validation log */}
        {vals.length > 0 && (
          <div style={panelStyle}>
            <div style={{ fontSize: 9, color: '#5a6f8a', marginBottom: 6 }}>VALIDATION LOG</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {vals.slice(-6).map((v: any, i: number) => {
                const ok = v?.sentinel_detected ?? (v?.final_metrics?.detection_rate_pct > 50)
                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9 }}>
                    <span className={ok ? 'g-green' : 'g-red'}>{ok ? '✓' : '✗'}</span>
                    <span style={{ color: '#b8c5d6', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {v?.attack_type ?? 'suite'}
                    </span>
                    <span style={{ color: '#5a6f8a' }}>{v?.block_rate_pct ?? 0}%</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* modules */}
        <div style={panelStyle}>
          <div style={{ fontSize: 9, color: '#5a6f8a', marginBottom: 6 }}>MODULES</div>
          {([
            ['CRYPTO',   '#bf5af2', sentUp ? 'on' : 'on'],
            ['RECON',    '#00d4ff', 'on'],
            ['DOS',      '#ff073a', 'on'],
            ['VALIDATE', '#00ff41', sentUp ? 'on' : 'warn'],
          ] as [string, string, string][]).map(([name, col, st]) => (
            <div
              key={name}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9, padding: '2px 0' }}
            >
              <span
                className="dot"
                style={{
                  background: st === 'on' ? col : '#ffb800',
                  boxShadow: `0 0 4px ${st === 'on' ? col : '#ffb800'}`,
                  width: 4, height: 4,
                }}
              />
              <span style={{ color: col }}>{name}</span>
              <span style={{ color: '#3a4f6a', marginLeft: 'auto' }}>LOADED</span>
            </div>
          ))}
        </div>

      </div>
    </div>
  )
}
