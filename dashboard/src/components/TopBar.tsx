import { useStore } from '../store/appStore'

export default function TopBar({ wsOk }: { wsOk: boolean }) {
  const { sentUp, running, runLabel } = useStore()

  return (
    <div
      className="flex items-center justify-between px-4 flex-shrink-0"
      style={{ height: 32, background: '#0a1018', borderBottom: '1px solid #1a2744' }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3">
        <span className="g-green font-display font-bold tracking-widest select-none" style={{ fontSize: 13 }}>
          ⚔ THREATFORGE
        </span>
        <span style={{ fontSize: 9, color: '#5a6f8a' }}>v0.1.0</span>
        <div style={{ width: 1, height: 12, background: '#1a2744' }} />
        <span style={{ fontSize: 9, color: '#3a4f6a', letterSpacing: '0.1em' }}>
          ADVERSARY EMULATION PLATFORM
        </span>
      </div>

      {/* Attack pulse */}
      <div>
        {running && (
          <div
            className="flex items-center gap-2 animate-pulse"
            style={{
              padding: '2px 12px', borderRadius: 3,
              background: 'rgba(255,7,58,0.1)', border: '1px solid rgba(255,7,58,0.4)'
            }}
          >
            <span className="dot dot-on" style={{ width: 6, height: 6 }} />
            <span style={{ fontSize: 9, color: '#ff073a', fontWeight: 700, letterSpacing: '0.08em' }}>
              ⚡ {runLabel.toUpperCase()} ACTIVE
            </span>
          </div>
        )}
      </div>

      {/* Status */}
      <div className="flex items-center gap-3" style={{ fontSize: 9 }}>
        <div className="flex items-center gap-1">
          <span className={`dot ${sentUp ? 'dot-on' : 'dot-off'}`} style={{ width: 6, height: 6 }} />
          <span style={{ color: sentUp ? '#00ff41' : '#ff073a' }}>SENTINEL</span>
        </div>
        <div style={{ width: 1, height: 12, background: '#1a2744' }} />
        <div className="flex items-center gap-1">
          <span className={`dot ${wsOk ? 'dot-on' : 'dot-off'}`} style={{ width: 6, height: 6 }} />
          <span style={{ color: wsOk ? '#00ff41' : '#ff073a' }}>STREAM</span>
        </div>
        <div style={{ width: 1, height: 12, background: '#1a2744' }} />
        <span style={{ color: '#3a4f6a' }}>
          {new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}
        </span>
      </div>
    </div>
  )
}
