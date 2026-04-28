import { useEffect, useRef } from 'react'
import { useStore, type LogType } from '../store/appStore'

const BADGE_CLASS: Record<LogType, string> = {
  info:       'badge badge-m',
  success:    'badge badge-g',
  error:      'badge badge-r',
  attack:     'badge badge-r',
  system:     'badge badge-c',
  warning:    'badge badge-y',
  validation: 'badge badge-p',
}

const LINE_COLOR: Record<LogType, string> = {
  info:       '#b8c5d6',
  success:    '#00ff41',
  error:      '#ff073a',
  attack:     '#ff6b35',
  system:     '#00d4ff',
  warning:    '#ffb800',
  validation: '#bf5af2',
}

const BANNER = `
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
    ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
    ██║   ███████║██████╔╝█████╗  ███████║   ██║
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
         ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
         ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
         █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
         ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
         ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
         ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝`.trim()

export default function MainTerminal() {
  const { lines, result, clearLines, setResult, running } = useStore()
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  return (
    <div className="flex-1 flex flex-col overflow-hidden" style={{ background: '#050a0e' }}>

      {/* title bar */}
      <div
        className="flex items-center justify-between flex-shrink-0"
        style={{
          height: 28, padding: '0 16px',
          background: '#0a1018', borderBottom: '1px solid #1a2744'
        }}
      >
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            {['#ff073a','#ffb800','#00ff41'].map(c => (
              <div key={c} style={{ width: 10, height: 10, borderRadius: '50%', background: c, opacity: 0.8 }} />
            ))}
          </div>
          <span style={{ fontSize: 10, color: '#5a6f8a' }}>
            threatforge<span style={{ color: '#3a4f6a' }}>@kali</span>:~$&nbsp;
            <span style={{ color: '#00ff41' }}>active</span>
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span style={{ fontSize: 9, color: '#3a4f6a' }}>{lines.length} lines</span>
          <button
            onClick={clearLines}
            style={{
              fontSize: 9, color: '#5a6f8a', background: 'none',
              border: 'none', cursor: 'pointer', padding: 0
            }}
            onMouseEnter={e => (e.currentTarget.style.color = '#ff073a')}
            onMouseLeave={e => (e.currentTarget.style.color = '#5a6f8a')}
          >
            [CLEAR]
          </button>
        </div>
      </div>

      {/* body */}
      <div
        className={`flex-1 overflow-y-auto ${running ? 'streaming' : ''}`}
        style={{ padding: 12 }}
      >
        {/* banner */}
        {lines.length === 0 && (
          <div className="animate-fadein select-none">
            <pre className="g-green" style={{ fontSize: 10, lineHeight: 1.3, marginBottom: 12 }}>
              {BANNER}
            </pre>
            <div style={{ fontSize: 10, lineHeight: 1.8, marginLeft: 4 }}>
              <div style={{ color: '#00d4ff' }}>
                ┌──────────────────────────────────────────────────┐
              </div>
              <div style={{ color: '#00d4ff' }}>
                │ <span style={{ color: '#e8edf4' }}>System</span>{'   '}
                <span style={{ color: '#b8c5d6' }}>All modules loaded and ready</span>
                {'                    '}│
              </div>
              <div style={{ color: '#00d4ff' }}>
                │ <span style={{ color: '#e8edf4' }}>Target</span>{'   '}
                <span style={{ color: '#b8c5d6' }}>Docker lab 172.25.0.0/24</span>
                {'                       '}│
              </div>
              <div style={{ color: '#00d4ff' }}>
                │ <span style={{ color: '#e8edf4' }}>Modules</span>{'  '}
                <span style={{ color: '#bf5af2' }}>CRYPTO </span>
                <span style={{ color: '#00d4ff' }}>RECON </span>
                <span style={{ color: '#ff073a' }}>DOS </span>
                <span style={{ color: '#00ff41' }}>VALIDATE</span>
                {'                  '}│
              </div>
              <div style={{ color: '#00d4ff' }}>
                │ <span style={{ color: '#e8edf4' }}>Ethics</span>{'   '}
                <span style={{ color: '#ffb800' }}>Authorized isolated testing only</span>
                {'               '}│
              </div>
              <div style={{ color: '#00d4ff' }}>
                └──────────────────────────────────────────────────┘
              </div>
              <div style={{ color: '#00ff41', marginTop: 8 }}>
                ▸ Click a command in the left panel to begin
              </div>
            </div>
          </div>
        )}

        {/* lines */}
        {lines.map(line => (
          <div
            key={line.id}
            className="flex items-start gap-2 animate-slideup"
            style={{ marginBottom: 2, fontSize: 10, lineHeight: 1.5 }}
          >
            <span style={{ color: '#3a4f6a', flexShrink: 0, width: 64, fontFamily: 'monospace' }}>
              {line.time}
            </span>
            <span className={BADGE_CLASS[line.type]} style={{ flexShrink: 0 }}>
              {line.source}
            </span>
            <span style={{ color: LINE_COLOR[line.type], wordBreak: 'break-all' }}>
              {line.message}
            </span>
          </div>
        ))}

        {/* cursor */}
        <div className="flex items-center gap-2" style={{ marginTop: 8, fontSize: 10 }}>
          <span style={{ width: 64 }} />
          <span style={{ color: '#00ff41', fontWeight: 700 }}>$</span>
          <span className="cursor" />
        </div>

        <div ref={endRef} />
      </div>

      {/* output panel */}
      {result && (
        <div
          className="flex flex-col"
          style={{
            borderTop: '1px solid #1a2744',
            background: '#0a1018',
            maxHeight: 192,
          }}
        >
          <div
            className="flex items-center justify-between flex-shrink-0"
            style={{ padding: '4px 12px', borderBottom: '1px solid #1a2744' }}
          >
            <span style={{ fontSize: 9, color: '#00d4ff', fontWeight: 700, letterSpacing: '0.08em' }}>
              ◆ OUTPUT
            </span>
            <button
              onClick={() => setResult(null)}
              style={{
                fontSize: 9, color: '#5a6f8a', background: 'none',
                border: 'none', cursor: 'pointer', padding: 0
              }}
              onMouseEnter={e => (e.currentTarget.style.color = '#ff073a')}
              onMouseLeave={e => (e.currentTarget.style.color = '#5a6f8a')}
            >
              [×] CLOSE
            </button>
          </div>
          <pre
            className="flex-1 overflow-auto"
            style={{ margin: 0, padding: 12, fontSize: 9, color: '#b8c5d6', lineHeight: 1.6 }}
          >
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
