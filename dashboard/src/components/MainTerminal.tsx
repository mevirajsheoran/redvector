import { useEffect, useRef } from 'react'
import { useStore, LogType } from '../store/appStore'

const BADGE: Record<LogType, string> = {
  info:       'badge badge-muted',
  success:    'badge badge-green',
  error:      'badge badge-red',
  attack:     'badge badge-red',
  system:     'badge badge-cyan',
  warning:    'badge badge-yellow',
  validation: 'badge badge-purple',
}

const TEXT: Record<LogType, string> = {
  info:       'text-h-text',
  success:    'text-h-green',
  error:      'text-h-red',
  attack:     'text-h-red',
  system:     'text-h-cyan',
  warning:    'text-h-yellow',
  validation: 'text-h-purple',
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
    <div className="flex-1 flex flex-col overflow-hidden bg-h-bg">

      {/* title bar */}
      <div className="flex items-center justify-between px-4 py-1 bg-h-panel border-b border-h-border flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-h-red opacity-75" />
            <div className="w-2.5 h-2.5 rounded-full bg-h-yellow opacity-75" />
            <div className="w-2.5 h-2.5 rounded-full bg-h-green opacity-75" />
          </div>
          <span className="text-2xs text-h-muted">
            threatforge<span className="text-h-dark">@kali</span>:~$&nbsp;
            <span className="text-h-green">active</span>
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-3xs text-h-dark">{lines.length} lines</span>
          <button onClick={clearLines} className="text-3xs text-h-muted hover:text-h-red transition-colors">
            [CLEAR]
          </button>
        </div>
      </div>

      {/* terminal body */}
      <div className={`flex-1 overflow-y-auto p-3 ${running ? 'streaming' : ''}`}>

        {/* welcome banner */}
        {lines.length === 0 && (
          <div className="animate-fadein select-none">
            <pre className="text-h-green text-2xs leading-tight glow-green mb-3">{BANNER}</pre>
            <div className="text-2xs space-y-0.5 ml-1">
              <div className="text-h-cyan">┌──────────────────────────────────────────────────┐</div>
              <div className="text-h-cyan">│&nbsp;
                <span className="text-h-white">System</span>&nbsp;&nbsp;&nbsp;&nbsp;
                <span className="text-h-text">All modules loaded and ready</span>
                &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│
              </div>
              <div className="text-h-cyan">│&nbsp;
                <span className="text-h-white">Target</span>&nbsp;&nbsp;&nbsp;&nbsp;
                <span className="text-h-text">Docker lab 172.25.0.0/24</span>
                &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│
              </div>
              <div className="text-h-cyan">│&nbsp;
                <span className="text-h-white">Modules</span>&nbsp;&nbsp;&nbsp;
                <span className="text-h-purple">CRYPTO</span>&nbsp;
                <span className="text-h-cyan">RECON</span>&nbsp;
                <span className="text-h-red">DOS</span>&nbsp;
                <span className="text-h-green">VALIDATE</span>
                &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│
              </div>
              <div className="text-h-cyan">│&nbsp;
                <span className="text-h-white">Ethics</span>&nbsp;&nbsp;&nbsp;&nbsp;
                <span className="text-h-yellow">Authorized isolated testing only</span>
                &nbsp;&nbsp;&nbsp;&nbsp;│
              </div>
              <div className="text-h-cyan">└──────────────────────────────────────────────────┘</div>
              <div className="mt-2 text-h-green">▸ Click a command in the left panel to begin</div>
            </div>
          </div>
        )}

        {/* log lines */}
        {lines.map(line => (
          <div
            key={line.id}
            className="flex items-start gap-2 text-2xs leading-relaxed animate-slideup mb-0.5"
          >
            <span className="text-h-dark flex-shrink-0 w-16 select-none">{line.time}</span>
            <span className={`flex-shrink-0 ${BADGE[line.type]} select-none`}>{line.source}</span>
            <span className={`break-all ${TEXT[line.type]}`}>{line.message}</span>
          </div>
        ))}

        {/* cursor */}
        <div className="flex items-center gap-2 text-2xs mt-2">
          <span className="w-16" />
          <span className="text-h-green font-bold select-none">$</span>
          <span className="cursor" />
        </div>

        <div ref={endRef} />
      </div>

      {/* output panel */}
      {result && (
        <div className="border-t border-h-border bg-h-panel flex flex-col max-h-48">
          <div className="flex items-center justify-between px-3 py-1 border-b border-h-border flex-shrink-0">
            <span className="text-2xs text-h-cyan font-bold tracking-wider">◆ OUTPUT</span>
            <button onClick={() => setResult(null)} className="text-3xs text-h-muted hover:text-h-red transition-colors">
              [×] CLOSE
            </button>
          </div>
          <pre className="p-3 text-3xs text-h-text overflow-auto flex-1 leading-relaxed">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}