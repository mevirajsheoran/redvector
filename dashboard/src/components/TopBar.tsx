import { useStore } from '../store/appStore'

export default function TopBar({ wsOk }: { wsOk: boolean }) {
  const { sentinelUp, running, runLabel } = useStore()

  return (
    <div className="flex items-center justify-between h-8 px-4 bg-h-panel border-b border-h-border flex-shrink-0">

      {/* logo */}
      <div className="flex items-center gap-3">
        <span className="font-display font-bold text-sm tracking-widest glow-green select-none">
          ⚔ THREATFORGE
        </span>
        <span className="text-3xs text-h-muted">v0.1.0</span>
        <div className="w-px h-3 bg-h-border" />
        <span className="text-3xs text-h-dark tracking-widest hidden md:block">
          ADVERSARY EMULATION PLATFORM
        </span>
      </div>

      {/* attack pulse */}
      <div className="flex items-center gap-2">
        {running && (
          <div className="flex items-center gap-2 px-3 py-0.5 rounded-sm border border-h-red/40 bg-h-red/10">
            <span className="dot dot-red animate-pulse w-1.5 h-1.5" />
            <span className="text-2xs text-h-red font-bold tracking-wider animate-pulse">
              ⚡ {runLabel.toUpperCase()} ACTIVE
            </span>
          </div>
        )}
      </div>

      {/* status */}
      <div className="flex items-center gap-3 text-2xs">
        <div className="flex items-center gap-1.5">
          <span className={`dot ${sentinelUp ? 'dot-green' : 'dot-red'}`} />
          <span className={sentinelUp ? 'text-h-green' : 'text-h-red'}>SENTINEL</span>
        </div>
        <div className="w-px h-3 bg-h-border" />
        <div className="flex items-center gap-1.5">
          <span className={`dot ${wsOk ? 'dot-green' : 'dot-red'}`} />
          <span className={wsOk ? 'text-h-green' : 'text-h-red'}>STREAM</span>
        </div>
        <div className="w-px h-3 bg-h-border" />
        <span className="text-h-dark">
          {new Date().toLocaleDateString('en-US', { weekday:'short', month:'short', day:'numeric' })}
        </span>
      </div>
    </div>
  )
}