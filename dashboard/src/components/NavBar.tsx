/**
 * src/components/NavBar.tsx
 * Top navigation with module selector
 */

import { useAppStore } from '../store/appStore'

interface NavBarProps {
  wsConnected: boolean
}

const modules = [
  { id: 'home', label: '[HOME]', icon: '⌂' },
  { id: 'crypto', label: '[CRYPTO]', icon: '🔐' },
  { id: 'recon', label: '[RECON]', icon: '🔍' },
  { id: 'dos', label: '[DoS]', icon: '💥' },
  { id: 'validation', label: '[VALIDATE]', icon: '✅' },
]

export default function NavBar({ wsConnected }: NavBarProps) {
  const { activeModule, setActiveModule, isAttackRunning, currentAttack, sentinelOnline } = useAppStore()

  return (
    <div className="bg-terminal-surface border-b border-terminal-border px-4 py-2 flex items-center justify-between">
      {/* Left: Logo */}
      <div className="flex items-center gap-3">
        <span className="text-terminal-green font-bold text-lg glow-green">
          ⚔ THREATFORGE
        </span>
        <span className="text-terminal-muted text-xs">v0.1.0</span>
      </div>

      {/* Center: Module navigation */}
      <div className="flex gap-1">
        {modules.map(mod => (
          <button
            key={mod.id}
            onClick={() => setActiveModule(mod.id as any)}
            disabled={isAttackRunning}
            className={`
              px-3 py-1 text-xs font-mono rounded transition-all
              ${activeModule === mod.id
                ? 'bg-terminal-green text-terminal-bg font-bold'
                : 'text-terminal-muted hover:text-terminal-green hover:bg-terminal-bg'
              }
              ${isAttackRunning ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
            `}
          >
            {mod.icon} {mod.label}
          </button>
        ))}
      </div>

      {/* Right: Status indicators */}
      <div className="flex items-center gap-4 text-xs">
        {isAttackRunning && (
          <span className="text-terminal-yellow animate-pulse">
            ⚡ {currentAttack?.toUpperCase()} RUNNING
          </span>
        )}
        <div className="flex items-center gap-1">
          <span className={`status-dot ${sentinelOnline ? 'online' : 'offline'}`} />
          <span className={sentinelOnline ? 'text-terminal-green' : 'text-terminal-red'}>
            SENTINEL
          </span>
        </div>
        <div className="flex items-center gap-1">
          <span className={`status-dot ${wsConnected ? 'online' : 'offline'}`} />
          <span className={wsConnected ? 'text-terminal-green' : 'text-terminal-red'}>
            WS
          </span>
        </div>
      </div>
    </div>
  )
}
