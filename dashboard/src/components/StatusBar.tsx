/**
 * src/components/StatusBar.tsx
 * Bottom status bar with system info
 */

import { useState, useEffect } from 'react'

export default function StatusBar() {
  const [time, setTime] = useState(new Date().toTimeString().slice(0, 8))

  useEffect(() => {
    const interval = setInterval(() => {
      setTime(new Date().toTimeString().slice(0, 8))
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="bg-terminal-surface border-t border-terminal-border px-4 py-1 flex items-center justify-between text-xs text-terminal-muted">
      <div className="flex gap-4">
        <span>⚔ ThreatForge v0.1.0</span>
        <span>📚 INS Lab TE7947</span>
        <span className="text-terminal-yellow">⚠ AUTHORIZED TESTING ONLY</span>
      </div>
      <div className="flex gap-4">
        <span>API: localhost:9000</span>
        <span>SENTINEL: localhost:8000</span>
        <span className="text-terminal-green">{time}</span>
      </div>
    </div>
  )
}
