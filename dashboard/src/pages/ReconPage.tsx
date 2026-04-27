/**
 * src/pages/ReconPage.tsx
 */

import { useState } from 'react'
import { reconApi } from '../hooks/useApi'
import { useAppStore } from '../store/appStore'

export default function ReconPage() {
  const { addTerminalLine } = useAppStore()
  const [result, setResult] = useState<any>(null)
  const [running, setRunning] = useState(false)
  const target = '172.25.0.12'

  const run = async (name: string, fn: () => Promise<any>) => {
    setRunning(true)
    addTerminalLine(`[RECON] Starting ${name} on ${target}...`)
    try {
      const { data } = await fn()
      setResult(data)
      addTerminalLine(`[RECON] ${name} complete`)
      if (data.open_ports) addTerminalLine(`[RECON] Open ports: ${data.open_ports.join(', ')}`)
      if (data.best_guess) addTerminalLine(`[RECON] OS guess: ${data.best_guess}`)
    } catch (e: any) {
      addTerminalLine(`[ERROR] ${e.message}`)
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="terminal-panel p-4">
        <div className="text-terminal-cyan font-bold text-sm mb-1">🔍 RECONNAISSANCE LAB</div>
        <div className="text-terminal-muted text-xs">Target: {target} (Docker Lab nginx)</div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[
          { name: 'TCP SCAN', fn: () => reconApi.tcpScan(target, 'top_20'), desc: 'Top 20 ports', icon: '🔌' },
          { name: 'BANNER GRAB', fn: () => reconApi.bannerGrab(target, [80, 443, 22, 8080]), desc: 'Service versions', icon: '🏷️' },
          { name: 'OS FINGERPRINT', fn: () => reconApi.osFingerprint(target), desc: 'TTL + window analysis', icon: '🖥️' },
          { name: 'STEALTH SCAN', fn: () => reconApi.stealthCompare(target), desc: 'Normal vs slow', icon: '🥷' },
          { name: 'FULL RECON', fn: () => reconApi.fullRecon(target), desc: 'Complete pipeline', icon: '🗺️' },
        ].map(item => (
          <button
            key={item.name}
            onClick={() => run(item.name, item.fn)}
            disabled={running}
            className="terminal-panel p-4 text-left hover:border-terminal-cyan border border-terminal-border transition-colors disabled:opacity-50"
          >
            <div className="text-xl mb-2">{item.icon}</div>
            <div className="text-terminal-cyan font-bold text-xs">{item.name}</div>
            <div className="text-terminal-muted text-xs mt-1">{item.desc}</div>
          </button>
        ))}
      </div>

      {result && (
        <div className="terminal-panel p-4">
          <div className="text-terminal-green font-bold text-xs mb-2">RESULT</div>
          <pre className="text-xs text-terminal-text overflow-auto max-h-64">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
