/**
 * src/pages/DoSPage.tsx
 * DoS simulation control panel
 */

import { useState } from 'react'
import { dosApi } from '../hooks/useApi'
import { useAppStore } from '../store/appStore'

const TARGET_HTTP = 'http://172.25.0.12'
const TARGET_IP = '172.25.0.12'

export default function DoSPage() {
  const { addTerminalLine, setAttackRunning } = useAppStore()
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<Record<string, any> | null>(null)

  const runAttack = async (name: string, apiFn: () => Promise<any>) => {
    setIsRunning(true)
    setAttackRunning(true, name)
    addTerminalLine(`[ATTACK] Starting ${name}...`)
    addTerminalLine(`[ATTACK] Target: ${TARGET_HTTP}`)
    try {
      const { data } = await apiFn()
      setResult(data)
      addTerminalLine(`[ATTACK] ${name} complete`)
      if (data.total_requests_sent) addTerminalLine(`[ATTACK] Requests sent: ${data.total_requests_sent}`)
      if (data.actual_rps) addTerminalLine(`[ATTACK] Actual RPS: ${data.actual_rps}`)
      if (data.success_rate_pct) addTerminalLine(`[ATTACK] Success rate: ${data.success_rate_pct}%`)
    } catch (e: any) {
      addTerminalLine(`[ERROR] ${name} failed: ${e.message}`)
    } finally {
      setIsRunning(false)
      setAttackRunning(false)
    }
  }

  const attacks = [
    {
      name: 'HTTP GET FLOOD',
      icon: '💧',
      color: 'bg-red-900 hover:bg-red-800',
      fn: () => dosApi.httpFlood(TARGET_HTTP, 50, 20),
      desc: '50 RPS | 20s | Application Layer L7'
    },
    {
      name: 'HTTP POST FLOOD',
      icon: '📮',
      color: 'bg-orange-900 hover:bg-orange-800',
      fn: () => dosApi.httpFlood(TARGET_HTTP, 30, 20),
      desc: '30 RPS | 20s | With payload body'
    },
    {
      name: 'SYN FLOOD',
      icon: '⚡',
      color: 'bg-yellow-900 hover:bg-yellow-800',
      fn: () => dosApi.synFlood(TARGET_IP),
      desc: '100 PPS | 15s | TCP State Exhaustion'
    },
    {
      name: 'SLOWLORIS',
      icon: '🐌',
      color: 'bg-purple-900 hover:bg-purple-800',
      fn: () => dosApi.slowloris(TARGET_IP),
      desc: '50 conns | 30s | Connection Exhaustion'
    },
    {
      name: 'CRED STUFFING',
      icon: '🔑',
      color: 'bg-blue-900 hover:bg-blue-800',
      fn: () => dosApi.credentialStuff(TARGET_HTTP),
      desc: '5 APS | 30s | Auth Endpoint Abuse'
    },
    {
      name: 'BASELINE',
      icon: '📊',
      color: 'bg-green-900 hover:bg-green-800',
      fn: () => dosApi.baseline(TARGET_HTTP),
      desc: 'Normal traffic | 30s | For comparison'
    }
  ]

  return (
    <div className="space-y-4">
      <div className="terminal-panel p-4">
        <div className="text-terminal-red font-bold text-sm mb-1">💥 DoS SIMULATION LAB</div>
        <div className="text-terminal-muted text-xs">
          Target: Docker Lab ({TARGET_HTTP}) | All attacks rate-limited | Ethical use only
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {attacks.map(attack => (
          <button
            key={attack.name}
            onClick={() => runAttack(attack.name, attack.fn)}
            disabled={isRunning}
            className={`${attack.color} text-white text-xs p-4 rounded text-left disabled:opacity-50 transition-colors`}
          >
            <div className="text-lg mb-1">{attack.icon}</div>
            <div className="font-bold">{attack.name}</div>
            <div className="opacity-70 mt-1">{attack.desc}</div>
          </button>
        ))}
      </div>

      {result && (
        <div className="terminal-panel p-4">
          <div className="text-terminal-green font-bold text-xs mb-2">LAST RESULT</div>
          <pre className="text-xs text-terminal-text overflow-auto max-h-48">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
