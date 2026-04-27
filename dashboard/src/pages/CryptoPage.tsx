/**
 * src/pages/CryptoPage.tsx
 */

import { useState } from 'react'
import { cryptoApi } from '../hooks/useApi'
import { useAppStore } from '../store/appStore'

export default function CryptoPage() {
  const { addTerminalLine } = useAppStore()
  const [result, setResult] = useState<any>(null)
  const [running, setRunning] = useState(false)

  const runDemo = async (name: string, fn: () => Promise<any>) => {
    setRunning(true)
    addTerminalLine(`[CRYPTO] Running ${name} demo...`)
    try {
      const { data } = await fn()
      setResult(data)
      addTerminalLine(`[CRYPTO] ${name} complete`)
      if (data.final_answer) {
        addTerminalLine(`[CRYPTO] Key found: ${data.final_answer.key}`)
        addTerminalLine(`[CRYPTO] Confidence: ${data.final_answer.confidence}`)
      }
      if (data.attack?.success) {
        addTerminalLine(`[CRYPTO] RSA broken! Recovered: ${data.attack.decrypted_value}`)
      }
    } catch (e: any) {
      addTerminalLine(`[ERROR] ${e.message}`)
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="terminal-panel p-4">
        <div className="text-terminal-purple font-bold text-sm mb-1">🔐 CRYPTANALYSIS LAB</div>
        <div className="text-terminal-muted text-xs">Break classical ciphers using algorithmic attacks</div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {[
          { name: 'CAESAR CIPHER', fn: () => cryptoApi.demoCaesar(13), desc: 'Brute force + frequency analysis', icon: '🔡' },
          { name: 'VIGENÈRE CIPHER', fn: () => cryptoApi.demoVigenere(), desc: 'Kasiski examination', icon: '🔤' },
          { name: 'RAIL FENCE', fn: () => cryptoApi.demoRailFence(3), desc: 'Pattern reconstruction', icon: '🚂' },
          { name: 'RSA FACTORIZATION', fn: () => cryptoApi.demoRSA(), desc: 'Trial division attack', icon: '🔢' },
        ].map(item => (
          <button
            key={item.name}
            onClick={() => runDemo(item.name, item.fn)}
            disabled={running}
            className="terminal-panel p-4 text-left hover:border-terminal-purple border border-terminal-border transition-colors disabled:opacity-50"
          >
            <div className="text-xl mb-2">{item.icon}</div>
            <div className="text-terminal-purple font-bold text-xs">{item.name}</div>
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
