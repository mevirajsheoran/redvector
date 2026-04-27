/**
 * src/components/Terminal.tsx
 * CLI-styled terminal output panel
 */

import { useEffect, useRef } from 'react'
import { useAppStore } from '../store/appStore'

export default function Terminal() {
  const { terminalLines, clearTerminal } = useAppStore()
  const bottomRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [terminalLines])

  // Color code terminal lines
  const colorize = (line: string) => {
    if (line.includes('[SYS]')) return 'text-terminal-cyan'
    if (line.includes('[ERROR]') || line.includes('❌')) return 'text-terminal-red'
    if (line.includes('[OK]') || line.includes('✅') || line.includes('SUCCESS')) return 'text-terminal-green'
    if (line.includes('[WARN]') || line.includes('⚠')) return 'text-terminal-yellow'
    if (line.includes('[ATTACK]') || line.includes('RUNNING')) return 'text-terminal-orange'
    if (line.includes('[VALIDATE]') || line.includes('SENTINEL')) return 'text-terminal-purple'
    if (line.startsWith('╔') || line.startsWith('║') || line.startsWith('╚')) return 'text-terminal-green'
    return 'text-terminal-text'
  }

  return (
    <div className="flex flex-col h-full bg-terminal-bg">
      {/* Terminal header */}
      <div className="flex items-center justify-between px-3 py-2 bg-terminal-surface border-b border-terminal-border">
        <div className="flex items-center gap-2">
          <div className="flex gap-1">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-xs text-terminal-muted">threatforge@kali ~ $</span>
        </div>
        <button
          onClick={clearTerminal}
          className="text-xs text-terminal-muted hover:text-terminal-red"
        >
          [CLEAR]
        </button>
      </div>

      {/* Terminal output */}
      <div className="flex-1 overflow-y-auto p-3 space-y-0.5">
        {terminalLines.map((line, idx) => (
          <div
            key={idx}
            className={`text-xs leading-relaxed font-mono whitespace-pre-wrap ${colorize(line)}`}
          >
            {line || '\u00A0'}
          </div>
        ))}
        {/* Blinking cursor */}
        <div className="text-terminal-green text-xs cursor" />
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
