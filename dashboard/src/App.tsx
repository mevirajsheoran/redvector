/**
 * src/App.tsx
 * Main application component - CLI-styled security dashboard
 */

import { useEffect } from 'react'
import { useAppStore } from './store/appStore'
import { useWebSocket } from './hooks/useWebSocket'
import { validateApi } from './hooks/useApi'

import NavBar from './components/NavBar'
import Terminal from './components/Terminal'
import StatusBar from './components/StatusBar'
import HomePage from './pages/HomePage'
import CryptoPage from './pages/CryptoPage'
import ReconPage from './pages/ReconPage'
import DoSPage from './pages/DoSPage'
import ValidationPage from './pages/ValidationPage'

export default function App() {
  const { activeModule, addTerminalLine, setSentinelOnline } = useAppStore()
  const { events, isConnected } = useWebSocket()

  // Forward WS events to terminal
  useEffect(() => {
    if (events.length === 0) return
    const latest = events[events.length - 1]
    if (latest.type === 'heartbeat') return  // Skip heartbeat noise

    const time = new Date(latest.timestamp * 1000).toTimeString().slice(0, 8)
    const module = latest.data?.module || latest.data?.attack_type || latest.type
    addTerminalLine(`[${time}] [${module.toUpperCase()}] ${JSON.stringify(latest.data).slice(0, 80)}`)
  }, [events])

  // Check Sentinel status periodically
  useEffect(() => {
    const checkSentinel = async () => {
      try {
        await validateApi.status()
        setSentinelOnline(true)
      } catch {
        setSentinelOnline(false)
      }
    }
    checkSentinel()
    const interval = setInterval(checkSentinel, 15000)
    return () => clearInterval(interval)
  }, [])

  const renderPage = () => {
    switch (activeModule) {
      case 'crypto': return <CryptoPage />
      case 'recon': return <ReconPage />
      case 'dos': return <DoSPage />
      case 'validation': return <ValidationPage />
      default: return <HomePage />
    }
  }

  return (
    <div className="min-h-screen bg-terminal-bg flex flex-col font-mono">
      {/* Top navigation */}
      <NavBar wsConnected={isConnected} />

      {/* Main content area */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: Module panel */}
        <div className="flex-1 overflow-auto p-4">
          {renderPage()}
        </div>

        {/* Right: Terminal */}
        <div className="w-96 border-l border-terminal-border">
          <Terminal />
        </div>
      </div>

      {/* Bottom status bar */}
      <StatusBar />
    </div>
  )
}
