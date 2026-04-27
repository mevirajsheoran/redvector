/**
 * src/hooks/useWebSocket.ts
 * WebSocket hook for live feed from ThreatForge backend
 */

import { useEffect, useRef, useState, useCallback } from 'react'

export interface LiveEvent {
  type: string
  timestamp: number
  data: Record<string, any>
}

interface UseWebSocketReturn {
  events: LiveEvent[]
  isConnected: boolean
  clearEvents: () => void
  latestEvent: LiveEvent | null
}

export function useWebSocket(url: string = 'ws://localhost:9000/ws/live-feed'): UseWebSocketReturn {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        setIsConnected(true)
        console.log('ThreatForge WS connected')
      }

      ws.onmessage = (event) => {
        try {
          const parsed: LiveEvent = JSON.parse(event.data)
          setEvents(prev => {
            // Keep only last 100 events to avoid memory issues
            const updated = [...prev, parsed]
            return updated.slice(-100)
          })
        } catch (e) {
          console.error('WS parse error', e)
        }
      }

      ws.onclose = () => {
        setIsConnected(false)
        // Auto-reconnect after 3 seconds
        reconnectTimer.current = setTimeout(connect, 3000)
      }

      ws.onerror = () => {
        setIsConnected(false)
        ws.close()
      }

    } catch (e) {
      setIsConnected(false)
    }
  }, [url])

  useEffect(() => {
    connect()
    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
      }
    }
  }, [connect])

  const clearEvents = useCallback(() => {
    setEvents([])
  }, [])

  const latestEvent = events.length > 0 ? events[events.length - 1] : null

  return { events, isConnected, clearEvents, latestEvent }
}
