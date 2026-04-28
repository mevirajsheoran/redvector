import { useEffect, useRef, useState, useCallback } from 'react'

export interface WsEvent {
  type: string
  timestamp: number
  data: Record<string, unknown>
}

export function useWebSocket(
  url: string = 'ws://localhost:9000/ws/live-feed'
) {
  const [events, setEvents] = useState<WsEvent[]>([])
  const [connected, setConnected] = useState(false)

  const wsRef = useRef<WebSocket | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
      }

      ws.onmessage = (e) => {
        try {
          const parsed = JSON.parse(e.data) as WsEvent
          setEvents((prev) => [...prev.slice(-80), parsed])
        } catch {
          // ignore invalid JSON
        }
      }

      ws.onclose = () => {
        setConnected(false)

        // prevent multiple timers
        if (timer.current) {
          clearTimeout(timer.current)
        }

        timer.current = setTimeout(() => {
          connect()
        }, 3000)
      }

      ws.onerror = () => {
        setConnected(false)
        ws.close()
      }
    } catch {
      setConnected(false)
    }
  }, [url])

  useEffect(() => {
    connect()

    return () => {
      // close websocket
      wsRef.current?.close()

      // clear reconnect timer safely
      if (timer.current) {
        clearTimeout(timer.current)
      }
    }
  }, [connect])

  return { events, connected }
}