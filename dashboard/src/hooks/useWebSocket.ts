import { useEffect, useRef, useState, useCallback } from 'react'

export interface WsEvent { type: string; timestamp: number; data: Record<string, any> }

export function useWebSocket(url = 'ws://localhost:9000/ws/live-feed') {
  const [events,      setEvents]      = useState<WsEvent[]>([])
  const [connected,   setConnected]   = useState(false)
  const wsRef   = useRef<WebSocket | null>(null)
  const timer   = useRef<ReturnType<typeof setTimeout>>()

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url)
      wsRef.current = ws
      ws.onopen    = () => setConnected(true)
      ws.onmessage = e => {
        try { setEvents(p => [...p.slice(-80), JSON.parse(e.data) as WsEvent]) } catch {}
      }
      ws.onclose = () => {
        setConnected(false)
        timer.current = setTimeout(connect, 3000)
      }
      ws.onerror = () => { setConnected(false); ws.close() }
    } catch { setConnected(false) }
  }, [url])

  useEffect(() => {
    connect()
    return () => { wsRef.current?.close(); clearTimeout(timer.current) }
  }, [connect])

  return { events, connected }
}