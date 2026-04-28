import { useEffect, useState } from 'react'
import { useStore } from './store/appStore'
import { useWebSocket } from './hooks/useWebSocket'
import { valApi } from './hooks/useApi'
import TopBar      from './components/TopBar'
import LeftSidebar from './components/LeftSidebar'
import MainTerminal from './components/MainTerminal'
import RightSidebar from './components/RightSidebar'
import BottomBar   from './components/BottomBar'

export default function App() {
  const { addLine, setSentinel } = useStore()
  const { events, connected }   = useWebSocket()
  const [cpu, setCpu] = useState(12)
  const [net, setNet] = useState<number[]>(Array(22).fill(3))

  /* forward WS events → terminal */
  useEffect(() => {
    if (!events.length) return
    const e = events[events.length - 1]
    if (e.type === 'heartbeat' || e.type === 'pong') return
    const src = (e.data?.module ?? e.data?.attack_type ?? e.type).toUpperCase().slice(0, 8)
    addLine(src, JSON.stringify(e.data).slice(0, 100), 'info')
  }, [events])   // eslint-disable-line

  /* check Sentinel */
  useEffect(() => {
    const check = async () => {
      try { const { data } = await valApi.status(); setSentinel(data.sentinel_connected) }
      catch { setSentinel(false) }
    }
    check()
    const id = setInterval(check, 15_000)
    return () => clearInterval(id)
  }, [])  // eslint-disable-line

  /* simulated metrics */
  useEffect(() => {
    const id = setInterval(() => {
      setCpu(Math.floor(Math.random() * 22 + 8))
      setNet(p => [...p.slice(1), Math.floor(Math.random() * 75 + 5)])
    }, 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden bg-h-bg">
      <TopBar wsOk={connected} />
      <div className="flex flex-1 overflow-hidden">
        <LeftSidebar />
        <MainTerminal />
        <RightSidebar net={net} />
      </div>
      <BottomBar cpu={cpu} net={net} />
    </div>
  )
}