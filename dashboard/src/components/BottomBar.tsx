import { useStore } from '../store/appStore'

export default function BottomBar({ cpu, net }: { cpu: number; net: number[] }) {
  const { lines, running } = useStore()
  const cur = net[net.length - 1] ?? 0
  const spark = net.slice(-16).map(v =>
    v > 80 ? '█' : v > 60 ? '▇' : v > 40 ? '▅' : v > 20 ? '▃' : '▁'
  ).join('')

  return (
    <div
      className="flex items-center justify-between px-4 flex-shrink-0 select-none"
      style={{ height: 24, background: '#0a1018', borderTop: '1px solid #1a2744', fontSize: 9 }}
    >
      <div className="flex items-center gap-4">
        <span style={{ color: '#5a6f8a' }}>
          CPU <span style={{ color: cpu > 60 ? '#ff073a' : cpu > 30 ? '#ffb800' : '#00ff41' }}>{cpu}%</span>
        </span>
        <span style={{ color: '#5a6f8a' }}>
          MEM <span style={{ color: '#00d4ff' }}>412M</span>
        </span>
        <span style={{ color: '#5a6f8a' }}>
          NET <span style={{ color: '#00d4ff' }}>{spark}</span>
          <span style={{ color: '#3a4f6a', marginLeft: 4 }}>{cur}kB/s</span>
        </span>
      </div>

      <div>
        {running
          ? <span style={{ color: '#ff073a', fontWeight: 700 }} className="animate-pulse">◉ ATTACK IN PROGRESS</span>
          : <span style={{ color: '#5a6f8a' }}>⚔ INS LAB TE7947 · <span style={{ color: '#ffb800' }}>AUTHORIZED USE ONLY</span></span>
        }
      </div>

      <div className="flex items-center gap-4">
        <span style={{ color: '#5a6f8a' }}>LOG <span style={{ color: '#b8c5d6' }}>{lines.length}</span></span>
        <span style={{ color: '#5a6f8a' }}>API <span style={{ color: '#00ff41' }}>:9000</span></span>
        <span style={{ color: '#5a6f8a' }}>VGL <span style={{ color: '#00ff41' }}>:8000</span></span>
      </div>
    </div>
  )
}
