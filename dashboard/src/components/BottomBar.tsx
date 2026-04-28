import { useStore } from '../store/appStore'

export default function BottomBar({ cpu, net }: { cpu: number; net: number[] }) {
  const { lines, running } = useStore()
  const cur = net[net.length - 1] ?? 0

  const spark = net.slice(-16).map(v =>
    v > 80 ? '█' : v > 60 ? '▇' : v > 40 ? '▅' : v > 20 ? '▃' : '▁'
  ).join('')

  return (
    <div className="flex items-center justify-between h-6 px-4 bg-h-panel border-t border-h-border text-3xs flex-shrink-0 select-none">

      <div className="flex items-center gap-3">
        <span className="text-h-muted">
          CPU <span className={cpu > 60 ? 'text-h-red' : cpu > 30 ? 'text-h-yellow' : 'text-h-green'}>{cpu}%</span>
        </span>
        <span className="text-h-muted">
          MEM <span className="text-h-cyan">412M</span>
        </span>
        <span className="text-h-muted">
          NET <span className="text-h-cyan">{spark}</span>
          <span className="text-h-dark ml-1">{cur}kB/s</span>
        </span>
      </div>

      <div>
        {running
          ? <span className="text-h-red font-bold animate-pulse">◉ ATTACK IN PROGRESS</span>
          : <span className="text-h-muted">⚔ INS LAB TE7947 · <span className="text-h-yellow">AUTHORIZED USE ONLY</span></span>
        }
      </div>

      <div className="flex items-center gap-3">
        <span className="text-h-muted">LOG <span className="text-h-text">{lines.length}</span></span>
        <span className="text-h-muted">API <span className="text-h-green">:9000</span></span>
        <span className="text-h-muted">VGL <span className="text-h-green">:8000</span></span>
      </div>
    </div>
  )
}