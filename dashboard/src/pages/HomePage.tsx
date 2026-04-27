/**
 * src/pages/HomePage.tsx
 * Welcome screen with module overview
 */

import { useAppStore } from '../store/appStore'

const modules = [
  {
    id: 'crypto',
    name: 'CRYPTANALYSIS',
    icon: '🔐',
    description: 'Break classical ciphers: Caesar, Vigenere, Rail Fence, Hill, RSA',
    attacks: ['Brute Force', 'Frequency Analysis', 'Kasiski Examination', 'Known Plaintext', 'Prime Factorization'],
    syllabus: 'Units 1-6 (CO1, CO2)',
    color: 'border-terminal-purple'
  },
  {
    id: 'recon',
    name: 'RECONNAISSANCE',
    icon: '🔍',
    description: 'Network scanning, banner grabbing, OS fingerprinting',
    attacks: ['TCP SYN Scan', 'UDP Scan', 'Banner Grab', 'OS Fingerprint', 'Stealth Modes'],
    syllabus: 'Units 7-8 (CO3)',
    color: 'border-terminal-cyan'
  },
  {
    id: 'dos',
    name: 'DoS SIMULATION',
    icon: '💥',
    description: 'Controlled DoS/DDoS attack simulation with metrics',
    attacks: ['HTTP Flood', 'SYN Flood', 'Slowloris', 'Credential Stuffing', 'Traffic Analysis'],
    syllabus: 'Units 10-12 (CO4, CO5)',
    color: 'border-terminal-red'
  },
  {
    id: 'validation',
    name: 'SENTINEL VALIDATE',
    icon: '✅',
    description: 'Validate Sentinel/Vigil detection with scientific metrics',
    attacks: ['Detection Rate', 'Latency Benchmark', 'False Positive Rate', 'Full Test Suite', 'Validation Matrix'],
    syllabus: 'All COs - Professional Standard',
    color: 'border-terminal-green'
  }
]

export default function HomePage() {
  const { setActiveModule } = useAppStore()

  return (
    <div className="max-w-4xl mx-auto py-8 space-y-6">
      {/* Header */}
      <div className="text-center space-y-2">
        <pre className="text-terminal-green text-xs leading-tight glow-green">
{`
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
    ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
    ██║   ███████║██████╔╝█████╗  ███████║   ██║   
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   
         ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
         ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
         █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
         ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
         ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
         ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
`}
        </pre>
        <p className="text-terminal-muted text-xs">
          Offensive Security Testing Framework | INS Lab TE7947 | Educational Use Only
        </p>
      </div>

      {/* Module cards */}
      <div className="grid grid-cols-2 gap-4">
        {modules.map(mod => (
          <div
            key={mod.id}
            onClick={() => setActiveModule(mod.id as any)}
            className={`terminal-panel border-l-4 ${mod.color} p-4 cursor-pointer hover:bg-terminal-bg transition-colors`}
          >
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xl">{mod.icon}</span>
              <span className="text-terminal-green font-bold text-sm">{mod.name}</span>
            </div>
            <p className="text-terminal-muted text-xs mb-3">{mod.description}</p>
            <div className="space-y-1">
              {mod.attacks.map(attack => (
                <div key={attack} className="text-xs text-terminal-text">
                  <span className="text-terminal-green mr-1">▸</span>
                  {attack}
                </div>
              ))}
            </div>
            <div className="mt-3 text-xs text-terminal-yellow">
              📚 {mod.syllabus}
            </div>
          </div>
        ))}
      </div>

      {/* System info */}
      <div className="terminal-panel p-4 text-xs space-y-1">
        <div className="text-terminal-green font-bold mb-2">[SYSTEM INFO]</div>
        <div><span className="text-terminal-muted">Backend API:</span> <span className="text-terminal-cyan">http://localhost:9000</span></div>
        <div><span className="text-terminal-muted">Sentinel/Vigil:</span> <span className="text-terminal-cyan">http://localhost:8000</span></div>
        <div><span className="text-terminal-muted">API Docs:</span> <span className="text-terminal-cyan">http://localhost:9000/docs</span></div>
        <div><span className="text-terminal-muted">Test Lab:</span> <span className="text-terminal-cyan">Docker (run: docker compose up -d)</span></div>
      </div>
    </div>
  )
}
