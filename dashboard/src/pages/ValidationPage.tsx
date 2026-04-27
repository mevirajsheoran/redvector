/**
 * src/pages/ValidationPage.tsx
 * Sentinel validation test suite - the SHOWSTOPPER demo page
 */

import { useState } from 'react'
import { validateApi } from '../hooks/useApi'
import { useAppStore } from '../store/appStore'

interface TestResult {
  test_id: string
  attack_type: string
  payloads_sent: number
  sentinel_detected: boolean
  detection_latency_s: number | null
  blocks_triggered: number
  block_rate_pct: number
  confidence: string
}

export default function ValidationPage() {
  const { addTerminalLine, setAttackRunning, sentinelOnline, addValidationResult, validationResults } = useAppStore()
  const [isRunning, setIsRunning] = useState(false)
  const [currentTest, setCurrentTest] = useState<string | null>(null)
  const [sentinelStatus, setSentinelStatus] = useState<Record<string, any> | null>(null)
  const [fullSuiteResult, setFullSuiteResult] = useState<Record<string, any> | null>(null)

  const checkSentinel = async () => {
    try {
      const { data } = await validateApi.status()
      setSentinelStatus(data)
      addTerminalLine(`[VALIDATE] Sentinel status: ${data.sentinel_connected ? 'ONLINE' : 'OFFLINE'}`)
      if (data.current_stats) {
        addTerminalLine(`[VALIDATE] Current block rate: ${data.current_stats.block_rate_pct}%`)
      }
    } catch (e) {
      addTerminalLine('[ERROR] Cannot reach Sentinel. Start with: uvicorn Vigil.main:app --port 8000')
    }
  }

  const runTest = async (testName: string, apiFn: () => Promise<any>) => {
    setIsRunning(true)
    setCurrentTest(testName)
    setAttackRunning(true, testName)
    addTerminalLine(`[VALIDATE] Starting ${testName} validation...`)

    try {
      const { data } = await apiFn()
      addTerminalLine(`[VALIDATE] ${testName} complete`)
      addTerminalLine(`[VALIDATE] Detected: ${data.sentinel_detected ? '✅ YES' : '❌ NO'}`)
      if (data.detection_latency_s) {
        addTerminalLine(`[VALIDATE] Detection latency: ${data.detection_latency_s}s`)
      }
      addTerminalLine(`[VALIDATE] Block rate: ${data.block_rate_pct || 0}%`)
      addValidationResult(data)
      return data
    } catch (e: any) {
      addTerminalLine(`[ERROR] ${testName} failed: ${e.message}`)
      return null
    } finally {
      setIsRunning(false)
      setCurrentTest(null)
      setAttackRunning(false)
    }
  }

  const runFullSuite = async () => {
    setIsRunning(true)
    setAttackRunning(true, 'full_validation_suite')
    addTerminalLine('[VALIDATE] ═══════════════════════════════════════')
    addTerminalLine('[VALIDATE] STARTING FULL VALIDATION SUITE')
    addTerminalLine('[VALIDATE] Tests: HTTP Flood | Cred Stuff | Enumeration')
    addTerminalLine('[VALIDATE] ═══════════════════════════════════════')

    try {
      const { data } = await validateApi.fullSuite()
      setFullSuiteResult(data)
      addTerminalLine('[VALIDATE] ═══════════════════════════════════════')
      addTerminalLine(`[VALIDATE] SUITE COMPLETE - ${data.tests_run} tests run`)
      addTerminalLine(`[VALIDATE] Detection Rate: ${data.final_metrics?.detection_rate_pct}%`)
      addTerminalLine(`[VALIDATE] Matrix saved to: ${data.files_saved?.csv}`)
      addTerminalLine('[VALIDATE] ═══════════════════════════════════════')
    } catch (e: any) {
      addTerminalLine(`[ERROR] Suite failed: ${e.message}`)
    } finally {
      setIsRunning(false)
      setAttackRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="terminal-panel p-4">
        <div className="text-terminal-green font-bold text-sm mb-1">✅ SENTINEL VALIDATION LAB</div>
        <div className="text-terminal-muted text-xs">
          Scientific proof that Sentinel/Vigil detects attacks. Generates validation_matrix.csv for your report.
        </div>
      </div>

      {/* Sentinel Status Check */}
      <div className="terminal-panel p-4">
        <div className="text-terminal-cyan font-bold text-xs mb-3">[STEP 1] CHECK SENTINEL STATUS</div>
        <button
          onClick={checkSentinel}
          disabled={isRunning}
          className="px-4 py-2 bg-terminal-cyan text-terminal-bg text-xs font-bold rounded hover:opacity-80 disabled:opacity-50"
        >
          CHECK SENTINEL CONNECTION
        </button>
        {sentinelStatus && (
          <div className="mt-3 space-y-1 text-xs">
            <div className={sentinelStatus.sentinel_connected ? 'text-terminal-green' : 'text-terminal-red'}>
              Status: {sentinelStatus.sentinel_connected ? '✅ ONLINE' : '❌ OFFLINE'}
            </div>
            {sentinelStatus.current_stats && (
              <>
                <div className="text-terminal-text">
                  Total Requests: {sentinelStatus.current_stats.total_requests}
                </div>
                <div className="text-terminal-text">
                  Block Rate: {sentinelStatus.current_stats.block_rate_pct}%
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* Individual Tests */}
      <div className="terminal-panel p-4">
        <div className="text-terminal-yellow font-bold text-xs mb-3">[STEP 2] RUN INDIVIDUAL TESTS</div>
        <div className="grid grid-cols-3 gap-2">
          <button
            onClick={() => runTest('http_flood', () => validateApi.httpFlood(20, 50))}
            disabled={isRunning}
            className="px-3 py-2 bg-terminal-red text-white text-xs rounded hover:opacity-80 disabled:opacity-50"
          >
            💧 HTTP FLOOD TEST
            <div className="text-xs opacity-70">20s | 50 RPS</div>
          </button>

          <button
            onClick={() => runTest('cred_stuff', () => validateApi.credentialStuff(20))}
            disabled={isRunning}
            className="px-3 py-2 bg-terminal-orange text-white text-xs rounded hover:opacity-80 disabled:opacity-50"
          >
            🔑 CRED STUFF TEST
            <div className="text-xs opacity-70">20s | 5 APS</div>
          </button>

          <button
            onClick={() => runTest('enumeration', () => validateApi.enumeration(20))}
            disabled={isRunning}
            className="px-3 py-2 bg-terminal-purple text-white text-xs rounded hover:opacity-80 disabled:opacity-50"
          >
            📋 ENUMERATION TEST
            <div className="text-xs opacity-70">20s | 10 IPS</div>
          </button>
        </div>
      </div>

      {/* Full Suite - SHOWSTOPPER */}
      <div className="terminal-panel p-4 border-terminal-green">
        <div className="text-terminal-green font-bold text-xs mb-1">
          [STEP 3] 🚀 FULL VALIDATION SUITE (DEMO SHOWSTOPPER)
        </div>
        <div className="text-terminal-muted text-xs mb-3">
          Runs all 3 tests sequentially. Generates validation_matrix.csv automatically.
        </div>
        <button
          onClick={runFullSuite}
          disabled={isRunning}
          className="w-full py-3 bg-terminal-green text-terminal-bg font-bold text-sm rounded hover:opacity-80 disabled:opacity-50 animate-pulse-green"
        >
          {isRunning ? `⚡ RUNNING: ${currentTest?.toUpperCase()}...` : '⚡ RUN COMPLETE VALIDATION SUITE'}
        </button>
      </div>

      {/* Results Table */}
      {validationResults.length > 0 && (
        <div className="terminal-panel p-4">
          <div className="text-terminal-green font-bold text-xs mb-3">
            📊 VALIDATION RESULTS ({validationResults.length} tests)
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-terminal-muted border-b border-terminal-border">
                  <th className="text-left py-1 pr-3">ATTACK</th>
                  <th className="text-left py-1 pr-3">SENT</th>
                  <th className="text-left py-1 pr-3">DETECTED</th>
                  <th className="text-left py-1 pr-3">LATENCY</th>
                  <th className="text-left py-1 pr-3">BLOCKS</th>
                  <th className="text-left py-1">CONFIDENCE</th>
                </tr>
              </thead>
              <tbody>
                {validationResults.map((r: any, idx) => (
                  <tr key={idx} className="border-b border-terminal-border border-opacity-30">
                    <td className="py-1 pr-3 text-terminal-cyan">{r.attack_type}</td>
                    <td className="py-1 pr-3">{r.payloads_sent || r.total_sent || 0}</td>
                    <td className="py-1 pr-3">
                      {r.sentinel_detected
                        ? <span className="text-terminal-green">✅ YES</span>
                        : <span className="text-terminal-red">❌ NO</span>
                      }
                    </td>
                    <td className="py-1 pr-3">
                      {r.detection_latency_s ? `${r.detection_latency_s}s` : 'N/A'}
                    </td>
                    <td className="py-1 pr-3">{r.blocks_triggered || 0}</td>
                    <td className="py-1">
                      <span className={
                        r.confidence === 'HIGH' ? 'text-terminal-green' :
                        r.confidence === 'MEDIUM' ? 'text-terminal-yellow' : 'text-terminal-muted'
                      }>
                        {r.confidence || 'N/A'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {fullSuiteResult?.final_metrics && (
            <div className="mt-4 p-3 bg-terminal-bg rounded text-xs space-y-1">
              <div className="text-terminal-green font-bold">FINAL METRICS:</div>
              <div>Detection Rate: <span className="text-terminal-green font-bold">{fullSuiteResult.final_metrics.detection_rate_pct}%</span></div>
              <div>Avg Block Rate: <span className="text-terminal-green">{fullSuiteResult.final_metrics.avg_block_rate_pct}%</span></div>
              <div className="text-terminal-muted">{fullSuiteResult.final_metrics.report_statement}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
