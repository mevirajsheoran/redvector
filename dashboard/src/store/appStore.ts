import { create } from 'zustand'

export type LogType = 'info' | 'success' | 'error' | 'attack' | 'system' | 'warning' | 'validation'

export interface LogLine {
  id:      number
  time:    string
  source:  string
  message: string
  type:    LogType
}

let lineId = 0

interface Store {
  lines:       LogLine[]
  addLine:     (source: string, message: string, type?: LogType) => void
  clearLines:  () => void

  result:      any
  setResult:   (r: any) => void

  running:     boolean
  runLabel:    string
  setRunning:  (v: boolean, label?: string) => void

  sentinelUp:  boolean
  setSentinel: (v: boolean) => void

  validations: any[]
  addVal:      (v: any) => void
}

export const useStore = create<Store>((set) => ({
  lines: [],
  addLine: (source, message, type = 'info') =>
    set(s => ({
      lines: [...s.lines.slice(-400), {
        id: lineId++,
        time: new Date().toLocaleTimeString('en-US', { hour12: false }),
        source: source.toUpperCase().slice(0, 8),
        message,
        type,
      }]
    })),
  clearLines: () => set({ lines: [] }),

  result: null,
  setResult: (r) => set({ result: r }),

  running: false,
  runLabel: '',
  setRunning: (v, label = '') => set({ running: v, runLabel: label }),

  sentinelUp: false,
  setSentinel: (v) => set({ sentinelUp: v }),

  validations: [],
  addVal: (v) => set(s => ({ validations: [...s.validations.slice(-20), v] })),
}))