import { create } from 'zustand'

export type LogType = 'info'|'success'|'error'|'attack'|'system'|'warning'|'validation'

export interface LogLine {
  id:      number
  time:    string
  source:  string
  message: string
  type:    LogType
}

let lid = 0

interface S {
  lines:      LogLine[]
  addLine:    (src: string, msg: string, t?: LogType) => void
  clearLines: () => void
  result:     any
  setResult:  (r: any) => void
  running:    boolean
  runLabel:   string
  setRunning: (v: boolean, lbl?: string) => void
  sentUp:     boolean
  setSent:    (v: boolean) => void
  vals:       any[]
  addVal:     (v: any) => void
}

export const useStore = create<S>((set) => ({
  lines: [],
  addLine: (src, msg, t = 'info') => set(s => ({
    lines: [...s.lines.slice(-400), {
      id: lid++,
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      source: src.toUpperCase().slice(0, 8),
      message: msg,
      type: t,
    }]
  })),
  clearLines: () => set({ lines: [] }),

  result: null,
  setResult: (r) => set({ result: r }),

  running: false,
  runLabel: '',
  setRunning: (v, lbl = '') => set({ running: v, runLabel: lbl }),

  sentUp: false,
  setSent: (v) => set({ sentUp: v }),

  vals: [],
  addVal: (v) => set(s => ({ vals: [...s.vals.slice(-20), v] })),
}))
