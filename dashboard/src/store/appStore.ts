/**
 * src/store/appStore.ts
 * Global application state using Zustand
 */

import { create } from 'zustand'

interface AppState {
  // Current module being demonstrated
  activeModule: 'crypto' | 'recon' | 'dos' | 'validation' | 'home'
  setActiveModule: (module: AppState['activeModule']) => void

  // Attack running state
  isAttackRunning: boolean
  currentAttack: string | null
  setAttackRunning: (running: boolean, attackName?: string) => void

  // Latest results
  lastResult: Record<string, any> | null
  setLastResult: (result: Record<string, any>) => void

  // Sentinel status
  sentinelOnline: boolean
  setSentinelOnline: (online: boolean) => void

  // Validation results
  validationResults: Record<string, any>[]
  addValidationResult: (result: Record<string, any>) => void
  clearValidation: () => void

  // Terminal output lines
  terminalLines: string[]
  addTerminalLine: (line: string) => void
  clearTerminal: () => void
}

export const useAppStore = create<AppState>((set) => ({
  activeModule: 'home',
  setActiveModule: (module) => set({ activeModule: module }),

  isAttackRunning: false,
  currentAttack: null,
  setAttackRunning: (running, attackName) => set({
    isAttackRunning: running,
    currentAttack: running ? (attackName || null) : null
  }),

  lastResult: null,
  setLastResult: (result) => set({ lastResult: result }),

  sentinelOnline: false,
  setSentinelOnline: (online) => set({ sentinelOnline: online }),

  validationResults: [],
  addValidationResult: (result) => set(state => ({
    validationResults: [...state.validationResults, result]
  })),
  clearValidation: () => set({ validationResults: [] }),

  terminalLines: [
    '╔══════════════════════════════════════════════════════════╗',
    '║       THREATFORGE v0.1.0  - Security Testing Platform    ║',
    '║       Academic Project - INS Lab TE7947                  ║',
    '║       ETHICAL USE ONLY - Authorized testing environments ║',
    '╚══════════════════════════════════════════════════════════╝',
    '',
    '[SYS] System initialized. All modules loaded.',
    '[SYS] Type or click buttons to begin testing.',
    ''
  ],
  addTerminalLine: (line) => set(state => ({
    terminalLines: [...state.terminalLines.slice(-200), line]
  })),
  clearTerminal: () => set({ terminalLines: [] })
}))
