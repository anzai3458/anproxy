import { useState, useCallback, useEffect } from 'react'

export type ToastType = 'error' | 'success' | 'warning' | 'info'

export interface Toast {
  id: string
  type: ToastType
  message: string
  duration?: number
}

interface ToastState {
  toasts: Toast[]
  addToast: (type: ToastType, message: string, duration?: number) => void
  removeToast: (id: string) => void
}

let toastListeners: ((toasts: Toast[]) => void)[] = []
let toasts: Toast[] = []

const notifyListeners = () => {
  toastListeners.forEach((listener) => listener([...toasts]))
}

const addToast = (type: ToastType, message: string, duration = 5000) => {
  const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`
  const toast: Toast = { id, type, message, duration }
  toasts = [toast, ...toasts].slice(0, 5) // Max 5 toasts
  notifyListeners()

  if (duration > 0) {
    setTimeout(() => removeToast(id), duration)
  }

  return id
}

const removeToast = (id: string) => {
  toasts = toasts.filter((t) => t.id !== id)
  notifyListeners()
}

export const toast = {
  error: (message: string, duration?: number) => addToast('error', message, duration),
  success: (message: string, duration?: number) => addToast('success', message, duration),
  warning: (message: string, duration?: number) => addToast('warning', message, duration),
  info: (message: string, duration?: number) => addToast('info', message, duration),
}

export function useToast(): ToastState {
  const [localToasts, setLocalToasts] = useState<Toast[]>(toasts)

  useEffect(() => {
    const listener = (newToasts: Toast[]) => setLocalToasts(newToasts)
    toastListeners.push(listener)
    return () => {
      toastListeners = toastListeners.filter((l) => l !== listener)
    }
  }, [])

  const addToastCallback = useCallback((type: ToastType, message: string, duration?: number) => {
    addToast(type, message, duration)
  }, [])

  const removeToastCallback = useCallback((id: string) => {
    removeToast(id)
  }, [])

  return {
    toasts: localToasts,
    addToast: addToastCallback,
    removeToast: removeToastCallback,
  }
}
