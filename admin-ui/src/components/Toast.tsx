import type { ToastType } from '../hooks/useToast.ts'

interface ToastProps {
  type: ToastType
  message: string
  onClose: () => void
}

const typeStyles: Record<ToastType, string> = {
  error: 'bg-red/10 border-red/30 text-red',
  success: 'bg-green/10 border-green/30 text-green',
  warning: 'bg-yellow/10 border-yellow/30 text-yellow',
  info: 'bg-blue/10 border-blue/30 text-blue',
}

const typeIcons: Record<ToastType, string> = {
  error: '✕',
  success: '✓',
  warning: '⚠',
  info: 'ℹ',
}

export default function Toast({ type, message, onClose }: ToastProps) {
  return (
    <div
      className={`flex items-center gap-3 px-4 py-3 rounded border ${typeStyles[type]} shadow-lg shadow-black/20 animate-slide-up`}
      role="alert"
    >
      <span className="flex items-center justify-center w-5 h-5 text-xs font-bold shrink-0">
        {typeIcons[type]}
      </span>
      <p className="flex-1 text-xs font-medium leading-relaxed">{message}</p>
      <button
        onClick={onClose}
        className="shrink-0 text-xs opacity-60 hover:opacity-100 transition-opacity cursor-pointer"
        aria-label="Dismiss"
      >
        ×
      </button>
    </div>
  )
}
