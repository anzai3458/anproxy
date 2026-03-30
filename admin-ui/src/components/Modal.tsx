import { type ReactNode, useEffect, useRef } from 'react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
}

export default function Modal({ open, onClose, title, children }: ModalProps) {
  const backdropRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      ref={backdropRef}
      onClick={(e) => { if (e.target === backdropRef.current) onClose() }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
    >
      <div className="bg-surface border border-border rounded-lg w-full max-w-md animate-slide-up">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold text-text">{title}</h2>
          <button
            onClick={onClose}
            className="text-text-dim hover:text-text text-xs cursor-pointer"
          >
            esc
          </button>
        </div>
        <div className="p-5">
          {children}
        </div>
      </div>
    </div>
  )
}
