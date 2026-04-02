import { useEffect, useState } from 'react'

interface CircleTimerProps {
  interval: number // milliseconds
  size?: number
  strokeWidth?: number
  className?: string
}

export function CircleTimer({
  interval,
  size = 16,
  strokeWidth = 2,
  className = ''
}: CircleTimerProps) {
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    let startTime = Date.now()
    let animationId: number

    const update = () => {
      const elapsed = Date.now() - startTime
      const pct = Math.min(elapsed / interval, 1)
      setProgress(pct)

      if (pct >= 1) {
        startTime = Date.now()
      }

      animationId = requestAnimationFrame(update)
    }

    animationId = requestAnimationFrame(update)
    return () => cancelAnimationFrame(animationId)
  }, [interval])

  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - progress)

  return (
    <svg
      width={size}
      height={size}
      className={`transform -rotate-90 ${className}`}
    >
      {/* Background circle */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        className="text-border opacity-50"
      />
      {/* Progress circle */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        className="text-accent transition-all duration-75"
      />
    </svg>
  )
}
