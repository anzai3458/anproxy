import { useEffect, useRef, useState } from 'react'

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
  const startTimeRef = useRef(Date.now())
  const intervalIdRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    // Update progress based on actual elapsed time
    const updateProgress = () => {
      const elapsed = Date.now() - startTimeRef.current
      const newProgress = Math.min(elapsed / interval, 1)
      setProgress(newProgress)

      // Reset when interval completes
      if (newProgress >= 1) {
        startTimeRef.current = Date.now()
      }
    }

    // Handle visibility change - resync timer when tab becomes visible
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        // Reset to start fresh when user returns
        // This ensures the timer is in sync with actual data refresh
        startTimeRef.current = Date.now()
        setProgress(0)
      }
    }

    // Use setInterval which is more reliable on mobile than requestAnimationFrame
    // Browsers throttle setInterval in background but usually to 1s, not completely paused
    intervalIdRef.current = setInterval(updateProgress, 100)
    document.addEventListener('visibilitychange', handleVisibilityChange)

    return () => {
      if (intervalIdRef.current) {
        clearInterval(intervalIdRef.current)
      }
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
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
        className="text-accent transition-all"
      />
    </svg>
  )
}
