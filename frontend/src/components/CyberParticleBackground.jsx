import { useEffect, useRef } from 'react'

const palette = [
  { r: 54, g: 224, b: 192, light: { r: 20, g: 125, b: 115 } },
  { r: 87, g: 149, b: 255, light: { r: 57, g: 120, b: 212 } },
  { r: 45, g: 196, b: 166, light: { r: 32, g: 145, b: 132 } },
  { r: 128, g: 190, b: 255, light: { r: 66, g: 132, b: 220 } },
]

export default function CyberParticleBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const context = canvas?.getContext('2d', { alpha: true })
    if (!canvas || !context) return undefined

    const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)')
    let width = 0
    let height = 0
    let pixelRatio = 1
    let frame = 0
    let particles = []
    let ripples = []

    const makeParticles = () => {
      const mobile = width < 700
      const target = Math.round(width * height / 15000)
      const count = Math.min(mobile ? 42 : 90, Math.max(mobile ? 26 : 40, target))
      particles = Array.from({ length: count }, () => {
        const speed = mobile ? 0.15 : 0.2
        return {
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * speed,
          vy: (Math.random() - 0.5) * speed,
          radius: Math.random() * 1.15 + 0.7,
          color: palette[Math.floor(Math.random() * palette.length)],
          alpha: Math.random() * 0.25 + 0.65,
        }
      })
    }

    const resize = () => {
      const oldWidth = width
      const oldHeight = height
      width = window.innerWidth
      height = window.innerHeight
      pixelRatio = Math.min(window.devicePixelRatio || 1, 1.75)
      canvas.width = Math.round(width * pixelRatio)
      canvas.height = Math.round(height * pixelRatio)
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0)
      if (particles.length && oldWidth && oldHeight) {
        const scaleX = width / oldWidth
        const scaleY = height / oldHeight
        particles.forEach(p => { p.x *= scaleX; p.y *= scaleY })
      } else makeParticles()
      if (motionPreference.matches) draw()
    }

    const createRipple = event => {
      if (motionPreference.matches) return
      const point = event.changedTouches?.[0] ?? event
      ripples.push({ x: point.clientX, y: point.clientY, startedAt: performance.now() })
      ripples = ripples.slice(-4)
    }

    const draw = (timestamp = performance.now()) => {
      context.clearRect(0, 0, width, height)
      const light = document.documentElement.dataset.theme === 'light'
      const linkReach = width < 700 ? 94 : 132
      const baseLine = light ? 0.3 : 0.38
      const pointAlpha = 1
      const time = motionPreference.matches ? 0 : timestamp

      const ambient = (x, y, radius, opacity) => {
        const gradient = context.createRadialGradient(x, y, 0, x, y, radius)
        gradient.addColorStop(0, `rgba(54, 224, 192, ${opacity})`)
        gradient.addColorStop(1, 'rgba(54, 224, 192, 0)')
        context.fillStyle = gradient
        context.fillRect(0, 0, width, height)
      }
      ambient(
        width * (0.18 + Math.sin(time * 0.00017) * 0.035),
        height * 0.2,
        Math.max(width * 0.38, 260),
        light ? 0.025 : 0.065,
      )
      ambient(
        width * (0.82 + Math.cos(time * 0.00013) * 0.04),
        height * 0.78,
        Math.max(width * 0.34, 240),
        light ? 0.02 : 0.05,
      )

      if (!motionPreference.matches) {
        const sweepY = (time * 0.008) % (height + 180) - 90
        const sweep = context.createLinearGradient(0, sweepY - 65, 0, sweepY + 65)
        sweep.addColorStop(0, 'rgba(54, 224, 192, 0)')
        sweep.addColorStop(0.5, `rgba(54, 224, 192, ${light ? 0.018 : 0.045})`)
        sweep.addColorStop(1, 'rgba(54, 224, 192, 0)')
        context.fillStyle = sweep
        context.fillRect(0, sweepY - 65, width, 130)

        const pointOnCurve = (start, control1, control2, end, progress) => {
          const inverse = 1 - progress
          return {
            x: inverse ** 3 * start.x + 3 * inverse ** 2 * progress * control1.x + 3 * inverse * progress ** 2 * control2.x + progress ** 3 * end.x,
            y: inverse ** 3 * start.y + 3 * inverse ** 2 * progress * control1.y + 3 * inverse * progress ** 2 * control2.y + progress ** 3 * end.y,
          }
        }

        for (let i = 0; i < 4; i++) {
          const startY = height * (0.12 + i * 0.2)
          const endY = height * (0.78 - i * 0.18)
          const wave = Math.sin(time * 0.00025 + i * 1.7) * height * 0.1
          const start = { x: -width * 0.08, y: startY }
          const control1 = { x: width * 0.28, y: startY + wave }
          const control2 = { x: width * 0.68, y: endY - wave }
          const end = { x: width * 1.08, y: endY }

          context.beginPath()
          context.moveTo(start.x, start.y)
          context.bezierCurveTo(control1.x, control1.y, control2.x, control2.y, end.x, end.y)
          context.setLineDash([2, 22])
          context.lineDashOffset = -time * 0.028
          context.strokeStyle = `rgba(${light ? '20, 125, 115' : '87, 149, 255'}, ${light ? 0.18 : 0.25})`
          context.lineWidth = 1
          context.stroke()
          context.setLineDash([])

          for (let pulse = 0; pulse < 2; pulse++) {
            const progress = (time * 0.00011 + i * 0.19 + pulse * 0.5) % 1
            const position = pointOnCurve(start, control1, control2, end, progress)
            const radius = 2.1 + Math.sin(time * 0.006 + i + pulse) * 0.7
            context.beginPath()
            context.arc(position.x, position.y, radius, 0, Math.PI * 2)
            context.fillStyle = `rgba(${light ? '20, 125, 115' : '54, 224, 192'}, ${light ? 0.72 : 0.9})`
            context.shadowColor = 'rgba(54, 224, 192, 0.9)'
            context.shadowBlur = 14
            context.fill()
            context.shadowBlur = 0
          }
        }
      }

      ripples = ripples.filter(ripple => time - ripple.startedAt < 900)
      ripples.forEach(ripple => {
        const progress = Math.max(0, (time - ripple.startedAt) / 900)
        const radius = 12 + progress * (width < 700 ? 70 : 105)
        context.beginPath()
        context.arc(ripple.x, ripple.y, radius, 0, Math.PI * 2)
        context.strokeStyle = `rgba(${light ? '20, 125, 115' : '54, 224, 192'}, ${(1 - progress) * (light ? 0.28 : 0.42)})`
        context.lineWidth = 1.2
        context.stroke()
      })

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i]
        if (!motionPreference.matches) {
          p.x += p.vx
          p.y += p.vy
          if (p.x < -8) p.x = width + 8
          else if (p.x > width + 8) p.x = -8
          if (p.y < -8) p.y = height + 8
          else if (p.y > height + 8) p.y = -8
        }

        const x = p.x
        const y = p.y
        for (let j = i + 1; j < particles.length; j++) {
          const q = particles[j]
          const dx = x - q.x
          const dy = y - q.y
          const distance = Math.hypot(dx, dy)
          if (distance >= linkReach) continue
          const alpha = Math.max(0.015, (1 - distance / linkReach) * baseLine)
          context.beginPath()
          context.moveTo(x, y)
          context.lineTo(q.x, q.y)
          context.strokeStyle = `rgba(${light ? '131, 0, 0' : '255, 80, 80'}, ${alpha})`
          context.lineWidth = light ? 0.9 : 0.75
          context.stroke()

          if ((i + j) % 7 === 0 && !motionPreference.matches) {
            const progress = (time * 0.00008 + i * 0.173 + j * 0.113) % 1
            context.beginPath()
            context.arc(x + (q.x - x) * progress, y + (q.y - y) * progress, 1.35, 0, Math.PI * 2)
            context.fillStyle = `rgba(54, 224, 192, ${light ? 0.28 : 0.36})`
            context.fill()
          }
        }

        const color = light ? p.color.light : p.color
        context.beginPath()
        context.arc(x, y, p.radius, 0, Math.PI * 2)
        context.fillStyle = `rgba(${color.r}, ${color.g}, ${color.b}, ${p.alpha * pointAlpha})`
        context.shadowColor = `rgba(${color.r}, ${color.g}, ${color.b}, ${light ? 0.55 : 0.94})`
        context.shadowBlur = light ? 7 : 10
        context.fill()
        context.shadowBlur = 0
      }

      if (!motionPreference.matches) frame = window.requestAnimationFrame(draw)
    }

    resize()
    draw()
    window.addEventListener('resize', resize, { passive: true })
    window.addEventListener('pointerdown', createRipple, { passive: true })

    return () => {
      window.cancelAnimationFrame(frame)
      window.removeEventListener('resize', resize)
      window.removeEventListener('pointerdown', createRipple)
    }
  }, [])

  return <canvas ref={canvasRef} className="cyber-particle-background" aria-hidden="true"/>
}
