import { Component } from 'react'

export default class AppErrorBoundary extends Component {
  state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, details) {
    console.error('Unhandled interface error', error, details.componentStack)
  }

  render() {
    if (!this.state.hasError) return this.props.children
    return <main role="alert" style={{ maxWidth: 640, margin: '12vh auto', padding: 24, color: '#e5eaf5', fontFamily: 'sans-serif' }}>
      <h1>The app could not display this page.</h1>
      <p>Reload the page. If the issue continues, check the frontend and API logs.</p>
      <button type="button" onClick={() => window.location.reload()}>Reload app</button>
    </main>
  }
}
