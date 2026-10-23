import { createContext, useCallback, useContext, useEffect, useMemo, useReducer } from 'react'

const AppStateContext = createContext(null)

function createInitialState() {
  const passwordResetPending = new URLSearchParams(window.location.search).has('reset_token')
  if (passwordResetPending) {
    localStorage.removeItem('siem-token')
    localStorage.removeItem('siem-user')
  }
  return {
    theme: localStorage.getItem('siem-theme') || 'dark',
    token: passwordResetPending ? '' : localStorage.getItem('siem-token') || '',
    user: passwordResetPending ? '' : localStorage.getItem('siem-user') || '',
    userRole: '',
  }
}

function appStateReducer(state, action) {
  switch (action.type) {
    case 'theme/changed':
      return { ...state, theme: action.theme }
    case 'session/started':
      return { ...state, token: action.session.access_token, user: action.session.username, userRole: '' }
    case 'session/role-loaded':
      return { ...state, userRole: action.role }
    case 'session/ended':
      return { ...state, token: '', user: '', userRole: '' }
    default:
      return state
  }
}

export function AppStateProvider({ children }) {
  const [state, dispatch] = useReducer(appStateReducer, undefined, createInitialState)
  useEffect(() => {
    document.documentElement.dataset.theme = state.theme
    localStorage.setItem('siem-theme', state.theme)
  }, [state.theme])
  useEffect(() => {
    if (state.token && state.user) {
      localStorage.setItem('siem-token', state.token)
      localStorage.setItem('siem-user', state.user)
    } else {
      localStorage.removeItem('siem-token')
      localStorage.removeItem('siem-user')
    }
  }, [state.token, state.user])

  const setTheme = useCallback(theme => dispatch({ type: 'theme/changed', theme }), [])
  const signIn = useCallback(session => dispatch({ type: 'session/started', session }), [])
  const setUserRole = useCallback(role => dispatch({ type: 'session/role-loaded', role }), [])
  const signOut = useCallback(() => dispatch({ type: 'session/ended' }), [])
  const value = useMemo(() => ({ ...state, setTheme, signIn, setUserRole, signOut }), [state, setTheme, signIn, setUserRole, signOut])

  return <AppStateContext.Provider value={value}>{children}</AppStateContext.Provider>
}

export function useAppState() {
  const state = useContext(AppStateContext)
  if (!state) throw new Error('useAppState must be used within AppStateProvider.')
  return state
}
