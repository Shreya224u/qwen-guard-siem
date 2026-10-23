import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import AppErrorBoundary from './components/AppErrorBoundary.jsx';
import { AppStateProvider } from './state/AppStateContext.jsx';

import './styles/global.css';
import './styles/dashboard.css';
import './styles/animations.css';
import './styles/cyber-particles.css';
import './styles/app-background.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <AppStateProvider>
        <App />
      </AppStateProvider>
    </AppErrorBoundary>
  </React.StrictMode>
);
