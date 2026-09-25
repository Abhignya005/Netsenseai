// src/main.jsx — the very first JavaScript file the browser loads.
//
// 1. It finds the <div id="root"> in index.html
// 2. It renders the <App /> component tree into it
// 3. It wraps everything in <BrowserRouter>, which enables the
//    sidebar navigation (react-router)

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

// Opt in to React Router v7 behaviors now so v6 stops logging
// future-flag warnings in the browser console (Phase 10 §26).
const ROUTER_FUTURE = {
  v7_startTransition: true,
  v7_relativeSplatPath: true,
}

import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter future={ROUTER_FUTURE}>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
