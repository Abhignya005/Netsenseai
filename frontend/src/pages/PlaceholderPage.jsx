// src/pages/PlaceholderPage.jsx
//
// A generic page shown for every section that is not implemented yet.
// It reads the page title from the URL (react-router) and shows the
// "Coming in next stage" message.

import { Hammer, Rocket } from 'lucide-react'
import { useParams } from 'react-router-dom'

// Turns "/tcp-analysis" into "Tcp Analysis" for the title.
function titleFromSlug(slug) {
  return slug
    .split('-')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

export default function PlaceholderPage() {
  const { slug } = useParams()

  return (
    <div className="flex h-full items-center justify-center p-8">
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-10 text-center shadow-sm">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-sky-100">
          <Hammer className="h-7 w-7 text-sky-600" />
        </div>

        <h1 className="mt-5 text-xl font-bold text-slate-900">{titleFromSlug(slug)}</h1>
        <p className="mt-2 text-sm text-slate-500">
          This section is part of the NetSense roadmap but is not implemented yet.
        </p>

        <div className="mt-6 inline-flex items-center gap-2 rounded-lg bg-amber-50 px-4 py-2 text-sm font-semibold text-amber-700">
          <Rocket className="h-4 w-4" />
          Coming in next stage
        </div>
      </div>
    </div>
  )
}
