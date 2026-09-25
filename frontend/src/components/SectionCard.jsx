// src/components/SectionCard.jsx
//
// A white rounded container used for every Dashboard section
// ("Network Overview", "Protocol Distribution", ...).
// It just provides the outer look + a title, and shows whatever
// children you put inside it.

export default function SectionCard({ title, subtitle, children, className = '' }) {
  return (
    <section className={`rounded-xl border border-slate-200 bg-white shadow-sm ${className}`}>
      <header className="border-b border-slate-100 px-5 py-4">
        <h2 className="text-base font-semibold text-slate-900">{title}</h2>
        {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
      </header>
      <div className="p-5">{children}</div>
    </section>
  )
}
