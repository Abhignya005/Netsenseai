// src/components/DataTable.jsx
//
// A simple reusable table. The Dashboard uses it twice:
//   - Recent Alerts   (columns: Severity, Message, Time)
//   - Connected Devices (columns: IP, MAC, Hostname, Type, Status)
// You pass the column headers and the rows as JSX.

export default function DataTable({ headers, children }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-slate-200">
            {headers.map((header) => (
              <th key={header} className="px-3 py-2.5 text-xs font-semibold uppercase tracking-wider text-slate-500">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">{children}</tbody>
      </table>
    </div>
  )
}
