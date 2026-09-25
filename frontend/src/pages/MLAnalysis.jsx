// src/pages/MLAnalysis.jsx — PHASE 8: machine learning analysis
//
// Data sources (all honest — missing models show "Not available",
// never fake predictions or invented metrics):
//   GET /api/ml/status      -> classifier / anomaly availability
//   GET /api/ml/features    -> the 10 behavioral features
//   GET /api/ml/model-info  -> classes, REAL training metrics, importances
//   POST /api/ml/analyze    -> classify + anomaly-score one flow
//
// Layout (sections 19-20):
//   1. Model status cards + dataset
//   2. Try-it-yourself flow analyzer (live inference)
//   3. Model metrics (real training numbers)
//   4. Feature importance (model-derived bars)
//   5. Feature list with live-traffic availability

import { useCallback, useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import Badge from '../components/Badge.jsx'
import DataTable from '../components/DataTable.jsx'
import SectionCard from '../components/SectionCard.jsx'
import {
  analyzeFlow,
  fetchMlFeatures,
  fetchMlModelInfo,
  fetchMlStatus,
} from '../api.js'

// Example flow presets — REAL feature shapes, clearly labeled as
// examples for the try-it form (never presented as live results).
const EXAMPLE_FLOWS = {
  calm: {
    flow_duration: 12.4, pkt_count_fwd: 20, pkt_count_bwd: 15,
    byte_rate: 1240.5, pkt_rate: 2.8, iat_mean: 430, iat_std: 120,
    syn_ratio: 0.05, rst_ratio: 0.01, avg_pkt_size: 440.2,
  },
  aggressive: {
    flow_duration: 3.1, pkt_count_fwd: 940, pkt_count_bwd: 4,
    byte_rate: 980_000, pkt_rate: 305, iat_mean: 3.2, iat_std: 1.1,
    syn_ratio: 0.92, rst_ratio: 0.35, avg_pkt_size: 1400,
  },
}

export default function MLAnalysis() {
  const [status, setStatus] = useState(null)
  const [features, setFeatures] = useState(null)
  const [modelInfo, setModelInfo] = useState(null)
  const [error, setError] = useState(null)

  const [flow, setFlow] = useState(EXAMPLE_FLOWS.calm)
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [analyzeError, setAnalyzeError] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [statusData, featureData, infoData] = await Promise.all([
        fetchMlStatus(),
        fetchMlFeatures(),
        fetchMlModelInfo(),
      ])
      setStatus(statusData)
      setFeatures(featureData)
      setModelInfo(infoData)
      setError(null)
    } catch (e) {
      setError(e.message)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  async function runAnalysis(event) {
    event.preventDefault()
    setAnalyzing(true)
    setAnalyzeError(null)
    setResult(null)
    try {
      setResult(await analyzeFlow(flow))
    } catch (e) {
      setAnalyzeError(e.message)
    } finally {
      setAnalyzing(false)
    }
  }

  const classifierReady = status?.classifier_available === true
  const anomalyReady = status?.anomaly_model_available === true
  const importance = modelInfo?.feature_importance ?? []
  const metrics = modelInfo?.metrics
  const importanceChart = importance.map((item) => ({
    name: item.feature.replace(/_/g, ' '),
    importance: item.importance,
  }))

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900">ML Analysis</h1>
        <p className="mt-1 text-sm text-slate-500">
          Machine-learning intelligence over real flow features — cautious
          wording, real metrics only, no claim of attack certainty.
        </p>
      </header>

      {error && (
        <p className="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          ⚠ {error}
        </p>
      )}

      {/* 1. ---- Model status + dataset (section 19) ---- */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            label: 'Classifier', value: classifierReady ? 'Available' : 'Not Available',
            sub: modelInfo?.classifier ?? 'Random Forest (not trained)', ok: classifierReady,
          },
          {
            label: 'Anomaly Detector', value: anomalyReady ? 'Available' : 'Not Available',
            sub: modelInfo?.anomaly_model ?? 'Isolation Forest (not trained)', ok: anomalyReady,
          },
          { label: 'Dataset', value: status?.dataset ?? 'CICIDS2017', sub: 'placed in ml/data/' },
          {
            label: 'Training Status', value: modelInfo?.training_status ?? 'not trained',
            sub: `${modelInfo?.feature_count ?? 10} behavioral features`,
          },
        ].map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">{card.label}</p>
            <p className={`mt-2 text-lg font-bold ${card.ok === undefined ? 'text-slate-900' : card.ok ? 'text-emerald-600' : 'text-slate-400'}`}>
              {card.value}
            </p>
            <p className="mt-1 text-[11px] text-slate-400">{card.sub}</p>
          </div>
        ))}
      </div>

      {!classifierReady && !anomalyReady && (
        <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-5 py-4 text-sm text-amber-800">
          <p className="font-semibold">No models trained yet — nothing is faked.</p>
          <p className="mt-1 text-xs leading-relaxed">
            Download CICIDS2017 CSV files into <code>ml/data/</code>, then run
            <code> python ml/train_classifier.py</code> and
            <code> python ml/train_anomaly.py</code>. See <code>ml/README.md</code>.
            Every result on this page comes only from models you actually trained.
          </p>
        </div>
      )}

      {/* 2. ---- Flow analyzer (section 18 + §1 wording) ---- */}
      <SectionCard
        title="Analyze a Flow"
        subtitle="Enter behavioral flow features — the models answer with careful, non-certain wording"
        className="mt-6"
      >
        <form onSubmit={runAnalysis} className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
            Example flow preset
            <select
              value={flow === EXAMPLE_FLOWS.calm ? 'calm' : 'aggressive'}
              onChange={(e) => setFlow(EXAMPLE_FLOWS[e.target.value])}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
            >
              <option value="calm">Calm browsing-like flow</option>
              <option value="aggressive">Aggressive flood-like flow</option>
            </select>
          </label>
          <button
            type="submit"
            disabled={analyzing || (!classifierReady && !anomalyReady)}
            className="rounded-lg bg-sky-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {analyzing ? 'Analyzing…' : 'Analyze flow'}
          </button>
          <p className="max-w-sm text-[11px] text-slate-400">
            The example presets are input shapes for this form — results always
            come from the trained models, never from the presets.
          </p>
        </form>

        {analyzeError && (
          <p className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-4 py-2.5 text-sm text-rose-700">⚠ {analyzeError}</p>
        )}

        {result && (
          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded-xl border border-slate-200 p-5">
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Traffic Classification</p>
              {result.classification.available ? (
                <>
                  <p className="mt-2 text-2xl font-bold text-slate-900">{result.classification.label}</p>
                  <p className="mt-1 text-sm text-slate-500">
                    Model confidence: {(result.classification.confidence * 100).toFixed(1)}%
                  </p>
                </>
              ) : (
                <p className="mt-2 text-sm text-slate-400">Classifier not available.</p>
              )}
            </div>
            <div className="rounded-xl border border-slate-200 p-5">
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Anomaly Detection</p>
              {result.anomaly.available ? (
                <>
                  <p className={`mt-2 text-2xl font-bold ${result.anomaly.status === 'normal' ? 'text-emerald-600' : 'text-amber-600'}`}>
                    {result.anomaly.status === 'normal' ? 'No significant anomaly detected' : 'Potentially anomalous traffic'}
                  </p>
                  <p className="mt-1 text-sm text-slate-500">
                    Anomaly score: {result.anomaly.score} · not proof of an attack
                  </p>
                </>
              ) : (
                <p className="mt-2 text-sm text-slate-400">Anomaly detector not available.</p>
              )}
            </div>
            {result.skipped && (
              <p className="lg:col-span-2 rounded-lg bg-slate-50 px-4 py-2.5 text-xs text-slate-500">{result.skipped}</p>
            )}
          </div>
        )}
      </SectionCard>

      {/* 3. ---- Model metrics (section 19, REAL numbers) ---- */}
      {metrics && (
        <SectionCard title="Model Metrics" subtitle="Real held-out test-set numbers from training" className="mt-6">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              ['Accuracy', metrics.accuracy], ['Precision', metrics.precision],
              ['Recall', metrics.recall], ['F1 Score', metrics.f1],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-slate-100 p-4 text-center">
                <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</p>
                <p className="mt-1 text-2xl font-bold text-slate-900">{(value * 100).toFixed(1)}%</p>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Trained on {metrics.samples_train?.toLocaleString()} samples · tested on {metrics.samples_test?.toLocaleString()} ·
            classes: {metrics.classes?.join(', ')}
          </p>
        </SectionCard>
      )}

      {/* 4. ---- Feature importance (section 20, model-derived) ---- */}
      {importanceChart.length > 0 && (
        <SectionCard title="Feature Importance" subtitle="Random Forest importances — actual model values, not manually assigned" className="mt-6">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={importanceChart} layout="vertical" margin={{ top: 5, right: 30, left: 90, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis type="number" tickLine={false} axisLine={false} fontSize={11} />
                <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} fontSize={11} width={140} />
                <Tooltip formatter={(value) => [value.toFixed(3), 'Importance']} />
                <Bar dataKey="importance" fill="#0ea5e9" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </SectionCard>
      )}

      {/* 5. ---- Feature list (section 14) ---- */}
      {features && (
        <SectionCard
          title={`Model Features (${features.feature_count})`}
          subtitle="Behavioral flow features only — IPs/ports/timestamps are excluded to prevent data leakage"
          className="mt-6"
        >
          <DataTable headers={['Feature', 'Available from Live Traffic', 'Note']}>
            {features.features.map((name) => (
              <tr key={name} className="hover:bg-slate-50">
                <td className="px-3 py-2.5 font-mono text-xs font-medium text-slate-800">{name}</td>
                <td className="px-3 py-2.5">
                  {features.available_from_live_traffic?.[name]
                    ? <Badge>YES</Badge>
                    : <Badge>UNAVAILABLE</Badge>}
                </td>
                <td className="px-3 py-2.5 text-xs text-slate-400">
                  {name.includes('IAT') ? 'Phase 4 flow engine (ms → µs)'
                    : name.includes('Ratio') ? 'Derived from Phase 4 flag counters'
                    : 'Phase 4 flow engine'}
                </td>
              </tr>
            ))}
          </DataTable>
          <ul className="mt-3 list-inside list-disc space-y-1 text-xs text-slate-400">
            {features.notes?.map((note) => <li key={note}>{note}</li>)}
          </ul>
        </SectionCard>
      )}
    </div>
  )
}
