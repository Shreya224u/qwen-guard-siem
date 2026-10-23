import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'

const axis = { fill: '#8794aa', fontSize: 11 }
const tooltipStyle = { background: '#11192a', border: '1px solid rgba(133,157,190,.2)', borderRadius: 8, color: '#e5eaf5' }
const activitySeries = {
  events: 'Logs · event time',
  threats: 'Alerts · event time',
  ingested_events: 'Logs · ingestion time',
  ingested_threats: 'Alerts · ingestion time',
}

function ActivityTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return <div style={{ ...tooltipStyle, maxWidth: 220, padding: '9px 11px', boxShadow: '0 8px 24px #0006' }}>
    <strong style={{ display: 'block', marginBottom: 6, fontSize: 12 }}>{label}</strong>
    <div className="activity-tooltip-rows">{payload.map(item => <div className="activity-tooltip-row" key={item.dataKey}>
      <i style={{ background: item.color }}/><span>{activitySeries[item.dataKey] || item.name}</span><strong>{Number(item.value) || 0}</strong>
    </div>)}</div>
  </div>
}

const severityMeaning = {
  Critical: 'Urgent threat indicators; investigate immediately.',
  High: 'High risk indicators; prioritize investigation.',
  Medium: 'Potentially suspicious activity; review the event.',
  Low: 'Low risk or informational activity.',
  Unknown: 'The uploaded row did not provide a recognized severity.',
}

function SeverityTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const { name, count, value, color } = payload[0].payload
  return <div style={{ ...tooltipStyle, padding: '10px 12px', maxWidth: 230, boxShadow: '0 8px 24px #0006' }}>
    <strong style={{ color, display: 'block', marginBottom: 4 }}>{name}</strong>
    <div>{count} detected - {value}% of uploaded rows</div>
    <small style={{ display: 'block', marginTop: 5, color: '#aab6c9', lineHeight: 1.45 }}>{severityMeaning[name]}</small>
  </div>
}

export function EventsLineChart({ data = [] }) {
  if (!data.some(row => row.events || row.threats || row.ingested_events || row.ingested_threats)) return <div className="chart-empty">No log or alert records exist in this time range.</div>
  return <div className="events-chart"><ResponsiveContainer><LineChart data={data} margin={{ top: 8, right: 8, left: -14, bottom: 0 }}><CartesianGrid stroke="rgba(133,157,190,.12)" strokeDasharray="3 3"/><XAxis dataKey="time" tick={axis} axisLine={false} tickLine={false} minTickGap={18}/><YAxis tick={axis} axisLine={false} tickLine={false} width={34} allowDecimals={false}/><Tooltip content={<ActivityTooltip/>} wrapperStyle={{ zIndex: 10, pointerEvents: 'none' }}/><Line type="monotone" dataKey="events" name={activitySeries.events} stroke="#5795ff" strokeWidth={2.5} dot={false} activeDot={{ r: 4 }}/><Line type="monotone" dataKey="threats" name={activitySeries.threats} stroke="#ff5f72" strokeWidth={2} dot={false} activeDot={{ r: 4 }}/><Line type="monotone" dataKey="ingested_events" name={activitySeries.ingested_events} stroke="#ffc857" strokeWidth={2} strokeDasharray="5 4" dot={false} activeDot={{ r: 4 }}/><Line type="monotone" dataKey="ingested_threats" name={activitySeries.ingested_threats} stroke="#bc8cff" strokeWidth={2} strokeDasharray="5 4" dot={false} activeDot={{ r: 4 }}/></LineChart></ResponsiveContainer></div>
}

export function SeverityDonut({ data = [] }) {
  if (!data.some(row => row.value > 0)) return <div className="chart-empty">No severity data available.</div>
  return <div className="severity-chart"><ResponsiveContainer><PieChart><Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={88} paddingAngle={1.5} stroke="none">{data.map(x => <Cell key={x.name} fill={x.color}/>)}</Pie><Tooltip content={<SeverityTooltip/>}/></PieChart></ResponsiveContainer></div>
}

export function AttackBarChart({ data = [] }) {
  if (!data.length) return <div className="chart-empty">No alert categories available.</div>
  return <div className="category-chart"><ResponsiveContainer><BarChart data={data} layout="vertical" margin={{ top: 3, right: 12, left: 8, bottom: 0 }}><CartesianGrid stroke="rgba(133,157,190,.12)" horizontal={false}/><XAxis type="number" tick={axis} axisLine={false} tickLine={false} allowDecimals={false}/><YAxis type="category" dataKey="name" width={116} tick={axis} axisLine={false} tickLine={false}/><Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'transparent', stroke: 'none' }}/><Bar dataKey="count" fill="#36e0c0" radius={[0, 5, 5, 0]} maxBarSize={18}/></BarChart></ResponsiveContainer></div>
}
