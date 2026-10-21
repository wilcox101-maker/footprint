import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const tipStyle = {
  background: "var(--color-elevated)",
  border: "1px solid var(--color-line)",
  borderRadius: 12,
  color: "var(--color-fg)",
  fontSize: 12,
};

export function DayLine({ data }: { data: { day: string; count: number }[] }) {
  if (!data.length) {
    return <p className="text-sm text-muted">No new entities in this window yet.</p>;
  }
  return (
    <div className="h-52">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="var(--color-line)" vertical={false} />
          <XAxis dataKey="day" tick={{ fill: "var(--color-faint)", fontSize: 11 }} tickLine={false} axisLine={false} minTickGap={24} />
          <YAxis allowDecimals={false} width={32} tick={{ fill: "var(--color-faint)", fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={tipStyle} />
          <Line type="monotone" dataKey="count" stroke="var(--color-info)" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export function CountBars({ data }: { data: { label: string; count: number }[] }) {
  if (!data.length) return <p className="text-sm text-muted">Nothing to chart.</p>;
  return (
    <div className="h-52">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="var(--color-line)" vertical={false} />
          <XAxis dataKey="label" tick={{ fill: "var(--color-faint)", fontSize: 11 }} tickLine={false} axisLine={false} interval={0} />
          <YAxis allowDecimals={false} width={32} tick={{ fill: "var(--color-faint)", fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={tipStyle} />
          <Bar dataKey="count" fill="var(--color-info)" radius={[6, 6, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
