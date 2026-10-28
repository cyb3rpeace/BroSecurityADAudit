import { Cell, Line, LineChart, Pie, PieChart, Bar, BarChart, XAxis, YAxis, CartesianGrid } from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Button } from "@/components/ui/button"

type Slice = { name: string; value: number; fill: string }

export function TrendChart({ points, color, onPoint }: { points: { label: string; score: number; scan_id: number }[]; color: string; onPoint: (scanId: number) => void }) {
  const config = { score: { label: "Индекс", color } } satisfies ChartConfig
  return (
    <ChartContainer config={config} className="aspect-auto h-[240px] w-full">
      <LineChart
        data={points}
        onClick={(state) => {
          const index = typeof state?.activeTooltipIndex === "number" ? state.activeTooltipIndex : -1
          const point = points[index]
          if (point?.scan_id) onPoint(point.scan_id)
        }}
      >
        <CartesianGrid vertical={false} />
        <XAxis dataKey="label" tickLine={false} axisLine={false} />
        <YAxis domain={[0, 100]} tickLine={false} axisLine={false} width={32} />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Line type="monotone" dataKey="score" stroke={color} strokeWidth={2} dot={{ r: 4, fill: color }} activeDot={{ r: 6 }} />
      </LineChart>
    </ChartContainer>
  )
}

export function Donut({ slices, onSlice }: { slices: Slice[]; onSlice?: (name: string) => void }) {
  const config = Object.fromEntries(slices.map((slice) => [slice.name, { label: slice.name, color: slice.fill }])) satisfies ChartConfig
  const total = slices.reduce((sum, slice) => sum + slice.value, 0)
  return (
    <div className="relative">
      <ChartContainer config={config} className="mx-auto aspect-square h-[220px]">
        <PieChart>
          <ChartTooltip content={<ChartTooltipContent hideLabel nameKey="name" />} />
          <Pie data={slices} dataKey="value" nameKey="name" innerRadius={68} outerRadius={92} paddingAngle={2} stroke="none" onClick={(_, index) => onSlice?.(slices[index]?.name || "")}>
            {slices.map((slice) => (
              <Cell key={slice.name} fill={slice.fill} className={onSlice ? "cursor-pointer" : ""} />
            ))}
          </Pie>
        </PieChart>
      </ChartContainer>
      <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
        <div>
          <b className="block text-3xl leading-none">{total}</b>
        </div>
      </div>
    </div>
  )
}

export function Bars({ rows, active, colors, onPick }: { rows: { name: string; value: number }[]; active: string; colors: string[]; onPick: (name: string) => void }) {
  const data = rows.map((row, index) => ({ ...row, fill: row.name === active ? colors[0] : colors[index % colors.length] }))
  const config = { value: { label: "Сигналы", color: colors[0] } } satisfies ChartConfig
  return (
    <ChartContainer config={config} className="aspect-auto h-[300px] w-full">
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 8 }} onClick={(state) => { if (typeof state?.activeLabel === "string") onPick(state.activeLabel) }}>
        <XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} />
        <YAxis type="category" dataKey="name" width={130} tickLine={false} axisLine={false} />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Bar dataKey="value" radius={8} barSize={16} className="cursor-pointer">
          {data.map((row) => (
            <Cell key={row.name} fill={row.fill} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}

export function LegendButtons({ items, active, onPick }: { items: { name: string; value: number; fill: string }[]; active: string; onPick: (name: string) => void }) {
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {items.map((item) => (
        <Button key={item.name} type="button" size="sm" variant={active === item.name ? "secondary" : "outline"} onClick={() => onPick(item.name)}>
          <span className="size-2 rounded-full" style={{ background: item.fill }} />
          {item.name} · {item.value}
        </Button>
      ))}
    </div>
  )
}
