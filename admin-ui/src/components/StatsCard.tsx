interface Props {
  label: string;
  value: string | number;
  color?: string;
}

export default function StatsCard({ label, value, color }: Props) {
  return (
    <div className="bg-gray-800 rounded-xl p-4">
      <div className="text-gray-400 text-sm mb-1">{label}</div>
      <div className={`text-2xl font-bold ${color ?? 'text-white'}`}>{value}</div>
    </div>
  );
}
