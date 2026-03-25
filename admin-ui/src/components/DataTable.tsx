interface Props {
  headers: string[];
  rows: string[][];
  onEdit?: (index: number) => void;
  onDelete?: (index: number) => void;
}

export default function DataTable({ headers, rows, onEdit, onDelete }: Props) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <thead>
          <tr className="border-b border-gray-700">
            {headers.map((h) => (
              <th key={h} className="py-2 px-3 text-gray-400 text-sm font-medium">{h}</th>
            ))}
            {(onEdit || onDelete) && <th className="py-2 px-3 text-gray-400 text-sm font-medium">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-gray-700/50 hover:bg-gray-800/50">
              {row.map((cell, j) => (
                <td key={j} className="py-2 px-3 text-gray-300">{cell}</td>
              ))}
              {(onEdit || onDelete) && (
                <td className="py-2 px-3 flex gap-2">
                  {onEdit && (
                    <button onClick={() => onEdit(i)} className="text-blue-400 hover:text-blue-300 text-sm">Edit</button>
                  )}
                  {onDelete && (
                    <button onClick={() => onDelete(i)} className="text-red-400 hover:text-red-300 text-sm">Delete</button>
                  )}
                </td>
              )}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr><td colSpan={headers.length + 1} className="py-4 text-center text-gray-500">No data</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
