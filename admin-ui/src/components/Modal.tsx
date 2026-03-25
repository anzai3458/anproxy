import { useState, useEffect } from 'react';

interface Field {
  name: string;
  label: string;
  defaultValue?: string;
}

interface Props {
  title: string;
  fields: Field[];
  onSave: (values: Record<string, string>) => void;
  onCancel: () => void;
}

export default function Modal({ title, fields, onSave, onCancel }: Props) {
  const [values, setValues] = useState<Record<string, string>>({});

  useEffect(() => {
    const init: Record<string, string> = {};
    for (const f of fields) init[f.name] = f.defaultValue ?? '';
    setValues(init);
  }, [fields]);

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onCancel}>
      <div className="bg-gray-800 rounded-xl p-6 w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-white text-lg font-bold mb-4">{title}</h2>
        {fields.map((f) => (
          <div key={f.name} className="mb-3">
            <label className="block text-gray-400 text-sm mb-1">{f.label}</label>
            <input
              className="w-full bg-gray-700 text-white rounded px-3 py-2 outline-none focus:ring-2 focus:ring-blue-500"
              value={values[f.name] ?? ''}
              onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}
            />
          </div>
        ))}
        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onCancel} className="px-4 py-2 text-gray-400 hover:text-white">Cancel</button>
          <button onClick={() => onSave(values)} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-500">Save</button>
        </div>
      </div>
    </div>
  );
}
