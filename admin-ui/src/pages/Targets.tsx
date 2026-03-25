import { useEffect, useState, useMemo } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import type { AppDispatch, RootState } from '../store';
import { fetchTargets, addTarget, updateTarget, deleteTarget } from '../store/targetsSlice';
import DataTable from '../components/DataTable';
import Modal from '../components/Modal';

export default function Targets() {
  const dispatch = useDispatch<AppDispatch>();
  const { items, loading } = useSelector((s: RootState) => s.targets);
  const [modal, setModal] = useState<{ mode: 'add' | 'edit'; index?: number } | null>(null);

  useEffect(() => { dispatch(fetchTargets()); }, [dispatch]);

  const fields = useMemo(() => {
    if (!modal) return [];
    const item = modal.mode === 'edit' && modal.index != null ? items[modal.index] : undefined;
    return [
      { name: 'host', label: 'Host', defaultValue: item?.host ?? '' },
      { name: 'address', label: 'Address', defaultValue: item?.address ?? '' },
    ];
  }, [modal, items]);

  const handleSave = (values: Record<string, string>) => {
    if (modal?.mode === 'add') {
      dispatch(addTarget({ host: values.host, address: values.address }));
    } else if (modal?.mode === 'edit') {
      dispatch(updateTarget({ host: values.host, address: values.address }));
    }
    setModal(null);
  };

  const handleDelete = (index: number) => {
    if (confirm(`Delete target "${items[index].host}"?`)) {
      dispatch(deleteTarget(items[index].host));
    }
  };

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Proxy Targets</h1>
        <button onClick={() => setModal({ mode: 'add' })} className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-500">
          Add Target
        </button>
      </div>
      {loading ? (
        <div className="text-gray-400">Loading...</div>
      ) : (
        <div className="bg-gray-800 rounded-xl p-4">
          <DataTable
            headers={['Host', 'Address']}
            rows={items.map((t) => [t.host, t.address])}
            onEdit={(i) => setModal({ mode: 'edit', index: i })}
            onDelete={handleDelete}
          />
        </div>
      )}
      {modal && (
        <Modal
          title={modal.mode === 'add' ? 'Add Target' : 'Edit Target'}
          fields={fields}
          onSave={handleSave}
          onCancel={() => setModal(null)}
        />
      )}
    </div>
  );
}
