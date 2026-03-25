import { useEffect, useState, useMemo } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import type { AppDispatch, RootState } from '../store';
import { fetchStaticDirs, addStaticDir, updateStaticDir, deleteStaticDir } from '../store/staticDirsSlice';
import DataTable from '../components/DataTable';
import Modal from '../components/Modal';

export default function StaticDirs() {
  const dispatch = useDispatch<AppDispatch>();
  const { items, loading } = useSelector((s: RootState) => s.staticDirs);
  const [modal, setModal] = useState<{ mode: 'add' | 'edit'; index?: number } | null>(null);

  useEffect(() => { dispatch(fetchStaticDirs()); }, [dispatch]);

  const fields = useMemo(() => {
    if (!modal) return [];
    const item = modal.mode === 'edit' && modal.index != null ? items[modal.index] : undefined;
    return [
      { name: 'host', label: 'Host', defaultValue: item?.host ?? '' },
      { name: 'dir', label: 'Directory', defaultValue: item?.dir ?? '' },
    ];
  }, [modal, items]);

  const handleSave = (values: Record<string, string>) => {
    if (modal?.mode === 'add') {
      dispatch(addStaticDir({ host: values.host, dir: values.dir }));
    } else if (modal?.mode === 'edit') {
      dispatch(updateStaticDir({ host: values.host, dir: values.dir }));
    }
    setModal(null);
  };

  const handleDelete = (index: number) => {
    if (confirm(`Delete static dir "${items[index].host}"?`)) {
      dispatch(deleteStaticDir(items[index].host));
    }
  };

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Static Directories</h1>
        <button onClick={() => setModal({ mode: 'add' })} className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-500">
          Add Static Dir
        </button>
      </div>
      {loading ? (
        <div className="text-gray-400">Loading...</div>
      ) : (
        <div className="bg-gray-800 rounded-xl p-4">
          <DataTable
            headers={['Host', 'Directory']}
            rows={items.map((s) => [s.host, s.dir])}
            onEdit={(i) => setModal({ mode: 'edit', index: i })}
            onDelete={handleDelete}
          />
        </div>
      )}
      {modal && (
        <Modal
          title={modal.mode === 'add' ? 'Add Static Dir' : 'Edit Static Dir'}
          fields={fields}
          onSave={handleSave}
          onCancel={() => setModal(null)}
        />
      )}
    </div>
  );
}
