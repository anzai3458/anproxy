import { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import type { AppDispatch, RootState } from '../store';
import { login } from '../store/authSlice';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const dispatch = useDispatch<AppDispatch>();
  const navigate = useNavigate();
  const error = useSelector((s: RootState) => s.auth.error);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const result = await dispatch(login({ username, password }));
    if (login.fulfilled.match(result)) navigate('/');
  };

  return (
    <div className="flex flex-col md:flex-row min-h-screen">
      <div className="flex-1 bg-gradient-to-br from-blue-600 to-purple-700 flex items-center justify-center p-8">
        <div className="text-center">
          <h1 className="text-5xl font-bold text-white mb-2">anproxy</h1>
          <p className="text-blue-200 text-lg">HTTPS Reverse Proxy Admin</p>
        </div>
      </div>
      <div className="flex-1 bg-gray-900 flex items-center justify-center p-8">
        <form onSubmit={handleSubmit} className="w-full max-w-sm">
          <h2 className="text-2xl font-bold text-white mb-6">Sign In</h2>
          {error && <div className="bg-red-900/50 text-red-300 rounded p-3 mb-4 text-sm">{error}</div>}
          <div className="mb-4">
            <label className="block text-gray-400 text-sm mb-1">Username</label>
            <input
              className="w-full bg-gray-800 text-white rounded px-3 py-2 outline-none focus:ring-2 focus:ring-blue-500"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="mb-6">
            <label className="block text-gray-400 text-sm mb-1">Password</label>
            <input
              type="password"
              className="w-full bg-gray-800 text-white rounded px-3 py-2 outline-none focus:ring-2 focus:ring-blue-500"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button type="submit" className="w-full bg-blue-600 text-white rounded py-2 hover:bg-blue-500 font-medium">
            Login
          </button>
        </form>
      </div>
    </div>
  );
}
