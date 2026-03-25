import { createAsyncThunk, createSlice } from '@reduxjs/toolkit';
import { api } from '../api';

interface Stats {
  active_connections: number;
  total_requests: number;
  errors: number;
  cert_expiry_days: number;
}

interface StatsState {
  data: Stats | null;
  loading: boolean;
  error: string | null;
}

const initialState: StatsState = { data: null, loading: false, error: null };

export const fetchStats = createAsyncThunk('stats/fetch', async () => {
  return (await api.getStats()) as Stats;
});

const statsSlice = createSlice({
  name: 'stats',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchStats.pending, (state) => { state.loading = true; })
      .addCase(fetchStats.fulfilled, (state, action) => {
        state.data = action.payload;
        state.loading = false;
        state.error = null;
      })
      .addCase(fetchStats.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message ?? 'Failed to fetch stats';
      });
  },
});

export default statsSlice.reducer;
