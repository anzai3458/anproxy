import { createAsyncThunk, createSlice } from '@reduxjs/toolkit';
import { api } from '../api';

interface Target {
  host: string;
  address: string;
}

interface TargetsState {
  items: Target[];
  loading: boolean;
  error: string | null;
}

const initialState: TargetsState = { items: [], loading: false, error: null };

export const fetchTargets = createAsyncThunk('targets/fetch', async () => {
  return (await api.getTargets()) as Target[];
});

export const addTarget = createAsyncThunk(
  'targets/add',
  async ({ host, address }: Target) => {
    await api.addTarget(host, address);
    return (await api.getTargets()) as Target[];
  },
);

export const updateTarget = createAsyncThunk(
  'targets/update',
  async ({ host, address }: Target) => {
    await api.updateTarget(host, address);
    return (await api.getTargets()) as Target[];
  },
);

export const deleteTarget = createAsyncThunk(
  'targets/delete',
  async (host: string) => {
    await api.deleteTarget(host);
    return (await api.getTargets()) as Target[];
  },
);

const targetsSlice = createSlice({
  name: 'targets',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchTargets.pending, (state) => { state.loading = true; })
      .addCase(fetchTargets.fulfilled, (state, action) => {
        state.items = action.payload;
        state.loading = false;
        state.error = null;
      })
      .addCase(fetchTargets.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message ?? 'Failed to fetch targets';
      })
      .addCase(addTarget.fulfilled, (state, action) => { state.items = action.payload; })
      .addCase(updateTarget.fulfilled, (state, action) => { state.items = action.payload; })
      .addCase(deleteTarget.fulfilled, (state, action) => { state.items = action.payload; });
  },
});

export default targetsSlice.reducer;
