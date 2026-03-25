import { createAsyncThunk, createSlice } from '@reduxjs/toolkit';
import { api } from '../api';

interface StaticDir {
  host: string;
  dir: string;
}

interface StaticDirsState {
  items: StaticDir[];
  loading: boolean;
  error: string | null;
}

const initialState: StaticDirsState = { items: [], loading: false, error: null };

export const fetchStaticDirs = createAsyncThunk('staticDirs/fetch', async () => {
  return (await api.getStaticDirs()) as StaticDir[];
});

export const addStaticDir = createAsyncThunk(
  'staticDirs/add',
  async ({ host, dir }: StaticDir) => {
    await api.addStaticDir(host, dir);
    return (await api.getStaticDirs()) as StaticDir[];
  },
);

export const updateStaticDir = createAsyncThunk(
  'staticDirs/update',
  async ({ host, dir }: StaticDir) => {
    await api.updateStaticDir(host, dir);
    return (await api.getStaticDirs()) as StaticDir[];
  },
);

export const deleteStaticDir = createAsyncThunk(
  'staticDirs/delete',
  async (host: string) => {
    await api.deleteStaticDir(host);
    return (await api.getStaticDirs()) as StaticDir[];
  },
);

const staticDirsSlice = createSlice({
  name: 'staticDirs',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchStaticDirs.pending, (state) => { state.loading = true; })
      .addCase(fetchStaticDirs.fulfilled, (state, action) => {
        state.items = action.payload;
        state.loading = false;
        state.error = null;
      })
      .addCase(fetchStaticDirs.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message ?? 'Failed to fetch static dirs';
      })
      .addCase(addStaticDir.fulfilled, (state, action) => { state.items = action.payload; })
      .addCase(updateStaticDir.fulfilled, (state, action) => { state.items = action.payload; })
      .addCase(deleteStaticDir.fulfilled, (state, action) => { state.items = action.payload; });
  },
});

export default staticDirsSlice.reducer;
