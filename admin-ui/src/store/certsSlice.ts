import { createAsyncThunk, createSlice } from '@reduxjs/toolkit';
import { api } from '../api';

interface CertsInfo {
  cert_path: string;
  key_path: string;
  expiry: string;
  days_until_expiry: number;
}

interface CertsState {
  data: CertsInfo | null;
  loading: boolean;
  error: string | null;
}

const initialState: CertsState = { data: null, loading: false, error: null };

export const fetchCerts = createAsyncThunk('certs/fetch', async () => {
  return (await api.getCerts()) as CertsInfo;
});

export const reloadCerts = createAsyncThunk('certs/reload', async () => {
  await api.reloadCerts();
  return (await api.getCerts()) as CertsInfo;
});

const certsSlice = createSlice({
  name: 'certs',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchCerts.pending, (state) => { state.loading = true; })
      .addCase(fetchCerts.fulfilled, (state, action) => {
        state.data = action.payload;
        state.loading = false;
        state.error = null;
      })
      .addCase(fetchCerts.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message ?? 'Failed to fetch certs';
      })
      .addCase(reloadCerts.fulfilled, (state, action) => {
        state.data = action.payload;
      });
  },
});

export default certsSlice.reducer;
