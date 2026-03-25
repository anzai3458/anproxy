import { createAsyncThunk, createSlice } from '@reduxjs/toolkit';
import { api } from '../api';

interface SpeedTestState {
  phase: 'idle' | 'ping' | 'download' | 'upload' | 'done';
  latency: number | null;
  downloadMbps: number | null;
  uploadMbps: number | null;
  error: string | null;
}

const initialState: SpeedTestState = {
  phase: 'idle',
  latency: null,
  downloadMbps: null,
  uploadMbps: null,
  error: null,
};

export const runSpeedTest = createAsyncThunk(
  'speedTest/run',
  async (_, { dispatch }) => {
    dispatch(speedTestSlice.actions.setPhase('ping'));
    const pingStart = performance.now();
    await api.speedTestPing();
    const latency = Math.round(performance.now() - pingStart);

    dispatch(speedTestSlice.actions.setPhase('download'));
    const dlStart = performance.now();
    const dlRes = await api.speedTestDownload();
    const dlBlob = await dlRes.blob();
    const dlTime = (performance.now() - dlStart) / 1000;
    const downloadMbps = Math.round((dlBlob.size * 8) / (dlTime * 1_000_000) * 100) / 100;

    dispatch(speedTestSlice.actions.setPhase('upload'));
    const uploadData = new Blob([new Uint8Array(10 * 1024 * 1024)]);
    const ulStart = performance.now();
    await api.speedTestUpload(uploadData);
    const ulTime = (performance.now() - ulStart) / 1000;
    const uploadMbps = Math.round((uploadData.size * 8) / (ulTime * 1_000_000) * 100) / 100;

    return { latency, downloadMbps, uploadMbps };
  },
);

const speedTestSlice = createSlice({
  name: 'speedTest',
  initialState,
  reducers: {
    setPhase(state, action: { payload: SpeedTestState['phase'] }) {
      state.phase = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(runSpeedTest.pending, (state) => {
        state.error = null;
        state.latency = null;
        state.downloadMbps = null;
        state.uploadMbps = null;
      })
      .addCase(runSpeedTest.fulfilled, (state, action) => {
        state.phase = 'done';
        state.latency = action.payload.latency;
        state.downloadMbps = action.payload.downloadMbps;
        state.uploadMbps = action.payload.uploadMbps;
      })
      .addCase(runSpeedTest.rejected, (state, action) => {
        state.phase = 'idle';
        state.error = action.error.message ?? 'Speed test failed';
      });
  },
});

export default speedTestSlice.reducer;
