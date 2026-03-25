import { configureStore } from '@reduxjs/toolkit';
import authReducer from './authSlice';
import targetsReducer from './targetsSlice';
import staticDirsReducer from './staticDirsSlice';
import statsReducer from './statsSlice';
import certsReducer from './certsSlice';
import speedTestReducer from './speedTestSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    targets: targetsReducer,
    staticDirs: staticDirsReducer,
    stats: statsReducer,
    certs: certsReducer,
    speedTest: speedTestReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
