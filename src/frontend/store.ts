/**
 * DevPulse - Zustand State Management Store
 * Global state management for the frontend application
 */

import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

interface User {
  id: string;
  email: string;
  name: string;
  plan: 'free' | 'pro' | 'enterprise';
  email_verified: boolean;
  created_at: string;
}

interface Collection {
  id: string;
  name: string;
  format: string;
  total_requests: number;
  created_at: string;
}

interface Scan {
  id: string;
  collection_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  risk_score: number;
  total_findings: number;
  started_at: string;
  completed_at?: string;
}

interface Finding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  remediation: string;
}

interface AppState {
  // Auth
  user: User | null;
  isAuthenticated: boolean;
  accessToken: string | null;
  refreshToken: string | null;

  // Collections
  collections: Collection[];
  selectedCollection: Collection | null;

  // Scans
  scans: Scan[];
  currentScan: Scan | null;

  // Findings
  findings: Finding[];

  // UI State
  loading: boolean;
  error: string | null;
  successMessage: string | null;
  sidebarOpen: boolean;
  darkMode: boolean;

  // Actions
  setUser: (user: User | null) => void;
  setAuthenticated: (authenticated: boolean) => void;
  setTokens: (accessToken: string, refreshToken: string) => void;
  logout: () => void;

  setCollections: (collections: Collection[]) => void;
  addCollection: (collection: Collection) => void;
  removeCollection: (collectionId: string) => void;
  setSelectedCollection: (collection: Collection | null) => void;

  setScans: (scans: Scan[]) => void;
  addScan: (scan: Scan) => void;
  updateScan: (scanId: string, scan: Partial<Scan>) => void;
  setCurrentScan: (scan: Scan | null) => void;

  setFindings: (findings: Finding[]) => void;
  addFinding: (finding: Finding) => void;

  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setSuccessMessage: (message: string | null) => void;
  setSidebarOpen: (open: boolean) => void;
  setDarkMode: (darkMode: boolean) => void;

  // Utility
  reset: () => void;
}

const initialState = {
  user: null,
  isAuthenticated: false,
  accessToken: null,
  refreshToken: null,
  collections: [],
  selectedCollection: null,
  scans: [],
  currentScan: null,
  findings: [],
  loading: false,
  error: null,
  successMessage: null,
  sidebarOpen: true,
  darkMode: false,
};

export const useAppStore = create<AppState>()(
  devtools(
    persist(
      (set, _get) => ({
        ...initialState,

        // Auth actions
        setUser: (user) => set({ user }),
        setAuthenticated: (isAuthenticated) => set({ isAuthenticated }),
        setTokens: (accessToken, refreshToken) =>
          set({ accessToken, refreshToken, isAuthenticated: true }),
        logout: () =>
          set({
            user: null,
            isAuthenticated: false,
            accessToken: null,
            refreshToken: null,
            collections: [],
            selectedCollection: null,
            scans: [],
            currentScan: null,
            findings: [],
          }),

        // Collection actions
        setCollections: (collections) => set({ collections }),
        addCollection: (collection) =>
          set((state) => ({
            collections: [...state.collections, collection],
          })),
        removeCollection: (collectionId) =>
          set((state) => ({
            collections: state.collections.filter((c) => c.id !== collectionId),
            selectedCollection:
              state.selectedCollection?.id === collectionId
                ? null
                : state.selectedCollection,
          })),
        setSelectedCollection: (collection) => set({ selectedCollection: collection }),

        // Scan actions
        setScans: (scans) => set({ scans }),
        addScan: (scan) =>
          set((state) => ({
            scans: [...state.scans, scan],
            currentScan: scan,
          })),
        updateScan: (scanId, scanUpdate) =>
          set((state) => ({
            scans: state.scans.map((s) =>
              s.id === scanId ? { ...s, ...scanUpdate } : s
            ),
            currentScan:
              state.currentScan?.id === scanId
                ? { ...state.currentScan, ...scanUpdate }
                : state.currentScan,
          })),
        setCurrentScan: (scan) => set({ currentScan: scan }),

        // Finding actions
        setFindings: (findings) => set({ findings }),
        addFinding: (finding) =>
          set((state) => ({
            findings: [...state.findings, finding],
          })),

        // UI actions
        setLoading: (loading) => set({ loading }),
        setError: (error) => set({ error }),
        setSuccessMessage: (successMessage) => set({ successMessage }),
        setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
        setDarkMode: (darkMode) => set({ darkMode }),

        // Utility
        reset: () => set(initialState),
      }),
      {
        name: 'devpulse-store',
        partialize: (state) => ({
          user: state.user,
          isAuthenticated: state.isAuthenticated,
          accessToken: state.accessToken,
          refreshToken: state.refreshToken,
          sidebarOpen: state.sidebarOpen,
          darkMode: state.darkMode,
        }),
      }
    )
  )
);

// Selectors
export const useUser = () => useAppStore((state) => state.user);
export const useIsAuthenticated = () =>
  useAppStore((state) => state.isAuthenticated);
export const useCollections = () => useAppStore((state) => state.collections);
export const useSelectedCollection = () =>
  useAppStore((state) => state.selectedCollection);
export const useScans = () => useAppStore((state) => state.scans);
export const useCurrentScan = () => useAppStore((state) => state.currentScan);
export const useFindings = () => useAppStore((state) => state.findings);
export const useLoading = () => useAppStore((state) => state.loading);
export const useError = () => useAppStore((state) => state.error);
export const useSuccessMessage = () =>
  useAppStore((state) => state.successMessage);
export const useSidebarOpen = () => useAppStore((state) => state.sidebarOpen);
export const useDarkMode = () => useAppStore((state) => state.darkMode);
