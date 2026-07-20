import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { Dashboard, type DashboardSnapshotState } from "./components/Dashboard";
import {
  clearApiToken,
  fetchDashboardData,
  saveApiToken,
} from "./lib/actionproxy-client";
import type { DashboardData } from "./types";

const initialData: DashboardData = {
  auditEvents: [],
  approvers: null,
  authorizedActions: [],
  health: null,
  integrations: null,
  pendingApprovals: [],
  policy: null,
  policyDetector: null,
  policyFile: null,
  toolCalls: [],
};

export function App() {
  return <AdminApp />;
}

function AdminApp() {
  const [data, setData] = useState<DashboardData>(initialData);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [authPromptVisible, setAuthPromptVisible] = useState(false);
  const [snapshotState, setSnapshotState] =
    useState<DashboardSnapshotState>("loading");
  const [lastSuccessfulRefreshAt, setLastSuccessfulRefreshAt] = useState<
    string | null
  >(null);
  const hasLoadedSnapshot = useRef(false);
  const refreshFailed = useRef(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const nextData = await fetchDashboardData();
      setData(nextData);
      setError(null);
      setAuthPromptVisible(false);
      setLastSuccessfulRefreshAt(new Date().toISOString());
      setSnapshotState(refreshFailed.current ? "recovered" : "ready");
      hasLoadedSnapshot.current = true;
      refreshFailed.current = false;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : String(caught);
      setError(message);
      setAuthPromptVisible(isAuthErrorMessage(message));
      setSnapshotState(hasLoadedSnapshot.current ? "stale" : "unavailable");
      refreshFailed.current = true;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => {
      // Keep an explicit retry available after a failed refresh. Automatically
      // replacing the error banner can detach its retry button while someone is
      // trying to use it, and it hides useful failure context.
      if (!refreshFailed.current) void refresh();
    }, 5_000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  if (authPromptVisible) {
    return <AccessTokenPrompt error={error} onTokenSaved={refresh} />;
  }

  return (
    <Dashboard
      data={data}
      error={error}
      lastSuccessfulRefreshAt={lastSuccessfulRefreshAt}
      loading={loading}
      onRefresh={refresh}
      snapshotState={snapshotState}
    />
  );
}

function AccessTokenPrompt({
  error,
  onTokenSaved,
}: {
  error: string | null;
  onTokenSaved: () => Promise<void> | void;
}) {
  const [token, setToken] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextToken = token.trim();
    if (!nextToken) return;
    setSaving(true);
    saveApiToken(nextToken);
    await onTokenSaved();
    setSaving(false);
  };

  return (
    <main className="auth-screen">
      <section className="panel auth-panel" aria-labelledby="auth-title">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">ActionProxy Community</p>
            <h1 id="auth-title">Enter access token</h1>
          </div>
        </div>
        <p className="muted">
          Paste a scoped ActionProxy API token for this workspace. The token is
          kept only in this browser tab and sent as a bearer token to API
          routes.
        </p>
        {error && <p className="form-error">{error}</p>}
        <form className="auth-token-form" onSubmit={submit}>
          <label>
            Access token
            <input
              autoComplete="off"
              placeholder="apx_..."
              spellCheck={false}
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
            />
          </label>
          <div className="button-row">
            <button disabled={saving || !token.trim()} type="submit">
              {saving ? "Checking..." : "Continue"}
            </button>
            <button
              className="ghost"
              type="button"
              onClick={() => {
                clearApiToken();
                setToken("");
              }}
            >
              Clear saved token
            </button>
          </div>
        </form>
      </section>
    </main>
  );
}

function isAuthErrorMessage(message: string): boolean {
  return /bearer authentication|required|invalid api key|authentication is required|unauthorized/i.test(
    message,
  );
}
