import { useState } from "react";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") || "http://127.0.0.1:8080/api/v1";

export function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [authStatus, setAuthStatus] = useState("");
  const [sessionTitle, setSessionTitle] = useState("");
  const [sessions, setSessions] = useState([]);
  const [activeSessionId, setActiveSessionId] = useState("");
  const [model, setModel] = useState("claude-opus-5-0");
  const [prompt, setPrompt] = useState("");
  const [chatOutput, setChatOutput] = useState("");
  const [messages, setMessages] = useState([]);
  const [usage, setUsage] = useState(null);

  async function auth(mode) {
    const response = await fetch(`${API_BASE}/auth/${mode}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });
    const data = await response.json();
    if (!response.ok) {
      setAuthStatus(`Auth failed: ${JSON.stringify(data)}`);
      return;
    }
    setToken(data.token);
    setAuthStatus(`${mode} success`);
    await loadSessions(data.token);
    await loadUsage(data.token);
  }

  async function loadSessions(nextToken = token) {
    if (!nextToken) return;
    const response = await fetch(`${API_BASE}/sessions`, {
      headers: headers(nextToken)
    });
    const data = await response.json();
    if (response.ok) setSessions(data);
  }

  async function loadUsage(nextToken = token) {
    if (!nextToken) return;
    const response = await fetch(`${API_BASE}/usage`, {
      headers: headers(nextToken)
    });
    const data = await response.json();
    if (response.ok) setUsage(data);
  }

  async function createSession() {
    if (!token) return;
    const response = await fetch(`${API_BASE}/sessions`, {
      method: "POST",
      headers: headers(token),
      body: JSON.stringify({
        title: sessionTitle || "New session",
        model
      })
    });
    const data = await response.json();
    if (!response.ok) return;
    setActiveSessionId(data.id);
    await loadSessions();
    await loadSessionMessages(data.id);
    await loadUsage();
  }

  async function loadSessionMessages(sessionId) {
    if (!token || !sessionId) return;
    const response = await fetch(`${API_BASE}/sessions/${sessionId}/messages`, {
      headers: headers(token)
    });
    const data = await response.json();
    if (response.ok) {
      setMessages(data);
    }
  }

  async function sendMessage() {
    if (!token || !activeSessionId) return;
    const response = await fetch(`${API_BASE}/sessions/${activeSessionId}/messages`, {
      method: "POST",
      headers: headers(token),
      body: JSON.stringify({ prompt, model })
    });
    const data = await response.json();
    if (!response.ok) {
      setChatOutput(JSON.stringify(data));
      return;
    }
    setChatOutput(
      `You: ${prompt}\n\nAssistant:\n${data.assistant_text}\n\nUsage total: ${data.usage_total_tokens}`
    );
    setPrompt("");
    await loadSessionMessages(activeSessionId);
    await loadUsage();
  }

  return (
    <main className="app">
      <header>
        <h1>iLopus SaaS</h1>
        <p>React UI for auth, sessions, and chat.</p>
      </header>

      <section className="panel">
        <h2>Authentication</h2>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
        />
        <div className="row">
          <button onClick={() => auth("signup")}>Sign Up</button>
          <button onClick={() => auth("login")}>Login</button>
        </div>
        <p>{authStatus}</p>
      </section>

      <section className="panel">
        <h2>Sessions</h2>
        <div className="row">
          <input
            value={sessionTitle}
            onChange={(e) => setSessionTitle(e.target.value)}
            placeholder="Session title"
          />
          <button onClick={createSession}>New Session</button>
        </div>
        <select value={model} onChange={(e) => setModel(e.target.value)}>
          <option value="claude-opus-5-0">Opus 5.0</option>
          <option value="claude-sonnet-4-6">Sonnet 4.6</option>
          <option value="claude-haiku-4-5-20251213">Haiku 4.5</option>
        </select>
        <ul className="sessions">
          {sessions.map((session) => (
            <li
              key={session.id}
              onClick={async () => {
                setActiveSessionId(session.id);
                await loadSessionMessages(session.id);
              }}
            >
              {session.title} ({session.model})
            </li>
          ))}
        </ul>
        <p>Active session: {activeSessionId || "none"}</p>
      </section>

      <section className="panel">
        <h2>Usage Dashboard</h2>
        {usage ? (
          <p>
            Sessions: {usage.session_count} | Messages: {usage.message_count} | Input tokens:{" "}
            {usage.input_tokens} | Output tokens: {usage.output_tokens} | Total: {usage.total_tokens}
          </p>
        ) : (
          <p>No usage yet.</p>
        )}
      </section>

      <section className="panel">
        <h2>Chat</h2>
        <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} rows={5} />
        <button onClick={sendMessage}>Send Message</button>
        <pre>{chatOutput}</pre>
        <h3>Message History</h3>
        <div>
          {messages.map((m, i) => (
            <p key={`${m.created_at}-${i}`}>
              <strong>{m.role}:</strong> {m.content}
            </p>
          ))}
        </div>
      </section>
    </main>
  );
}

function headers(token) {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`
  };
}

