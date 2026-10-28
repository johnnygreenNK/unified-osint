"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError, login, register } from "@/lib/api";

export default function HomePage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(email, password, displayName);
      }
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Nie udalo sie polaczyc z API");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="container" style={{ maxWidth: 420 }}>
      <h1>UnifiedOSINT</h1>
      <div className="card">
        <div className="row" style={{ marginBottom: 16 }}>
          <button className={mode === "login" ? "" : "secondary"} onClick={() => setMode("login")} type="button">
            Logowanie
          </button>
          <button className={mode === "register" ? "" : "secondary"} onClick={() => setMode("register")} type="button">
            Rejestracja
          </button>
        </div>
        <form onSubmit={onSubmit} className="row" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <input
            type="email"
            placeholder="E-mail"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          {mode === "register" && (
            <input
              type="text"
              placeholder="Nazwa wyswietlana"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              required
            />
          )}
          <input
            type="password"
            placeholder="Haslo"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={mode === "register" ? 10 : undefined}
            required
          />
          {error && <div className="error">{error}</div>}
          <button type="submit" disabled={busy}>
            {mode === "login" ? "Zaloguj" : "Zarejestruj"}
          </button>
        </form>
      </div>
      <p className="muted">
        Nowe konto otrzymuje rolę "viewer". Źródła typu breach-data wymagają roli analyst/admin, nadawanej recznie.
      </p>
    </div>
  );
}
