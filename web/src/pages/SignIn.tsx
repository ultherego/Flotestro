import { useState, type FormEvent } from "react";
import { api } from "../lib/api";
import { useT } from "../i18n";

/**
 * Signing in with a name and a password.
 *
 * The refusal is deliberately one sentence for a name nobody has and for a
 * wrong password alike: the person at the keyboard learns nothing about
 * which names exist, and the administrator reading the trail afterwards
 * learns which of the two it was. A locked account is the exception - its
 * owner has to know that waiting is the answer, not retyping.
 */
export function PasswordSignIn() {
  const t = useT();
  const [subject, setSubject] = useState("");
  const [password, setPassword] = useState("");
  const [refusal, setRefusal] = useState("");
  const [busy, setBusy] = useState(false);

  const signIn = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setRefusal("");
    try {
      const answer = await api.post<{ must_change_password?: boolean }>("/auth/password", {
        subject: subject.trim(), password,
      });
      window.location.href = answer.must_change_password ? "/profile?change_password=1" : "/dashboard";
    } catch (error) {
      setRefusal(error instanceof Error ? error.message : String(error));
      setBusy(false);
    }
  };

  return (
    <form className="login-form" onSubmit={signIn}>
      <label className="field">
        <span className="field-label">{t("Identity")}</span>
        <input value={subject} onChange={(event) => setSubject(event.target.value)}
               autoComplete="username" data-testid="signin-subject" />
      </label>
      <label className="field">
        <span className="field-label">{t("Password")}</span>
        <input type="password" value={password} onChange={(event) => setPassword(event.target.value)}
               autoComplete="current-password" data-testid="signin-password" />
      </label>
      {refusal !== "" && <p className="page-error" data-testid="signin-refusal">{refusal}</p>}
      <button type="submit" disabled={busy || subject.trim() === "" || password === ""}
              data-testid="signin-submit">
        {busy ? t("signing in…") : t("Sign in")}
      </button>
    </form>
  );
}

