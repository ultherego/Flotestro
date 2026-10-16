import { useState, type FormEvent } from "react";
import { api, BEARER_TOKEN_KEY } from "../lib/api";
import { LogoMark } from "../components/Logo";
import { useT } from "../i18n";

/**
 * The way in.
 *
 * It is the first thing anybody sees of this product, and for a long time
 * it was a form floating on an empty page. It is a card now, on a ground
 * lit from two corners, and it is set a size larger than the panel
 * behind it: a person typing a password is reading one line at a time,
 * not scanning a board.
 *
 * The three ways in stand in the order they are needed. The password is
 * first because where there is no identity provider it is the only one,
 * and where there is one an administrator still keeps a local account
 * for the day the provider is the thing that is down. The provider is
 * second. The bootstrap token is last and folded away: it works once,
 * at the first run, and the checklist warns while it still does.
 */
export function Door({ provider }: { provider: boolean }) {
  const t = useT();
  return (
    <div className="fl-app">
      <div className="fl-door">
        <section className="fl-door-card">
          <header className="fl-door-head">
            <span className="fl-door-mark" aria-hidden="true">
              <LogoMark size={34} ground="var(--fl-brand)" />
            </span>
            <h1 className="fl-door-name">Flotestro</h1>
            <p className="fl-door-lead">{t("Linux fleet management")}</p>
          </header>

          <PasswordDoor />

          {provider && (
            <>
              <div className="fl-door-or"><span>{t("or")}</span></div>
              <button
                type="button"
                className="fl-quiet fl-door-wide"
                onClick={() => (window.location.href = "/auth/login?redirect=/dashboard")}
              >
                {t("Sign in with identity provider")}
              </button>
              <p className="fl-note">
                {t("Your identity provider may sign you in with an account you already have an open session for.")}{" "}
                <a href="/auth/login?force=1&redirect=/dashboard">{t("Sign in as a different user")}</a>
              </p>
            </>
          )}

          <BootstrapDoor />
        </section>
      </div>
    </div>
  );
}

/**
 * A name and a password.
 *
 * The refusal is one sentence for a name nobody has and for a wrong
 * password alike: the person at the keyboard learns nothing about which
 * names exist, and the administrator reading the trail afterwards learns
 * which of the two it was. A locked account is the exception - its owner
 * has to know that waiting is the answer and not retyping.
 */
function PasswordDoor() {
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
    <form className="fl-door-form" onSubmit={signIn}>
      <label className="fl-field">
        <span className="fl-field-label">{t("Identity")}</span>
        <input
          value={subject}
          onChange={(event) => setSubject(event.target.value)}
          autoComplete="username"
          data-testid="signin-subject"
        />
      </label>
      <label className="fl-field">
        <span className="fl-field-label">{t("Password")}</span>
        <input
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="current-password"
          data-testid="signin-password"
        />
      </label>
      {refusal !== "" && <p className="fl-problem" role="alert" data-testid="signin-refusal">{refusal}</p>}
      <button
        type="submit"
        className="fl-door-wide"
        disabled={busy || subject.trim() === "" || password === ""}
        data-testid="signin-submit"
      >
        {busy ? t("signing in…") : t("Sign in")}
      </button>
    </form>
  );
}

/** The token printed at the first start, for the first group mapping only. */
function BootstrapDoor() {
  const t = useT();
  const [token, setToken] = useState("");
  return (
    <details className="fl-door-more">
      <summary>{t("Sign in with a bootstrap token")}</summary>
      <p className="fl-note">
        {t("The bootstrap token is printed at the first start and lies in the state directory. It is for the first group mapping only: the first-run checklist warns while it still works.")}
      </p>
      <label className="fl-field">
        <span className="fl-field-label">{t("Bootstrap token")}</span>
        <input
          type="password"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          placeholder="flta…"
          autoComplete="off"
          data-testid="bootstrap-token"
        />
      </label>
      <button
        type="button"
        className="fl-quiet fl-door-wide"
        disabled={token.trim() === ""}
        onClick={() => {
          try { sessionStorage.setItem(BEARER_TOKEN_KEY, token.trim()); } catch { /* a window without storage: the token is simply not kept */ }
          window.location.href = "/setup";
        }}
      >
        {t("Continue to the first run")}
      </button>
    </details>
  );
}
