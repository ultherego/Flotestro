import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { DefinitionForm, type Definition } from "./Backups";

/* The panel writes a backup definition back whole. The form used to show six
   of its fields and start empty every time, so saving a definition after
   changing one path cleared the retention, the pruning, the tags, the note and
   the environment of the tool on the host - silently, and the next copy ran
   under rules nobody chose. */

const existing: Definition = {
  id: "1", name: "nightly", tool: "restic", repository: "sftp:backup:/srv",
  paths: ["/etc", "/var/lib/app"], excludes: ["*.tmp"], tags: ["db", "prod"],
  keep_last: 7, keep_daily: 14, keep_weekly: 8, keep_monthly: 12,
  prune: true, initialize: false, password_secret: "backup.nightly",
  env_secrets: { AWS_SECRET_ACCESS_KEY: "aws.backup" },
  note: "the one the auditor asks about",
  updated_by: "operator", updated_at: "2026-09-20T00:00:00Z",
  status: "ok", unverified: false,
};

afterEach(cleanup);

describe("the backup definition form", () => {
  it("saves back every part of the definition it was opened with", () => {
    const saved: Record<string, unknown>[] = [];
    render(<DefinitionForm runbooks={[]} existing={existing} onSave={(body) => saved.push(body)} />);
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));
    expect(saved).toHaveLength(1);
    expect(saved[0]).toMatchObject({
      name: "nightly", tool: "restic", repository: "sftp:backup:/srv",
      paths: ["/etc", "/var/lib/app"], excludes: ["*.tmp"], tags: ["db", "prod"],
      keep_last: 7, keep_daily: 14, keep_weekly: 8, keep_monthly: 12,
      prune: true, initialize: false, note: "the one the auditor asks about",
      password_secret: "backup.nightly",
      env_secrets: { AWS_SECRET_ACCESS_KEY: "aws.backup" },
    });
  });

  it("changes only what was changed", () => {
    const saved: Record<string, unknown>[] = [];
    render(<DefinitionForm runbooks={[]} existing={existing} onSave={(body) => saved.push(body)} />);
    fireEvent.change(screen.getByDisplayValue("/etc /var/lib/app"), { target: { value: "/etc" } });
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));
    expect(saved[0]).toMatchObject({ paths: ["/etc"], keep_daily: 14, prune: true });
  });

  it("starts a new definition empty and names the button for it", () => {
    const saved: Record<string, unknown>[] = [];
    render(<DefinitionForm runbooks={[]} existing={null} onSave={(body) => saved.push(body)} />);
    const save = screen.getByRole("button", { name: /save definition/i });
    expect(save).toBeDisabled();
  });
});
