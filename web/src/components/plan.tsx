import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../lib/api";
import type { Attempt } from "../lib/types";

/**
 * Plan per host: to, na co operator naprawde wyraza zgode.
 *
 * Zamowienie jest jedno, ale zmiana na kazdym hoscie inna: plik o innej
 * tresci, regula w innym ksztalcie, dysk pod ta sama sciezka z innym UUID.
 * Plan liczony na hoscie mowi, co sie tam stanie - albo dlaczego nie.
 */
type PlanHosta = {
  action?: string;
  changes?: string[];
  refusal?: string;
  validator_failed?: boolean;
  validator_output?: string;
  requested_source?: string;
  resolved_source?: string;
  ruleset_hash?: string;
  plan_hash?: string;
};

const NAZWY_DZIALAN: Record<string, string> = {
  create: "will be created",
  update: "will change",
  no_change: "already in desired state",
  remove: "will be removed",
  remove_absent: "already absent",
};

export function jestPlanemHosta(kind: string | undefined): boolean {
  return kind === "file_plan" || kind === "firewall_plan" || kind === "mount_plan" || kind === "network_plan";
}

/** Streszczenie planu z wyniku typowanego operacji planujacej. */
export function StreszczeniePlanu({ plan }: { plan: PlanHosta }) {
  if (plan.refusal) {
    return <span className="znacznik blad">refused: {plan.refusal}</span>;
  }
  if (plan.validator_failed) {
    return (
      <span className="znacznik blad">
        validator failed{plan.validator_output ? `: ${plan.validator_output.slice(0, 200)}` : ""}
      </span>
    );
  }
  const czesci = [NAZWY_DZIALAN[plan.action ?? ""] ?? plan.action ?? "plan"];
  if (plan.changes?.length) czesci.push(plan.changes.join(", "));
  // Zrodlo rozwiazane do UUID jest tym, co pojedzie na host; sciezka
  // z zamowienia zostaje tylko dla porownania.
  if (plan.resolved_source && plan.resolved_source !== plan.requested_source) {
    czesci.push(`${plan.requested_source} → ${plan.resolved_source}`);
  }
  return <span>{czesci.join(" · ")}</span>;
}

/** Plan hosta odczytany z ostatniej proby operacji planujacej. */
export function PlanZadania({ jobId }: { jobId: string }) {
  const { data, error } = useQuery({
    queryKey: ["attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
  });
  if (error) return <span className="zrodlo">plan unavailable</span>;
  const proba = [...(data?.items ?? [])].reverse().find((pozycja) => jestPlanemHosta(pozycja.detail?.kind as string));
  if (!proba) return <span className="zrodlo">—</span>;
  return <StreszczeniePlanu plan={(proba.detail?.plan ?? {}) as PlanHosta} />;
}
