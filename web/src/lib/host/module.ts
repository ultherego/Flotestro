import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { awaitJob } from "../jobs";
import { emptyForm, operationForm, type FormProblem, type FormValue } from "../operations";
import type { Job } from "../types";
import type { Translate } from "../../i18n";

/**
 * What every module of a host page does the same way: compose an order
 * through the operation registry, and read the host again once the host
 * has actually answered.
 *
 * A host page orders the same operations the Bulk workspace does, so it
 * composes them the same way: through the registry entry. A page that built
 * its own payload would also carry its own idea of what is valid, and the
 * two would drift apart the moment one of them was corrected.
 */

/** One order as the registry composes it: what would be sent, and what is wrong with it. */
export type RegistryOrder = {
  action: string;
  payload: Record<string, unknown>;
  problems: FormProblem[];
};

/**
 * Puts an order through the registry entry of its action. The seed carries
 * only the fields the module fills in; the rest come from the entry's own
 * empty form, so the payload is the one the Bulk workspace would send.
 */
export function registryOrder(action: string, seed: FormValue): RegistryOrder {
  const entry = operationForm(action);
  // An action with no entry is a programming mistake, not an operator one:
  // the order is refused rather than sent as a payload nobody composed.
  if (!entry) {
    return {
      action,
      payload: {},
      problems: [{ message: "The registry has no form for {action} yet.", params: { action } }],
    };
  }
  const form = { ...emptyForm(entry), ...seed };
  return { action, payload: entry.toPayload(form), problems: entry.validate(form) };
}

/** Whether the registry would take this order as it stands. */
export function orderReady(order: RegistryOrder): boolean {
  return order.problems.length === 0;
}

/**
 * The first refusal of an order as a sentence, or an empty string when the
 * registry takes it. It is what a disabled button says in its hint, so it
 * takes the translator rather than calling the hook: a row in a list uses
 * it too.
 */
export function refusalOf(t: Translate, order: RegistryOrder): string {
  const problem = order.problems[0];
  return problem ? t(problem.message, problem.params) : "";
}

/**
 * A read whose answer lands in the inventory - the full list of the units,
 * the snapshot of the processes - is settled when the job is over, not when
 * it is queued: the order answers at once, the host later, and the module is
 * read again only then.
 */
export function useModuleRefresh(hostID: string, modules: string[]) {
  const queryClient = useQueryClient();
  return (job: Job) => {
    void awaitJob(api, job.id).then(() => {
      queryClient.invalidateQueries({ queryKey: ["jobs", hostID] });
      for (const module of modules) {
        queryClient.invalidateQueries({ queryKey: ["inventory", hostID, module] });
      }
      // The API answering with an error is not the screen's to report here:
      // the job list shows the job, and the refetch comes on its own.
    }, () => undefined);
  };
}
