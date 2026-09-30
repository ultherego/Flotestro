import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Card } from "./layout";
import { Empty, ErrorBox } from "./ui";
import {
  readableDetail, remainingSteps, setupChecklistQuery, stateLabels, stepGuide, stepTone,
} from "../lib/setup";
import { useT } from "../i18n";

/**
 * What a panel on its first run still has to settle, condensed.
 *
 * This is the server's checklist and nothing else: the same read, the same
 * order, the same states as the first-run screen. It lists no step of its own,
 * so a step the server adds or moves appears here without a second edit, and
 * the two screens cannot end up describing one flow two ways. It reports every
 * step and settles none - the forms stay on the first-run screen.
 */
export function FirstRunCard() {
  const t = useT();
  const checklist = useQuery(setupChecklistQuery);
  const list = checklist.data;
  const words = stepGuide(t);
  const labels = stateLabels(t);
  // An optional step is an integration this installation has none of: it is
  // dropped by remainingSteps, so a panel that integrates with nothing is asked
  // for no provider and no group mapping here.
  const remaining = list ? remainingSteps(list.steps) : [];
  return (
    <Card
      tone="warn"
      title={t("No host is enrolled yet")}
      description={list
        ? t("{done} of {total} required steps done", { done: list.done, total: list.total })
        : undefined}
      actions={<Link className="button primary" to="/setup">{t("Open the first-run checklist")}</Link>}
    >
      {checklist.error ? <ErrorBox error={checklist.error} /> : !list ? (
        <Empty>{t("Loading…")}</Empty>
      ) : remaining.length === 0 ? (
        <Empty>{t("Every required step is done")}</Empty>
      ) : (
        <ol className="steps">
          {remaining.map((step) => (
            <li key={step.key}>
              {/* Each step leads where it is dealt with, which the server names
                  along with the state; the sentence under it is the server's too. */}
              <Link to={step.path}>{words[step.key]?.title ?? step.key}</Link>{" "}
              <span className={`badge ${stepTone(step.state)}`}>{labels[step.state]}</span>
              <div className="source">{readableDetail(step.detail)}</div>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}
