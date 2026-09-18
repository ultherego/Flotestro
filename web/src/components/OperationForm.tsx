import { useState } from "react";
import { Field, FieldGrid } from "./layout";
import { useT } from "../i18n";
import {
  body, count, flag, payloadTextOf, readPayloadText, text,
  type FieldSuggestions, type FieldValue, type FormProblem, type FormValue,
  type OperationEntry, type OperationField,
} from "../lib/operations";

/**
 * The form of one operation, drawn from the registry.
 *
 * The component knows nothing about any particular operation: it takes the
 * entry, draws its fields and hands back the value. That is what lets the
 * Bulk wizard and a host page show the operator the same form, with the
 * same words and the same refusals, instead of each keeping its own copy.
 *
 * The JSON has not gone away, it has moved: the advanced view shows exactly
 * the payload the fields produce and lets it be edited by hand, for the
 * field the registry does not carry yet and for an order composed
 * elsewhere. A payload the fields can show goes back to being theirs, so
 * the advanced view is a detour rather than a one-way door.
 */
export function OperationForm({
  entry, value, onChange, json, onJson, suggestions,
}: {
  entry: OperationEntry;
  value: FormValue;
  onChange: (value: FormValue) => void;
  /**
   * What the host this order is for really has, by field name. A screen
   * that has just read the host passes it; the Bulk wizard, which orders
   * on many hosts at once, passes nothing.
   */
  suggestions?: FieldSuggestions;
  /**
   * The payload as hand-written JSON, when the fields cannot show it. An
   * empty string means the fields are what the order carries.
   */
  json: string;
  onJson: (json: string) => void;
}) {
  const t = useT();
  const [advanced, setAdvanced] = useState(json !== "");
  // The text of the advanced view lives here rather than in the order: a
  // value that reformats itself on every keystroke cannot be typed into.
  const [draft, setDraft] = useState(() => json || payloadTextOf(entry, value));
  const problems = entry.validate(value);
  const problemOf = (name: string) => problems.find((problem) => problem.field === name);

  // The caller hands over a complete form - the registry's own starting
  // value laid under whatever was typed - so one field changing does not
  // have to rebuild the rest.
  const set = (field: OperationField, next: FieldValue) =>
    onChange({ ...value, [field.name]: next });

  const editJson = (next: string) => {
    setDraft(next);
    const read = readPayloadText(entry, next);
    if (read) {
      // The fields can carry this payload, so they take it back: the
      // advanced view stops being what the order is made of.
      onChange(read);
      onJson("");
      return;
    }
    onJson(next);
  };

  const openAdvanced = () => {
    setDraft(payloadTextOf(entry, value));
    setAdvanced(true);
  };

  const closeAdvanced = () => {
    setAdvanced(false);
    onJson("");
  };

  return (
    <>
      <div className="actions">
        <label className="toggle">
          <input
            type="checkbox"
            checked={advanced}
            onChange={(event) => (event.target.checked ? openAdvanced() : closeAdvanced())}
          />{" "}
          {t("Advanced (JSON)")}
        </label>
        <span className="source">{t(entry.title)}</span>
      </div>

      {entry.note && <p className="subtitle">{t(entry.note)}</p>}
      {entry.plan && <p className="subtitle">{t(entry.plan)}</p>}

      {advanced ? (
        <FieldGrid>
          <Field
            label={t("Payload (JSON, the same shape as a single-host operation)")}
            hint={advancedWords(t, entry, draft)}
            wide
          >
            <textarea
              rows={Math.min(24, Math.max(6, draft.split("\n").length + 1))}
              value={draft}
              onChange={(event) => editJson(event.target.value)}
              spellCheck={false}
            />
          </Field>
        </FieldGrid>
      ) : (
        <>
          <FieldGrid>
            {entry.fields.map((field) => (
              <FormField
                key={field.name}
                field={field}
                value={value}
                problem={problemOf(field.name)}
                set={set}
                suggestions={suggestions?.[field.name]}
              />
            ))}
          </FieldGrid>
          {entry.fields.length === 0 && (
            <p className="subtitle">{t("This operation takes no settings.")}</p>
          )}
          {problems.length > 0 && (
            <p className="page-error">
              {problems.map((problem) => t(problem.message, problem.params)).join(" ")}
            </p>
          )}
        </>
      )}
    </>
  );
}

// advancedWords says what the advanced view holds right now. It reads the
// text in the box rather than what the order carries: the operator is told
// about what they have just typed, not about the last thing that was
// accepted.
function advancedWords(t: (text: string) => string, entry: OperationEntry, draft: string): string {
  if (readPayloadText(entry, draft)) {
    return t("The fields can show this payload, so they are what the order carries; close the advanced view and they are filled in with it.");
  }
  if (readsAsObject(draft)) {
    return t("The fields cannot show this payload, so it travels exactly as typed. The server checks it and names what is wrong.");
  }
  return t("This is not valid JSON.");
}

function readsAsObject(draft: string): boolean {
  try {
    const parsed: unknown = JSON.parse(draft);
    return Boolean(parsed) && typeof parsed === "object" && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

/**
 * One field. A flag is drawn as its own block rather than inside a Field,
 * because a label around a checkbox and its explanation sends every click
 * on the explanation to the checkbox.
 */
function FormField({
  field, value, problem, set, suggestions,
}: {
  field: OperationField;
  value: FormValue;
  problem?: FormProblem;
  set: (field: OperationField, next: FieldValue) => void;
  suggestions?: string[];
}) {
  const t = useT();
  // A field that is wrong says so where its explanation stood: one place
  // to look, and the explanation is no use until the value is right.
  const hint = problem
    ? t(problem.message, problem.params)
    : field.hint ? t(field.hint) : undefined;

  if (field.kind === "boolean") {
    return (
      <div className={field.wide ? "field wide" : "field"}>
        <label className="toggle">
          <input
            type="checkbox"
            checked={flag(value, field.name)}
            onChange={(event) => set(field, event.target.checked)}
          />{" "}
          {t(field.label)}
        </label>
        {hint && <span className="field-hint">{hint}</span>}
      </div>
    );
  }

  return (
    <Field label={t(field.label)} hint={hint} wide={field.wide}>
      {control(t, field, value, set, suggestions)}
    </Field>
  );
}

function control(
  t: (text: string) => string,
  field: OperationField,
  value: FormValue,
  set: (field: OperationField, next: FieldValue) => void,
  suggestions?: string[],
) {
  // What the host has is offered, not imposed: a list beside the field
  // rather than a select, because an operator ordering something the host
  // does not report yet - a volume about to be created, a unit from a
  // package being installed - must still be able to type it.
  const listID = suggestions && suggestions.length > 0 ? "operation-field-" + field.name : undefined;
  const list = listID ? (
    <datalist id={listID}>
      {suggestions!.map((option) => <option key={option} value={option} />)}
    </datalist>
  ) : null;
  switch (field.kind) {
    case "select":
      return (
        <select value={text(value, field.name)} onChange={(event) => set(field, event.target.value)}>
          {(field.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>{t(option.label)}</option>
          ))}
        </select>
      );

    case "number":
    case "duration":
      return (
        <input
          type="number"
          min={field.min}
          max={field.max}
          value={String(count(value, field.name))}
          onChange={(event) => set(field, event.target.value === "" ? 0 : Number(event.target.value))}
        />
      );

    case "textarea":
    case "list":
    case "packages":
    case "pairs": {
      const written = body(value, field.name);
      return (
        <textarea
          rows={Math.min(16, Math.max(field.kind === "textarea" ? 6 : 3, written.split("\n").length + 1))}
          value={written}
          placeholder={field.placeholder}
          onChange={(event) => set(field, event.target.value)}
          spellCheck={false}
        />
      );
    }

    default:
      return (
        <>
          <input
            type="text"
            value={body(value, field.name)}
            placeholder={field.placeholder}
            list={listID}
            onChange={(event) => set(field, event.target.value)}
            spellCheck={field.kind === "text"}
          />
          {list}
        </>
      );
  }
}
