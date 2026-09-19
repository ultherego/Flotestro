import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { CampaignTarget, SelectorExpression } from "./types";
import { OPERATIONS_INTERVAL } from "./stream";

/**
 * A target as the targets endpoint returns it: the campaign target and,
 * while the host's operation waits on its host, the resource lock it waits
 * on as the agent named it ("units held by task <id> (schedule.
 */
export type TargetRow = CampaignTarget & { blocker?: string };

/** One page of a campaign's targets, in the order of the rollout. */
export type TargetPage = {
  items: TargetRow[];
  count: number;
  /** How many targets match the filter across every page. */
  total: number;
  next_cursor?: string;
};

export type TargetFilter = { state?: string; wave?: number; search?: string };

/** How many targets one request fetches; a screen grows page by page. */
export const TARGET_PAGE = 200;

/**
 * The targets of a campaign, page by page and filtered on the server.
 */
export function useTargets(campaignID: string, filter: TargetFilter) {
  return useInfiniteQuery({
    queryKey: ["campaign-targets", campaignID, filter],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ limit: String(TARGET_PAGE) });
      if (filter.state) params.set("state", filter.state);
      if (filter.wave !== undefined && filter.wave >= 0) params.set("wave", String(filter.wave));
      if (filter.search) params.set("q", filter.search);
      if (pageParam) params.set("cursor", pageParam);
      return api.get<TargetPage>(`/api/v1/campaigns/${campaignID}/targets?${params}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    enabled: campaignID !== "",
    refetchInterval: OPERATIONS_INTERVAL,
  });
}

/** The rows loaded so far, in one list. */
export function loadedTargets(data?: { pages: TargetPage[] }): TargetRow[] {
  return data?.pages.flatMap((page) => page.items) ?? [];
}

/**
 * The link between a campaign and the campaign that compensates it, as the
 * server returns it on a campaign.
 */
export type CompensationLinks = {
  compensates_campaign_id?: string;
  compensates_campaign_name?: string;
  compensated_by?: { id: string; name: string; state: string }[];
  changed_hosts?: number;
};

/**
 * The bounds of the wait for a rebooted host, in seconds, as the server
 * validates them.
 */
export const REBOOT_TIMEOUT = { min: 60, max: 7200, default: 900 };

/**
 * The states a target can be in, for the filter, in the order a host moves
 * through them.
 */
export const TARGET_STATES = [
  "pending", "awaiting_budget", "queued_offline", "planning", "dispatched", "awaiting_lock",
  "running", "rebooting", "verifying",
  "succeeded", "no_change", "failed", "unknown", "skipped", "ineligible", "excluded", "canceled",
];

/**
 * The states a campaign has settled in: nothing changes on any host any
 * more, the report is on record, and a compensation can be ordered.
 */
export const SETTLED_CAMPAIGN_STATES = [
  "completed", "completed_with_issues", "failed", "plan_failed", "expired", "canceled",
];

/** One executable step of a target: plan, execute, reboot, verify or compensate. */
export type CampaignStep = {
  id: string;
  campaign_id: string;
  target_id: string;
  host_id: string;
  hostname?: string;
  step_key: string;
  /** The step this one waited for; absent for the first step of the host. */
  depends_on?: string;
  /** The digest of the plan the step ran under; absent for the plan step and for a campaign without a planner. */
  plan_hash?: string;
  state: "pending" | "running" | "succeeded" | "failed" | "skipped" | "canceled";
  /** The task of the latest attempt; absent for a step settled without one. */
  job_id?: string;
  attempts: number;
  /** Why the step ended the way it did; never empty for a failed, skipped or canceled step. */
  reason?: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  updated_at?: string;
  wave: number;
  position: number;
};

/** One page of a campaign's steps, cut between hosts. */
export type StepPage = {
  items: CampaignStep[];
  count: number;
  next_cursor?: string;
  /** The order the steps of one host run in, from the server's contract. */
  step_order: string[];
};

/**
 * The steps of one host in a campaign.
 */
export function useTargetSteps(campaignID: string, hostID: string) {
  return useQuery({
    queryKey: ["campaign-steps", campaignID, hostID],
    queryFn: () => api.get<StepPage>(`/api/v1/campaigns/${campaignID}/steps?host_id=${hostID}&limit=1`),
    enabled: campaignID !== "" && hostID !== "",
    refetchInterval: OPERATIONS_INTERVAL,
  });
}

/* ---------------------------------------------------------------------- */
/* The text form of a selector.                                            */
/* ---------------------------------------------------------------------- */

/**
 * A selector leaf as the server reads it: the fields of the campaign
 * selector plus the facts a live selector may name - the health signals, the
 * agent version as a comparison, the relay, the failure domain.
 */
export type SelectorNode = Omit<SelectorExpression, "all" | "any" | "not"> & {
  os_version?: string;
  security_updates?: string;
  reboot_required?: string;
  failed_units?: string;
  agent_version?: string;
  relay?: string;
  failure_domain?: string;
  all?: SelectorNode[];
  any?: SelectorNode[];
  not?: SelectorNode;
};

/** One fact an expression may name, for the parser and for the suggestions under the field. */
export type SelectorKey = {
  name: string;
  /** The shorter spellings the parser also takes. */
  aliases?: string[];
  /** The values of a key that takes a fixed set; absent for free text. */
  values?: string[];
  /** The key compares with <, <=, > and >= as well as =. */
  ordered?: boolean;
};

/** The states a selector may name; the same lists the server constrains. */
export const CONNECTION_STATES = ["online", "offline", "stale", "unknown"];
export const LIFECYCLE_STATES = ["active", "quarantined", "recovery", "retiring", "retired"];
const BOOLEANS = ["true", "false"];

/**
 * The keys of an expression, in the order the field suggests them.
 */
export const SELECTOR_KEYS: SelectorKey[] = [
  { name: "site" },
  { name: "environment", aliases: ["env"] },
  { name: "os_family", aliases: ["os"] },
  { name: "os_version" },
  { name: "tag" },
  { name: "group" },
  { name: "owner" },
  { name: "capability" },
  { name: "connection_state", aliases: ["connection"], values: CONNECTION_STATES },
  { name: "lifecycle_state", aliases: ["lifecycle"], values: LIFECYCLE_STATES },
  { name: "channel", aliases: ["release_channel"], values: ["stable", "beta"] },
  { name: "security_updates", values: BOOLEANS },
  { name: "reboot_required", values: BOOLEANS },
  { name: "failed_units", values: BOOLEANS },
  { name: "agent_version", ordered: true },
  { name: "relay" },
  { name: "failure_domain" },
];

/** The operators of an expression; the ordered ones apply to agent_version alone. */
export const SELECTOR_OPERATORS = ["=", "!=", "<", "<=", ">", ">="];

/** The shape of a tag, as the server checks it: a lower-case key, optionally with a value. */
const TAG_PATTERN = /^[a-z0-9][a-z0-9_.-]*(=[a-zA-Z0-9_.:/-]+)?$/;
/** The shape of a version in a comparison: up to four numeric parts, an optional v in front. */
const VERSION_PATTERN = /^v?(\d+(?:\.\d+){0,3})$/;
const MAX_VALUE = 128;

/** The key a word names, by name or alias; undefined for a word no key carries. */
export function selectorKey(word: string): SelectorKey | undefined {
  const name = word.toLowerCase();
  return SELECTOR_KEYS.find((key) => key.name === name || key.aliases?.includes(name));
}

/** The result of reading an expression: the selector it means, or where it goes wrong. */
export type ExpressionCheck =
  | { ok: true; expression: SelectorNode }
  | { ok: false; error: string; at: number };

type TokenKind = "end" | "word" | "operator" | "open" | "close" | "quoted";
/** A token; a word that names a key and stands where a key may is marked as one. */
type Token = { kind: TokenKind; text: string; at: number; key?: boolean };

const OPERATOR_CHARS = "=!<>";
const isKeyChar = (c: string) => /[A-Za-z0-9_]/.test(c);
const isSpace = (c: string) => /\s/.test(c);

class ExpressionError extends Error {
  constructor(message: string, readonly at: number) {
    super(message);
  }
}

/**
 * Cuts the text into words, operators, parentheses and quoted strings the
 * way the server does: a key runs over letters, digits and '_' and ends at
 * its operator; the value after an operator runs to the next space,
 */
function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  let afterKey = false;
  let valueNext = false;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (isSpace(c)) {
      i++;
    } else if (c === "(" || c === ")") {
      tokens.push({ kind: c === "(" ? "open" : "close", text: c, at: i });
      afterKey = valueNext = false;
      i++;
    } else if (c === '"') {
      let end = i + 1;
      let value = "";
      while (end < text.length && text[end] !== '"') {
        if (text[end] === "\\" && end + 1 < text.length) end++;
        value += text[end];
        end++;
      }
      if (end >= text.length) throw new ExpressionError(`the quote opened at ${i} is never closed`, i);
      tokens.push({ kind: "quoted", text: value, at: i });
      afterKey = valueNext = false;
      i = end + 1;
    } else if (afterKey && OPERATOR_CHARS.includes(c)) {
      let end = i;
      while (end < text.length && OPERATOR_CHARS.includes(text[end])) end++;
      tokens.push({ kind: "operator", text: text.slice(i, end), at: i });
      afterKey = false;
      valueNext = true;
      i = end;
    } else {
      let end = i;
      while (end < text.length && !isSpace(text[end]) && text[end] !== "(" && text[end] !== ")" && text[end] !== '"') {
        if (!valueNext && !isKeyChar(text[end])) break;
        end++;
      }
      if (end === i) {
        // An operator with no key before it is cut as one, so the error
        // can say what is missing in front of it.
        while (end < text.length && OPERATOR_CHARS.includes(text[end])) end++;
        if (end === i) throw new ExpressionError(`unexpected "${c}" at ${i}`, i);
        tokens.push({ kind: "operator", text: text.slice(i, end), at: i });
        afterKey = false;
        valueNext = true;
        i = end;
        continue;
      }
      const word = text.slice(i, end);
      afterKey = !valueNext && selectorKey(word) !== undefined;
      tokens.push({ kind: "word", text: word, at: i, key: afterKey });
      valueNext = false;
      i = end;
    }
  }
  tokens.push({ kind: "end", text: "", at: text.length });
  return tokens;
}

/** A recursive-descent reader over the tokens: or, then and, then not, then a condition. */
class Parser {
  private pos = 0;
  constructor(private readonly tokens: Token[]) {}

  peek(): Token { return this.tokens[this.pos]; }
  next(): Token {
    const token = this.tokens[this.pos];
    if (token.kind !== "end") this.pos++;
    return token;
  }
  keyword(word: string): boolean {
    const token = this.peek();
    return token.kind === "word" && token.text.toLowerCase() === word;
  }

  or(): SelectorNode {
    const left = this.and();
    if (!this.keyword("or")) return left;
    const alternatives = [left];
    while (this.keyword("or")) {
      this.next();
      alternatives.push(this.and());
    }
    return { any: alternatives };
  }

  and(): SelectorNode {
    const left = this.not();
    if (!this.keyword("and")) return left;
    const all = [left];
    while (this.keyword("and")) {
      this.next();
      all.push(this.not());
    }
    return { all };
  }

  not(): SelectorNode {
    if (this.keyword("not")) {
      this.next();
      return { not: this.not() };
    }
    return this.primary();
  }

  primary(): SelectorNode {
    const token = this.next();
    switch (token.kind) {
      case "open": {
        const inner = this.or();
        const closing = this.next();
        if (closing.kind !== "close") throw new ExpressionError(`the parenthesis opened at ${token.at} is never closed`, token.at);
        return inner;
      }
      case "word":
        return this.condition(token);
      case "end":
        throw new ExpressionError("a condition is missing at the end", token.at);
      default:
        throw new ExpressionError(`unexpected "${token.text}" at ${token.at}`, token.at);
    }
  }

  condition(name: Token): SelectorNode {
    const key = selectorKey(name.text);
    if (!key) {
      throw new ExpressionError(`"${name.text}" at ${name.at} is not a key; use one of ${SELECTOR_KEYS.map((k) => k.name).join(", ")}`, name.at);
    }
    const operator = this.next();
    if (operator.kind !== "operator") {
      throw new ExpressionError(`an operator such as = is expected after "${name.text}" at ${name.at}`, operator.at);
    }
    const value = this.next();
    if (value.kind !== "word" && value.kind !== "quoted") {
      throw new ExpressionError(`a value is expected after "${operator.text}" at ${operator.at}`, value.at);
    }
    switch (operator.text) {
      case "=":
      case "==":
        return leaf(key, value.text, value.at);
      case "!=":
        return { not: leaf(key, value.text, value.at) };
      case "<":
      case "<=":
      case ">":
      case ">=":
        if (!key.ordered) {
          throw new ExpressionError(`${key.name} compares only with = and !=; ${operator.text} at ${operator.at} applies to agent_version`, operator.at);
        }
        return leaf(key, `${operator.text} ${value.text}`, value.at);
      default:
        throw new ExpressionError(`"${operator.text}" at ${operator.at} is not an operator; use =, !=, <, <=, > or >=`, operator.at);
    }
  }
}

/**
 * One leaf, checked the way the server validates it, so the field refuses
 * what the server would refuse and in the same words.
 */
function leaf(key: SelectorKey, value: string, at: number): SelectorNode {
  if (value === "") throw new ExpressionError(`${key.name} needs a value at ${at}`, at);
  if (value.length > MAX_VALUE) throw new ExpressionError(`${key.name} is longer than ${MAX_VALUE} characters at ${at}`, at);
  if (value.trim() !== value) throw new ExpressionError(`${key.name} has surrounding whitespace at ${at}`, at);
  if (key.values && !key.values.includes(value)) {
    throw new ExpressionError(`${key.name} ${value} at ${at} is not one of ${key.values.join(", ")}`, at);
  }
  if (key.name === "tag" && !TAG_PATTERN.test(value)) {
    throw new ExpressionError(`${value} at ${at} is not a tag (key or key=value, lower-case key)`, at);
  }
  if (key.name === "agent_version") {
    const version = value.replace(/^(<=|>=|<|>|=)\s*/, "");
    if (!VERSION_PATTERN.test(version)) {
      throw new ExpressionError(`${version} at ${at} is not a version such as 0.49.0`, at);
    }
  }
  const node: SelectorNode = {};
  (node as Record<string, string>)[key.name] = value;
  return node;
}

/**
 * Reads the text form of a selector - "site = warsaw and (tag = role=db or
 * not environment = prod)", "agent_version < 0.
 */
export function parseExpression(text: string): ExpressionCheck {
  try {
    const tokens = tokenize(text);
    const parser = new Parser(tokens);
    if (parser.peek().kind === "end") return { ok: false, error: "the expression is empty", at: 0 };
    const expression = parser.or();
    const rest = parser.peek();
    if (rest.kind !== "end") return { ok: false, error: `unexpected "${rest.text}" at ${rest.at}`, at: rest.at };
    return { ok: true, expression };
  } catch (error) {
    if (error instanceof ExpressionError) return { ok: false, error: error.message, at: error.at };
    throw error;
  }
}

/**
 * The words that could come next, for the list under the field: the keys
 * where a condition starts, the values of a key that takes a fixed set after
 * its operator, and the keywords after a complete condition.
 */
export function expressionSuggestions(text: string): string[] {
  let tokens: Token[];
  try {
    tokens = tokenize(text);
  } catch {
    return [];
  }
  // The token being typed is the last one when the text does not end
  // in a space; otherwise the next token is empty and the last is done.
  const typing = text.length > 0 && !isSpace(text[text.length - 1]);
  const done = tokens.slice(0, -1);
  const lastToken = done[done.length - 1];
  const current = typing && lastToken && (lastToken.kind === "word" || lastToken.kind === "operator") ? lastToken : undefined;
  const before = current ? done.slice(0, -1) : done;
  const prefix = current?.kind === "word" ? current.text.toLowerCase() : "";
  const last = before[before.length - 1];
  const narrow = (words: string[]) => words.filter((word) => word.startsWith(prefix) && word !== prefix);

  if (!last || last.kind === "open" || (last.kind === "word" && !last.key && ["and", "or", "not"].includes(last.text.toLowerCase()))) {
    const keys = narrow([...SELECTOR_KEYS.map((key) => key.name), "not"]);
    // A key typed in full and nothing else to offer: the operators come next.
    if (keys.length === 0 && current?.key) return operatorsOf(selectorKey(current.text));
    return keys;
  }
  if (last.kind === "operator") {
    const named = before[before.length - 2];
    const key = named?.kind === "word" && named.key ? selectorKey(named.text) : undefined;
    return key?.values ? narrow(key.values) : [];
  }
  if (last.kind === "word" && last.key) {
    return current?.kind === "word" ? [] : operatorsOf(selectorKey(last.text));
  }
  if (last.kind === "word" || last.kind === "quoted" || last.kind === "close") {
    return narrow(["and", "or"]);
  }
  return [];
}

/** The operators a key takes: every one for an ordered key, equality and its negation otherwise. */
function operatorsOf(key: SelectorKey | undefined): string[] {
  return key?.ordered ? SELECTOR_OPERATORS : SELECTOR_OPERATORS.slice(0, 2);
}

/**
 * The expression in one line as the server describes it and the field reads
 * it back: "(site=warsaw and not tag=role=db)".
 */
export function expressionText(expression?: SelectorNode | null): string {
  if (!expression) return "";
  if (expression.all) return `(${expression.all.map(expressionText).join(" and ")})`;
  if (expression.any) return `(${expression.any.map(expressionText).join(" or ")})`;
  if (expression.not) return `not ${expressionText(expression.not)}`;
  const [field, raw] = Object.entries(expression).find(([, v]) => typeof v === "string") ?? ["nothing", ""];
  const value = typeof raw === "string" ? raw : "";
  if (!value) return field;
  if (field === "agent_version") {
    const match = /^(<=|>=|<|>|=)?\s*(.*)$/.exec(value);
    return `${field} ${match?.[1] ?? "="} ${match?.[2] ?? value}`;
  }
  return `${field}=${value}`;
}
