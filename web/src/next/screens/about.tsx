import type { ReactNode } from "react";
import type { IconName } from "../../components/icons";

/**
 * What each screen is, in one line and at length.
 *
 * It is here and not in the screens because a heading is not a screen's
 * own business: every one of them must have the same shape - the mark of
 * its place, its name, the line that says what it answers, and the mark
 * that opens the rest. Left to each screen, seventeen of them wrote
 * seventeen headings and six wrote none at all.
 *
 * The shell draws it from here, so a screen cannot forget it, and a test
 * refuses an address that has no entry.
 */
export type About = {
  /** The English title; it goes through the translation catalogue. */
  title: string;
  /** One line, at most about eighty characters: what this screen answers. */
  lead: string;
  /** The rest of it, behind the mark beside the title. */
  help: ReactNode;
  /** The mark of the screen; the same one the rail gives its place. */
  icon: IconName;
};

export const ABOUT: Record<string, About> = {
  dashboard: {
    title: "Fleet dashboard",
    lead: "Only what needs a decision.",
    icon: "dashboard",
    help: "Every counter here is taken in the database over the hosts you are allowed to see, not over a page of them. A counter the server could not answer honestly for your view is left out rather than drawn as a nought, and a count at zero is a word under the list rather than a tile of its own.",
  },
  hosts: {
    title: "Hosts",
    lead: "Every machine this installation manages, as the agents last reported them.",
    icon: "hosts",
    help: "The list narrows on the server, so a filter answers over the whole fleet you may see rather than over the page in front of you. A figure a host never reported is an em dash: a machine nobody has asked is not a machine with nothing wrong.",
  },
  jobs: {
    title: "Jobs",
    lead: "Every operation ordered on a host, and what became of it.",
    icon: "jobs",
    help: "A job is one operation on one host. It carries who ordered it, who approved it where approval was needed, and the result the host reported. An outcome nobody could confirm is not a failure and not a success - it is in Needs confirmation until somebody rules on it.",
  },
  unresolved: {
    title: "Needs confirmation",
    lead: "What the fleet could not confirm, kept apart from what it could.",
    icon: "jobs",
    help: "Two different uncertainties, and they are never added together. 'Did it happen?' is an operation whose outcome never came back. 'Did it hold?' is a change that was applied and could not be verified afterwards. Nothing here disappears with time; somebody rules on it.",
  },
  readiness: {
    title: "Readiness",
    lead: "What the fleet cannot be asked to do, and why.",
    icon: "overview",
    help: "Ordering work a host cannot carry out is refused one host at a time. This is where that is read once, before the order: which operations have nowhere to run, which have a gap on some hosts, and which hosts have reported no adapter at all. A silent host is not a complete host.",
  },
  reads: {
    title: "Reads",
    lead: "A read ordered on several hosts at once.",
    icon: "reads",
    help: "A diagnostic rather than a change: it asks the hosts something and gathers the answers. It is made of ordinary jobs, so every answer is in the trail, and a host that could not be asked says so rather than being left out of the count.",
  },
  campaigns: {
    title: "Campaigns",
    lead: "How the fleet is changed at scale.",
    icon: "campaigns",
    help: "A campaign carries one operation, its payload and the rollout it was approved with: a canary first, then waves, with a gate between them where one is asked for. Every host gets its own plan, and one approval covers the set. A campaign that fails past its threshold stops itself.",
  },
  security: {
    title: "Security",
    lead: "Versioned checks over the facts the hosts already report.",
    icon: "security",
    help: "One bad setting on a hundred hosts is one problem, not a hundred, so a check is the row and the hosts are its count. The sweep has a time budget: when it could not reach the whole fleet the screen says so rather than passing a part off as all of it. A check nobody could judge is never counted as passing.",
  },
  vulnerabilities: {
    title: "Vulnerabilities",
    lead: "What the hosts' own package lists say about known advisories.",
    icon: "vulnerabilities",
    help: "Read from what each host reports it has installed, against the feeds this installation trusts. A host whose packages were never read is not a host with no vulnerabilities, so it is counted apart. Where a vendor fix exists the fix is one campaign.",
  },
  certificates: {
    title: "Certificates",
    lead: "What expires, when, and on which host.",
    icon: "certificates",
    help: "The certificates the hosts report, nearest deadline first. A certificate nobody could read is not a valid one: it is counted as unreadable and says why. The fleet's own authority and its rotation are at the bottom - distributing a new one and withdrawing the old are four deliberate steps, not one button.",
  },
  backups: {
    title: "Backups",
    lead: "What is backed up, how old the newest copy is, and what was never verified.",
    icon: "backups",
    help: "A host that never reported a backup is not a host with no backups, and a copy nobody verified is not a copy that works. Both are counted apart from what is known to be well. The age of the newest copy is the figure that decides whether somebody has to act.",
  },
  monitoring: {
    title: "Monitoring",
    lead: "The rules this installation keeps, and what is firing against them.",
    icon: "monitoring",
    help: "The agents sample; the panel keeps the readings and judges the rules. A rule with no data is not a rule that passed - it says so, and the policy for how long silence is tolerated is part of the rule. A silence stops the alert, not the reading.",
  },
  audit: {
    title: "Audit",
    lead: "Who did what, to what, and what the server made of it.",
    icon: "audit",
    help: "Every change and every refusal, in the order they happened, hash-chained so a gap can be proved rather than argued about. The trail filters on the server. A denial is kept as carefully as a success: one is a typo, a run of them is somebody probing.",
  },
  notifications: {
    title: "Notifications",
    lead: "Where the panel sends what it has to say, and what is stuck.",
    icon: "notifications",
    help: "A channel is an address the panel delivers to - a webhook, a mailbox - and the queue beside it is what it has not managed to deliver. A dead letter is the one that needs a person: the worker has stopped trying. A channel that is disabled stays listed, because it would carry again the moment somebody enables it.",
  },
  relays: {
    title: "Relays",
    lead: "The plumbing of each site, and what it is holding.",
    icon: "relays",
    help: "A relay carries a site's hosts to the control plane and buffers what it cannot deliver yet. A spool that keeps growing is a site going quiet; a relay that never reported its buffer is not a relay with an empty one.",
  },
  groups: {
    title: "Groups",
    lead: "Saved answers to the question 'which hosts'.",
    icon: "groups",
    help: "A member list is what somebody wrote down; a selector is asked again every time it is read, so it follows the fleet. A selector that stopped resolving is not an empty group - it says it cannot be resolved and why.",
  },
  tags: {
    title: "Tags",
    lead: "What operators recorded about the hosts.",
    icon: "groups",
    help: "A tag is either a word or a key and a value. It is written by people, so it is the one fact about a host the panel never infers. Renaming one reaches every host carrying it at once, which is why it asks for a reason.",
  },
  teams: {
    title: "Teams",
    lead: "The boundary of authority over a set of hosts.",
    icon: "accounts",
    help: "A team is not a tag. A tag says what a host is; a team says who answers for it, and a role granted over a team reaches exactly the hosts in it. Moving a host between teams hands the machine to other people, so it takes its own permission.",
  },
  access: {
    title: "Users and access",
    lead: "Who may sign in to this installation, and what each of them may do.",
    icon: "access",
    help: "A role is a set of permissions; a scope says where it applies - the whole fleet, a site, an environment, a team. A role granted by a group of the identity provider cannot be taken away here, because it would come back at the next sign-in: the mapping is where it is edited.",
  },
  profile: {
    title: "My settings",
    lead: "Everything you set for yourself.",
    icon: "settings",
    help: "The theme, the language, the time zone, how long a page is and where the panel opens are kept on the server under your identity, so they follow you to another browser. The size of the text is kept in this browser, because it answers to this screen and no other.",
  },
};
