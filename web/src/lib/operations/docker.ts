import {
  bounded, COMPOSE_PROJECT, define, required, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Containers.
 *
 * A container is named by its identifier and not by its name: a name is a
 * label that can move to another container between the plan and the
 * execution, and the operator approved one specific object. The name
 * travels beside it for the audit trail, so what they saw is what stays in
 * the record.
 */

const GROUP = "Containers";

/** The engine's own identifier: twelve to sixty-four hexadecimal characters. */
const CONTAINER_ID = /^[0-9a-f]{12,64}$/;

const containerField: OperationField = {
  name: "container_id",
  label: "Container",
  kind: "text",
  hint: "The engine's identifier, as the container list shows it. A name may point at a different container by the time the change runs.",
  placeholder: "3f2a9c1b4d55",
};

const nameField: OperationField = {
  name: "name",
  label: "Name it had",
  kind: "text",
  hint: "What the container was called when the order was made; it serves the record alone and changes nothing.",
};

function containerCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "container_id", "Name the container this acts on.")) {
    shaped(problems, form, "container_id", CONTAINER_ID,
      "A container identifier is twelve to sixty-four hexadecimal characters.");
  }
  bounded(problems, form, "timeout_seconds", 1, 3600, "The time to shut down lies between 1 and 3600 seconds.");
  return problems;
}

const stopTimeout: OperationField = {
  name: "timeout_seconds",
  label: "Give it this long to shut down",
  kind: "duration",
  min: 0,
  max: 3600,
  hint: "How long the container may take to stop before it is killed. Zero takes the engine's own.",
};

export const docker: OperationEntry[] = [
  define({
    action: "docker.container.start",
    title: "Start a container",
    group: GROUP,
    key: "docker_container",
    fields: [containerField, nameField],
    check: containerCheck,
    target: (form) => text(form, "name") || text(form, "container_id"),
  }),

  define({
    action: "docker.container.stop",
    title: "Stop a container",
    group: GROUP,
    key: "docker_container",
    fields: [containerField, nameField, stopTimeout],
    check: containerCheck,
    target: (form) => text(form, "name") || text(form, "container_id"),
  }),

  define({
    action: "docker.container.restart",
    title: "Restart a container",
    group: GROUP,
    key: "docker_container",
    fields: [containerField, nameField, stopTimeout],
    check: containerCheck,
    target: (form) => text(form, "name") || text(form, "container_id"),
  }),

  define({
    action: "docker.image.pull",
    title: "Fetch a container image",
    group: GROUP,
    key: "docker_image",
    note: "Only the image is fetched; nothing on the host starts using it until a container is recreated.",
    fields: [
      {
        name: "reference", label: "Image", kind: "text", placeholder: "nginx:1.27",
        hint: "The full reference, registry included where it is not the default one. Name the tag or the digest: without one the host takes whatever latest points at that day.",
        wide: true,
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "reference", "Name the image to fetch.")) {
        const reference = text(form, "reference");
        if (/\s/.test(reference) || reference.length > 512) {
          problems.push({ field: "reference", message: "An image reference is one word, e.g. nginx:1.27." });
        }
      }
      return problems;
    },
    target: (form) => text(form, "reference"),
  }),

  define({
    action: "docker.compose.deploy",
    title: "Deploy a Compose project",
    group: GROUP,
    key: "compose",
    plan: "Every host computes its own plan first: the planning step resolves the images the manifest names to their digests and returns the digest of the whole plan, and the deployment carries it back. A tag that moved in the meantime stops the deployment.",
    note: "The manifest travels in the order rather than as a reference to a file on the host: the operator approves the content they read.",
    fields: [
      {
        name: "project", label: "Project", kind: "text", placeholder: "storefront",
        hint: "The project name the containers are grouped under; lower-case letters, digits, underscore and hyphen.",
      },
      {
        name: "manifest", label: "Compose file", kind: "textarea", wide: true,
        hint: "The whole compose file as it is to stand on the host.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "project", "Give the project a name.")) {
        shaped(problems, form, "project", COMPOSE_PROJECT,
          "A project name is lower-case letters, digits, underscore and hyphen.");
      }
      const manifest = text(form, "manifest");
      if (manifest === "") {
        problems.push({ field: "manifest", message: "Paste the compose file the project is to run from." });
      } else if (manifest.length > 256 * 1024) {
        problems.push({ field: "manifest", message: "The compose file is larger than 256 kB; that is no longer something an approver reads." });
      }
      return problems;
    },
    target: (form) => text(form, "project"),
  }),
];
