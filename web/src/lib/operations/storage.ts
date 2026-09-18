import {
  define, DEVICE_PATH, DURABLE_SOURCE, FILESYSTEM_TYPE, LVM_SIZE, MOUNT_OPTIONS, required, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Disks, filesystems and volumes.
 *
 * A device is named by something that still means the same thing after a
 * reboot: /dev/sdb is whichever disk the kernel found second this time. The
 * planning step resolves the source to the filesystem's own identifier, and
 * that identifier is what travels in the change.
 */

const GROUP = "Storage";

const PLAN_NOTE =
  "Every host computes its own plan first: the planning step resolves the device to the filesystem it really holds, says whether it is mounted and how much room there is, and the change is bound to that.";

const deviceField: OperationField = {
  name: "device",
  label: "Device",
  kind: "text",
  placeholder: "/dev/vg0/data",
  hint: "A path in /dev, or a durable identifier such as UUID=…",
};

function deviceCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "device", "Name the device this acts on.")) {
    const value = text(form, "device");
    if (!DEVICE_PATH.test(value) && !DURABLE_SOURCE.test(value)) {
      problems.push({
        field: "device",
        message: "A device is a path in /dev or a durable identifier: UUID=, PARTUUID=, LABEL= or PARTLABEL=.",
      });
    }
  }
  return problems;
}

export const storage: OperationEntry[] = [
  define({
    action: "mount.ensure",
    title: "Mount a filesystem",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    fields: [
      {
        name: "source", label: "Filesystem", kind: "text", placeholder: "UUID=…",
        hint: "A durable identifier or a path in /dev. The planning step turns a path into the identifier of the filesystem the host really has there.",
      },
      {
        name: "target", label: "Mount point", kind: "path", placeholder: "/srv/data",
        hint: "The directory it appears at. The panel mounts nothing onto the system's own directories.",
      },
      { name: "fs_type", label: "Filesystem type", kind: "text", placeholder: "ext4" },
      {
        name: "options", label: "Mount options", kind: "text", placeholder: "defaults,noatime",
        hint: "As they would stand in fstab, separated by commas.",
      },
      {
        name: "persist", label: "Keep it after a reboot", kind: "boolean",
        hint: "Writes the entry in fstab. Without it the mount is gone at the next boot - and that is something to know before the outage, not after.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "source", "Name the filesystem to mount.")) {
        const source = text(form, "source");
        if (!DEVICE_PATH.test(source) && !DURABLE_SOURCE.test(source)) {
          problems.push({
            field: "source",
            message: "A filesystem is named by a durable identifier (UUID=, LABEL=) or by a path in /dev.",
          });
        }
      }
      if (required(problems, form, "target", "Say where it is to appear.")) {
        const target = text(form, "target");
        if (!target.startsWith("/") || target.includes("..") || /[\n\t]/.test(target)) {
          problems.push({ field: "target", message: "The mount point is an absolute, normalised path." });
        } else if (["/", "/boot", "/dev", "/etc", "/proc", "/run", "/sys", "/usr", "/var",
          "/var/lib", "/var/log", "/bin", "/sbin", "/lib"].includes(target)) {
          problems.push({ field: "target", message: "The panel mounts nothing onto {value}.", params: { value: target } });
        }
      }
      if (required(problems, form, "fs_type", "Say what kind of filesystem it is.")) {
        if (!FILESYSTEM_TYPE.test(text(form, "fs_type"))) {
          problems.push({ field: "fs_type", message: "A filesystem type is lower-case letters and digits, e.g. ext4 or xfs." });
        }
      }
      if (!MOUNT_OPTIONS.test(text(form, "options"))) {
        problems.push({ field: "options", message: "The options carry a character fstab would not take." });
      }
      return problems;
    },
    target: (form) => text(form, "target"),
  }),

  define({
    action: "mount.remove",
    title: "Unmount a filesystem",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "The entry in fstab goes with it, so the filesystem does not come back at the next boot.",
    fields: [
      { name: "target", label: "Mount point", kind: "path", placeholder: "/srv/data", hint: "The directory the filesystem appears at now." },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "target", "Say which mount point is to go.")) {
        const target = text(form, "target");
        if (!target.startsWith("/") || target.includes("..") || /[\n\t]/.test(target)) {
          problems.push({ field: "target", message: "The mount point is an absolute, normalised path." });
        }
      }
      return problems;
    },
    target: (form) => text(form, "target"),
  }),

  define({
    action: "filesystem.check",
    title: "Check a filesystem",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "A mounted filesystem is not checked: the planning step says so and the host refuses rather than reporting a check that never ran.",
    fields: [
      deviceField,
      {
        name: "repair", label: "Repair what it finds", kind: "boolean",
        hint: "Off only reports. On lets the check rewrite the filesystem's structures, which is why it is a decision of its own.",
      },
    ],
    check: deviceCheck,
    target: (form) => text(form, "device"),
  }),

  define({
    action: "filesystem.resize",
    title: "Grow a filesystem to its volume",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "A volume made bigger gives not a byte of space until the filesystem on it follows.",
    fields: [
      deviceField,
      {
        name: "expected_uuid", label: "Only if it is this filesystem", kind: "text", placeholder: "UUID value",
        hint: "Binds the operation to one filesystem, so a device path that came to mean something else stops it.",
      },
    ],
    check: deviceCheck,
    target: (form) => text(form, "device"),
  }),

  define({
    action: "lvm.extend",
    title: "Grow a logical volume",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "The filesystem on the volume grows together with it: a volume bigger than its filesystem is space nobody can use.",
    fields: [
      { ...deviceField, label: "Volume", hint: "The logical volume as a path in /dev, e.g. /dev/vg0/data." },
      {
        name: "size", label: "Grow it by", kind: "text", placeholder: "+10G",
        hint: "An increment such as +10G, or a share of what is free such as +100%FREE. The panel only grows volumes.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "device", "Name the volume to grow.")) {
        if (!DEVICE_PATH.test(text(form, "device"))) {
          problems.push({ field: "device", message: "A logical volume is a path in /dev, e.g. /dev/vg0/data." });
        }
      }
      if (required(problems, form, "size", "Say how much to add.")) {
        if (!LVM_SIZE.test(text(form, "size"))) {
          problems.push({
            field: "size",
            message: "The size is an increment starting with +, e.g. +10G or +100%FREE.",
          });
        }
      }
      return problems;
    },
    target: (form) => text(form, "device"),
  }),
];
