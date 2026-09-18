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

// No example device here on purpose. A path in /dev is whatever this
// host's kernel handed out, and these orders format, delete and overwrite:
// an example that looks like a real disk is an invitation to wipe one. The
// host's storage page prints the true name on every row.
const deviceField: OperationField = {
  name: "device",
  label: "Device",
  kind: "text",
  hint: "A path in /dev or a durable identifier such as UUID=…, copied from the device's own row on the host's storage page.",
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

/**
 * A size LVM takes for something being created: absolute, or a share of
 * what is free. An increment starting with "+" belongs to a growth, where
 * there is already something to add to.
 */
const LVM_ABSOLUTE_SIZE = /^\d{1,9}[KMGTkmgt]$|^\d{1,3}%(FREE|VG|PVS|ORIGIN)$/;

/** An LVM name: what LVM itself accepts, without a leading hyphen. */
const LVM_NAME = /^[A-Za-z0-9+_.][A-Za-z0-9+_.-]{0,62}$/;

const ARRAY_PATH = /^\/dev\/md[0-9]{1,4}$|^\/dev\/md\/[A-Za-z0-9._-]{1,64}$/;

const ARRAY_NOTE =
  "The panel manages the members of an array that exists. Creating an array and destroying one are decisions about a machine's whole disk layout, taken on the machine when it is built, and the panel refuses them by name.";

const arrayField: OperationField = {
  name: "array",
  label: "Array",
  kind: "text",
  hint: "The array as the kernel names it, copied from the array's card on the host's storage page. The order also carries the UUID out of its superblock, because the path is whichever array the kernel assembled first this boot.",
};

const arrayIdentityField: OperationField = {
  name: "expected_array_uuid",
  label: "Only if the array is this one",
  kind: "text",
  placeholder: "The UUID from the array's row",
  hint: "The identity out of the superblock. Without it the order names a path, and a path is not an array.",
};

const memberField: OperationField = {
  name: "device",
  label: "Member",
  kind: "text",
  hint: "The device inside the array, copied from the member's row on the array's card.",
};

const memberIdentityField: OperationField = {
  name: "expected_by_id",
  label: "Only if the member is this disk",
  kind: "text",
  placeholder: "/dev/disk/by-id/…",
  hint: "The by-id link of the member. A path in /dev points at another disk after a reboot, which in an array is the difference between the dying disk and the healthy one.",
};

/** What every array order has to name before the host is asked. */
function memberCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "array", "Name the array this acts on.")) {
    if (!ARRAY_PATH.test(text(form, "array"))) {
      problems.push({ field: "array", message: "An array is a path in /dev: /dev/md and its number, or /dev/md/ and its name." });
    }
  }
  if (required(problems, form, "device", "Name the member this acts on.")) {
    if (!DEVICE_PATH.test(text(form, "device"))) {
      problems.push({ field: "device", message: "A member is a path in /dev, as the array's card names it." });
    }
  }
  required(problems, form, "expected_array_uuid",
    "Give the UUID of the array; a path alone names whichever array the kernel assembled first.");
  required(problems, form, "expected_by_id",
    "Give the by-id link of the member; a path in /dev points at another disk after a reboot.");
  return problems;
}

/**
 * Software RAID: the members of an array that exists.
 *
 * Failing a member is how a dying disk leaves the array before it takes the
 * array with it - and it is also the move that spends the array's
 * redundancy, which is why the plan says what the array is left with and
 * the host refuses on an array that has nothing left to lose.
 */
const arrays: OperationEntry[] = [
  define({
    action: "raid.member.fail",
    title: "Mark an array member failed",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: `${ARRAY_NOTE} Failing a member spends the redundancy of the array: the host refuses on a level that keeps no copy, on an array already degraded, on one that is rebuilding, and on the last member carrying data.`,
    fields: [arrayField, memberField, arrayIdentityField, memberIdentityField],
    check: memberCheck,
    target: (form) => `${text(form, "array")} ${text(form, "device")}`,
  }),

  define({
    action: "raid.member.remove",
    title: "Take a member out of an array",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "A member that still carries data is not removed: mark it failed first, then take it out. Two orders, because they are two decisions.",
    fields: [arrayField, memberField, arrayIdentityField, memberIdentityField],
    check: memberCheck,
    target: (form) => `${text(form, "array")} ${text(form, "device")}`,
  }),

  define({
    action: "raid.member.add",
    title: "Add a member to an array",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "The device joins as a spare and a degraded array starts rebuilding onto it at once. Whatever the device carried is overwritten with an array superblock, so it is bound to the same stable identity a format is.",
    fields: [arrayField, memberField, arrayIdentityField, memberIdentityField],
    check: memberCheck,
    target: (form) => `${text(form, "array")} ${text(form, "device")}`,
  }),
];

const groupField: OperationField = {
  name: "group",
  label: "Volume group",
  kind: "text",
  hint: "The group the operation acts in, named as the host's storage page lists it. The order also carries the group's UUID: a name can be given to another group after a rename.",
};

const groupIdentityField: OperationField = {
  name: "expected_group_uuid",
  label: "Only if the group is this one",
  kind: "text",
  placeholder: "The UUID from the group's row",
  hint: "The group's LVM UUID.",
};

const volumeIdentityField: OperationField = {
  name: "expected_volume_uuid",
  label: "Only if the volume is this one",
  kind: "text",
  placeholder: "The UUID from the volume's row",
  hint: "The volume's LVM UUID. A path is a name another volume can carry tomorrow.",
};

/**
 * LVM beyond growing a volume.
 *
 * The group is never created here: which disks a machine gives to LVM is
 * decided when the machine is built. What these orders do is work inside a
 * group that exists - and every one of them names the group or the volume
 * by its UUID, because that is what makes the consent mean one thing.
 */
const volumes: OperationEntry[] = [
  define({
    action: "lvm.volume.create",
    title: "Create a logical volume",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "The volume is created in a group that exists. A group without room for it is a refusal in the plan, and the size is read back afterwards: LVM allocates whole extents and rounds a request up.",
    fields: [
      groupField,
      { name: "volume", label: "Name", kind: "text", hint: "The name of the new volume inside the group." },
      {
        name: "size", label: "Size", kind: "text", placeholder: "10G",
        hint: "An absolute size such as 10G, or a share of what is free such as 100%FREE.",
      },
      groupIdentityField,
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "group", "Name the group to create it in.")) {
        if (!LVM_NAME.test(text(form, "group"))) {
          problems.push({ field: "group", message: "A group name starts with a letter, a digit, a dot or an underscore." });
        }
      }
      if (required(problems, form, "volume", "Name the volume.")) {
        if (!LVM_NAME.test(text(form, "volume"))) {
          problems.push({ field: "volume", message: "A volume name starts with a letter, a digit, a dot or an underscore." });
        }
      }
      if (required(problems, form, "size", "Say how big it is to be.")) {
        if (!LVM_ABSOLUTE_SIZE.test(text(form, "size"))) {
          problems.push({ field: "size", message: "The size is absolute, e.g. 10G, or a share of what is free, e.g. 100%FREE." });
        }
      }
      required(problems, form, "expected_group_uuid",
        "Give the UUID of the group; a group name is a label another group can carry.");
      return problems;
    },
    target: (form) => `${text(form, "group")}/${text(form, "volume")}`,
  }),

  define({
    action: "lvm.group.extend",
    title: "Add a disk to a volume group",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "The disk is given an LVM label, which overwrites whatever it carried, and then joins the group. That is the same loss as a format, so it takes two approvals, the target typed out and the by-id link of the disk.",
    fields: [
      groupField,
      { ...deviceField, label: "Disk", hint: "The disk or partition to hand to the group. Everything on it is overwritten." },
      groupIdentityField,
      {
        name: "expected_by_id", label: "Only if the disk is this one", kind: "text",
        placeholder: "/dev/disk/by-id/…",
        hint: "The by-id link of the disk. The size is a description and is never taken as an identity.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = deviceCheck(form);
      if (required(problems, form, "group", "Name the group to extend.")) {
        if (!LVM_NAME.test(text(form, "group"))) {
          problems.push({ field: "group", message: "A group name starts with a letter, a digit, a dot or an underscore." });
        }
      }
      required(problems, form, "expected_group_uuid", "Give the UUID of the group.");
      required(problems, form, "expected_by_id",
        "Give the by-id link of the disk; a path in /dev points at another disk after a reboot.");
      return problems;
    },
    target: (form) => `${text(form, "group")} ← ${text(form, "device")}`,
  }),

  define({
    action: "lvm.volume.remove",
    title: "Delete a logical volume",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "The extents go back to the group and the filesystem on them is gone. Like formatting, it takes two approvals, the target typed out and the stable identity of the volume; a volume with snapshots on it is refused until they are gone.",
    fields: [
      { ...deviceField, label: "Volume", hint: "The logical volume as a path in /dev, copied from the volume's row on the host's storage page." },
      volumeIdentityField,
      {
        name: "expected_by_id", label: "Only if the volume is this device", kind: "text",
        placeholder: "/dev/disk/by-id/dm-uuid-…",
        hint: "The by-id link the kernel publishes for the volume.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "device", "Name the volume to delete.")) {
        if (!DEVICE_PATH.test(text(form, "device"))) {
          problems.push({ field: "device", message: "A logical volume is a path in /dev, as the volume's row prints it." });
        }
      }
      required(problems, form, "expected_volume_uuid", "Give the UUID of the volume.");
      required(problems, form, "expected_by_id", "Give the by-id link of the volume.");
      return problems;
    },
    target: (form) => text(form, "device"),
  }),

  define({
    action: "lvm.snapshot.create",
    title: "Take a snapshot of a volume",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "A snapshot needs room in the group for its copy-on-write space, and a snapshot that fills up is dropped by the kernel. It is taken of a volume, never of another snapshot.",
    fields: [
      { ...deviceField, label: "Origin volume", hint: "The volume to snapshot, as a path in /dev." },
      { name: "volume", label: "Snapshot name", kind: "text", placeholder: "logs-before-upgrade" },
      {
        name: "size", label: "Copy-on-write space", kind: "text", placeholder: "2G",
        hint: "An absolute size such as 2G, or a share of the origin such as 20%ORIGIN.",
      },
      volumeIdentityField,
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "device", "Name the volume to snapshot.")) {
        if (!DEVICE_PATH.test(text(form, "device"))) {
          problems.push({ field: "device", message: "A logical volume is a path in /dev, as the volume's row prints it." });
        }
      }
      if (required(problems, form, "volume", "Name the snapshot.")) {
        if (!LVM_NAME.test(text(form, "volume"))) {
          problems.push({ field: "volume", message: "A snapshot name starts with a letter, a digit, a dot or an underscore." });
        }
      }
      if (required(problems, form, "size", "Say how much copy-on-write space it gets.")) {
        if (!LVM_ABSOLUTE_SIZE.test(text(form, "size"))) {
          problems.push({ field: "size", message: "The size is absolute, e.g. 2G, or a share of the origin, e.g. 20%ORIGIN." });
        }
      }
      required(problems, form, "expected_volume_uuid", "Give the UUID of the origin volume.");
      return problems;
    },
    target: (form) => `${text(form, "volume")} ← ${text(form, "device")}`,
  }),

  define({
    action: "lvm.snapshot.remove",
    title: "Drop a snapshot",
    group: GROUP,
    key: "storage",
    plan: PLAN_NOTE,
    note: "Only a snapshot: the same command on an ordinary volume deletes somebody's filesystem, which is a separate operation with two approvals behind it.",
    fields: [
      { ...deviceField, label: "Snapshot", hint: "The snapshot as a path in /dev, copied from the snapshot's row on the host's storage page." },
      volumeIdentityField,
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "device", "Name the snapshot to drop.")) {
        if (!DEVICE_PATH.test(text(form, "device"))) {
          problems.push({ field: "device", message: "A snapshot is a path in /dev, as the snapshot's row prints it." });
        }
      }
      required(problems, form, "expected_volume_uuid", "Give the UUID of the snapshot.");
      return problems;
    },
    target: (form) => text(form, "device"),
  }),
];

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
        name: "target", label: "Mount point", kind: "path",
        hint: "The absolute path the filesystem is to appear at. The panel mounts nothing onto the system's own directories, and a directory that already holds something has it hidden under the mount.",
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
      {
        name: "target", label: "Mount point", kind: "path",
        hint: "The directory the filesystem appears at now, copied from the mount's row on the host's storage page.",
      },
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
        name: "expected_uuid", label: "Only if it is this filesystem", kind: "text",
        placeholder: "The UUID from the filesystem's row",
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
      { ...deviceField, label: "Volume", hint: "The logical volume as a path in /dev, copied from the volume's row on the host's storage page." },
      {
        name: "size", label: "Grow it by", kind: "text", placeholder: "+10G",
        hint: "An increment such as +10G, or a share of what is free such as +100%FREE. The panel only grows volumes.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "device", "Name the volume to grow.")) {
        if (!DEVICE_PATH.test(text(form, "device"))) {
          problems.push({ field: "device", message: "A logical volume is a path in /dev, as the volume's row prints it." });
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

  ...arrays,
  ...volumes,
];