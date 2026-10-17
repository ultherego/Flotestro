/**
 * What a process row says about a process, apart from the numbers.
 *
 * Both panels print the same two things: the scheduler letter in words, and
 * whether the row is a kernel thread rather than something somebody started.
 */

/**
 * The scheduler state in words.
 */
export function stateWords(state: string): string {
  switch (state.charAt(0)) {
    case "R": return "running";
    case "S": return "sleeping";
    case "D": return "waiting on disk";
    case "Z": return "zombie";
    case "T":
    case "t": return "stopped";
    case "I": return "idle";
    case "X": return "dead";
    default: return state;
  }
}

/**
 * Whether a process is a kernel thread: a child of kthreadd (PID 2) or
 * kthreadd itself.
 */
export function kernelThread(process: { pid: number; ppid: number }): boolean {
  return process.pid === 2 || process.ppid === 2;
}
