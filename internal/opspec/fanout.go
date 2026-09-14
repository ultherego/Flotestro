package opspec

// fanOutLimits is the registry of diagnostic reads that may run on many
// hosts at once, with the ceiling of hosts one fan-out covers.
//
// A read fan-out is not a campaign: it changes nothing, needs no approval
// and has no waves - it is the same read the operator orders on one host,
// ordered on a handful at once. The ceiling protects the control plane,
// not the hosts: every host answers with its own output, and fifty
// journal reads at once are fifty outputs the panel has to hold and merge.
//
// The registry is an explicit list for the same reason the campaign modes
// are one: a read being cheap on one host says nothing about what it costs
// on a hundred. An operation outside this map does not fan out - a missing
// declaration is a refusal, not consent by omission. The ceilings follow
// the module chapters of the multitasking document: a process snapshot on
// ten hosts, a log read on twenty, a state read or a test on fifty.
var fanOutLimits = map[ActionType]int{
	// A process snapshot is the largest single read: up to five hundred
	// rows per host, each with a command line.
	ActionProcessList: 10,

	// Log reads return text by the line and are merged into one timeline;
	// the ceiling keeps the merge readable and the output bounded.
	ActionReadJournal:  20,
	ActionReadLogFile:  20,
	ActionDockerLogs:   20,
	ActionDockerEvents: 20,
	// A file read hands the panel the content of the file: the same
	// ceiling as a log, because that is what it usually is.
	ActionFileRead: 20,

	// State reads, plans and tests: one structured answer per host.
	ActionSecurityScan:     50,
	ActionCertificateScan:  50,
	ActionDNSResolveTest:   50,
	ActionTimeSyncTest:     50,
	ActionPackageList:      50,
	ActionPackagePlan:      50,
	ActionUnitStatus:       50,
	ActionDockerRead:       50,
	ActionComposePlan:      50,
	ActionStoragePlan:      50,
	ActionStorageSmartRead: 50,
	ActionNetworkPlan:      50,
	ActionFirewallPlan:     50,
	ActionSSHConfigPlan:    50,
	ActionSysctlPlan:       50,
	ActionFilePlan:         50,
	ActionDomainPreflight:  50,
}

// FanOutLimit says how many hosts one diagnostic read may cover at once.
//
// Zero means an operation that does not fan out: every mutation, and the
// reads that are deliberately kept to one host. A live view of the journal
// is one of them - it holds a process on the host for as long as it lasts,
// and five hosts streaming into one screen is a different feature with its
// own limits, not a read repeated five times.
func (a ActionType) FanOutLimit() int {
	if a.Mutating() {
		return 0
	}
	return fanOutLimits[a]
}

// FanOutRefusal names the reason an operation does not fan out. An empty
// value means it does.
func FanOutRefusal(action ActionType) string {
	if !action.Known() {
		return "unknown operation"
	}
	if action.Mutating() {
		return "a fan-out is for reads only; a change on many hosts is a campaign"
	}
	if action == ActionFollowJournal {
		return "a live view holds a process on the host for as long as it lasts; " +
			"follow one host at a time, or read the journal on many"
	}
	if fanOutLimits[action] == 0 {
		return "this read is not available as a fan-out; run it host by host"
	}
	return ""
}
