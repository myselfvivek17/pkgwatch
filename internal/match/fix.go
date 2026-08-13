package match

// FixFor returns the version this package should move to in order to clear an
// advisory: the lowest published fixed bound that is above the version actually
// installed. Empty means the advisory publishes no fix.
//
// The lowest bound overall is the wrong answer and a dangerous one. A single
// advisory routinely carries a fixed version per maintained branch — salt's
// PYSEC records list fifteen, from 2015.8.10 to 3002.5 — and a machine on
// 3002.x told to upgrade to 2015.8.10 is being told to downgrade five years.
// Someone who follows that instruction ends up further from safe than they
// started, and someone who checks it stops believing the column.
//
// Malware has no fix by construction: there is no version of a malicious
// package that is safe to move to, and naming one would read as "upgrade and
// carry on" for the one finding where the answer is remove it.
func FixFor(adv Advisory, pkg Package) string {
	if adv.Kind == "malware" {
		return ""
	}

	compare, err := comparatorFor(adv.Ecosystem)
	if err != nil {
		// No comparator for this ecosystem: fall back to the lowest bound by
		// string order. It is what the query this replaced always did, so this
		// is never worse than before — and never silently better either.
		return lowestFix(adv)
	}

	best := ""
	for _, r := range adv.Ranges {
		if r.Fixed == "" {
			continue
		}
		above, err := compare(r.Fixed, pkg.Version)
		if err != nil || above <= 0 {
			// Unparseable, or at or below what is installed: a bound that is not
			// above the installed version is a different branch's fix.
			continue
		}
		if best == "" {
			best = r.Fixed
			continue
		}
		if lower, err := compare(r.Fixed, best); err == nil && lower < 0 {
			best = r.Fixed
		}
	}
	if best != "" {
		return best
	}

	// Every bound sits at or below the installed version. That happens when the
	// advisory covers a branch this machine has already left, and reporting no
	// fix would be the wrong half of the truth — the lowest bound at least names
	// a version where the fix exists.
	return lowestFix(adv)
}

// lowestFix is the pre-comparator rule: the lowest bound by string order.
func lowestFix(adv Advisory) string {
	if adv.Kind == "malware" {
		return ""
	}
	fix := ""
	for _, r := range adv.Ranges {
		if r.Fixed == "" {
			continue
		}
		if fix == "" || r.Fixed < fix {
			fix = r.Fixed
		}
	}
	return fix
}
