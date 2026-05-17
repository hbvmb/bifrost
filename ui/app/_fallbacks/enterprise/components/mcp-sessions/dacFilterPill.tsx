// OSS-only fallback. The enterprise build replaces this with a DAC scope
// toggle (own / team / all) that drives the sessions tab listing query. OSS
// has no DAC concept, so this slot is intentionally empty.

export default function DACFilterPill() {
	return null;
}
