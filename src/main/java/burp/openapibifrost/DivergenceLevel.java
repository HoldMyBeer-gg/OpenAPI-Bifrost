package burp.openapibifrost;

import java.util.List;

/**
 * Classifies the across-identity response pattern for a single endpoint into a short
 * label the UI can colour and the human can eyeball. Identity order in the cells list
 * represents priority ascending — index 0 is the least-privileged identity (e.g.
 * anonymous), last index the most-privileged (e.g. admin).
 */
public enum DivergenceLevel {

    /** Not every cell has completed yet. */
    UNKNOWN,

    /** All network errors; nothing to compare. */
    ALL_ERRORED,

    /** Every identity got a 2xx — endpoint is effectively public (or tiering is broken open). */
    CONSISTENT_ALLOW,

    /** Every identity got denied (4xx/5xx) — consistent rejection. */
    CONSISTENT_DENY,

    /** Allow outcomes form a monotonic suffix — lower-priority identities denied, higher-priority allowed. Healthy. */
    TIERED,

    /** Non-monotonic: a lower-priority identity got a 2xx that a higher-priority did not (or similar). */
    DIVERGENT;

    /**
     * Classifies a row of cells in identity-priority order.
     *
     * @param cells cells for one endpoint, ordered least-privileged first. {@code null}
     *              entries mean "not yet computed" — the row is considered {@link #UNKNOWN}.
     */
    public static DivergenceLevel classify(List<RbacCellResult> cells) {
        if (cells == null || cells.isEmpty()) return UNKNOWN;
        for (RbacCellResult c : cells) {
            if (c == null) return UNKNOWN;
        }

        long errorCount = cells.stream().filter(RbacCellResult::isError).count();
        if (errorCount == cells.size()) return ALL_ERRORED;

        boolean hasAllow = false;
        boolean hasDeny = false;
        boolean monotonic = true;
        boolean seenAllow = false;

        for (RbacCellResult c : cells) {
            if (c.isError()) continue;
            if (c.is2xx()) {
                hasAllow = true;
                seenAllow = true;
            } else {
                hasDeny = true;
                if (seenAllow) monotonic = false;
            }
        }

        if (hasAllow && !hasDeny) return CONSISTENT_ALLOW;
        if (!hasAllow && hasDeny) return CONSISTENT_DENY;
        return monotonic ? TIERED : DIVERGENT;
    }
}
