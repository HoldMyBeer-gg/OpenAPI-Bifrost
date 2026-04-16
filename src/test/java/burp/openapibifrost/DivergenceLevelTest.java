package burp.openapibifrost;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DivergenceLevelTest {

    private static RbacCellResult ok(int status) { return RbacCellResult.ok(status, 0, 0); }
    private static RbacCellResult err() { return RbacCellResult.error("boom", 0); }

    @Test
    void nullOrEmpty_isUnknown() {
        assertEquals(DivergenceLevel.UNKNOWN, DivergenceLevel.classify(null));
        assertEquals(DivergenceLevel.UNKNOWN, DivergenceLevel.classify(List.of()));
    }

    @Test
    void anyNullCell_isUnknown() {
        assertEquals(DivergenceLevel.UNKNOWN,
                DivergenceLevel.classify(Arrays.asList(ok(200), null, ok(403))));
    }

    @Test
    void allErrors_isAllErrored() {
        assertEquals(DivergenceLevel.ALL_ERRORED,
                DivergenceLevel.classify(List.of(err(), err(), err())));
    }

    @Test
    void allAllowed_isConsistentAllow() {
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(List.of(ok(200), ok(204), ok(201))));
    }

    @Test
    void allDenied_isConsistentDeny() {
        assertEquals(DivergenceLevel.CONSISTENT_DENY,
                DivergenceLevel.classify(List.of(ok(401), ok(403), ok(403))));
    }

    @Test
    void monotonicSuffixAllow_isTiered() {
        // Low-priority denied, higher ones allowed — healthy role enforcement.
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(401), ok(403), ok(200))));
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(401), ok(200), ok(200))));
    }

    @Test
    void allowThenDeny_isDivergent() {
        // Low-priority got in, high-priority was denied — inversion.
        assertEquals(DivergenceLevel.DIVERGENT,
                DivergenceLevel.classify(List.of(ok(200), ok(403), ok(403))));
    }

    @Test
    void allowDenyAllow_isDivergent() {
        assertEquals(DivergenceLevel.DIVERGENT,
                DivergenceLevel.classify(List.of(ok(200), ok(401), ok(200))));
    }

    @Test
    void errorsInMiddle_skippedDuringClassification() {
        // One identity errored out; the remaining two show healthy tiering.
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(401), err(), ok(200))));
    }

    @Test
    void errorsMixedWithAllAllowed_stillConsistentAllow() {
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(List.of(ok(200), err(), ok(200))));
    }

    @Test
    void singleAllowed_isConsistentAllow() {
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(List.of(ok(200))));
    }

    @Test
    void singleDenied_isConsistentDeny() {
        assertEquals(DivergenceLevel.CONSISTENT_DENY,
                DivergenceLevel.classify(List.of(ok(403))));
    }

    @Test
    void singleError_isAllErrored() {
        assertEquals(DivergenceLevel.ALL_ERRORED,
                DivergenceLevel.classify(List.of(err())));
    }
}
