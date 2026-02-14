package burp.bopenapi;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link EndpointTableModel}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class EndpointTableModelTest {

    private EndpointTableModel model;
    private List<ApiEndpoint> endpoints;

    @BeforeEach
    void setUp() {
        model = new EndpointTableModel();
        endpoints = List.of(
                new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "List"),
                new ApiEndpoint(2, "https", "POST", "https://api.test.com", "/users", List.of(), "Create")
        );
    }

    @Test
    void setEndpoints_updatesTable() {
        model.setEndpoints(endpoints);
        assertEquals(2, model.getRowCount());
        assertEquals(7, model.getColumnCount());
        assertEquals("#", model.getColumnName(0));
        assertEquals("GET", model.getValueAt(0, 2));
    }

    @Test
    void setEndpoints_null_clearsTable() {
        model.setEndpoints(endpoints);
        model.setEndpoints(null);
        assertEquals(0, model.getRowCount());
    }

    @Test
    void setFilter_matching_reducesRows() {
        model.setEndpoints(endpoints);
        model.setFilter("POST");
        assertEquals(1, model.getFilterHitCount());
        assertEquals("POST", model.getValueAt(0, 2));
    }

    @Test
    void setFilter_invalidRegex_ignored() {
        model.setEndpoints(endpoints);
        model.setFilter("[invalid");
        assertEquals(2, model.getFilterHitCount());
    }

    @Test
    void getEndpointAt_validIndex_returnsEndpoint() {
        model.setEndpoints(endpoints);
        var ep = model.getEndpointAt(0);
        assertNotNull(ep);
        assertEquals("/users", ep.getPath());
    }

    @Test
    void getEndpointAt_invalidIndex_returnsNull() {
        model.setEndpoints(endpoints);
        assertNull(model.getEndpointAt(-1));
        assertNull(model.getEndpointAt(99));
    }

    @Test
    void getSelectedEndpoints_returnsList() {
        model.setEndpoints(endpoints);
        var selected = model.getSelectedEndpoints(new int[]{0, 1});
        assertEquals(2, selected.size());
    }
}
