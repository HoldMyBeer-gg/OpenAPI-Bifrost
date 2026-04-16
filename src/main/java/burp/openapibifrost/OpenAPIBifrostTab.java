package burp.openapibifrost;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Main OpenAPI-Bifrost tab panel. Provides the UI for loading OpenAPI specs, viewing parsed
 * endpoints, and sending requests to Scanner, Repeater, or Intruder.
 * <p>
 * Supports loading specs via drag-and-drop, URL, file path (including network drives),
 * or raw paste. Includes base URL override, regex filtering, and request preview.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class OpenAPIBifrostTab extends JPanel {

    private final MontoyaApi api;
    private final Logging logging;
    private final OpenAPIParser parser = new OpenAPIParser();
    private final RequestGenerator requestGenerator = new RequestGenerator();
    private final EndpointTableModel tableModel = new EndpointTableModel();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final IdentityStore identityStore;

    private JTextField urlOrPathField;
    private JTextArea rawSpecArea;
    private JTextField baseUrlOverrideField;
    private JTextField bearerField;
    private JTextField apiKeyValueField;
    private JTextField apiKeyNameField;
    private JComboBox<AuthConfig.ApiKeyLocation> apiKeyLocationCombo;
    private JTextField basicUserField;
    private JPasswordField basicPassField;
    private JTextArea extraHeadersArea;
    private JComboBox<String> identityDropdown;
    private JTextField filterField;
    private JLabel filterHitsLabel;
    private JTable endpointTable;
    private HttpRequestEditor requestEditor;
    private JLabel statusLabel;
    private JLabel specAuthSummaryLabel;
    private String defaultServer = "";
    private boolean hasScanner = false;
    /** Suppresses capture-on-change when we're programmatically loading fields. */
    private boolean suppressCapture = false;

    public OpenAPIBifrostTab(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.hasScanner = detectScannerSupport(api);
        this.identityStore = new IdentityStore(new MontoyaPrefsBackend(api.persistence().preferences()));
        buildUi();
        loadActiveIdentityIntoFields();
    }

    /** Test-only constructor that takes an explicit IdentityStore (skips Montoya wiring). */
    OpenAPIBifrostTab(MontoyaApi api, IdentityStore identityStore) {
        this.api = api;
        this.logging = api.logging();
        this.hasScanner = detectScannerSupport(api);
        this.identityStore = identityStore;
        buildUi();
        loadActiveIdentityIntoFields();
    }

    private static boolean detectScannerSupport(MontoyaApi api) {
        try {
            BurpSuiteEdition edition = api.burpSuite().version().edition();
            return edition == BurpSuiteEdition.PROFESSIONAL || edition == BurpSuiteEdition.ENTERPRISE_EDITION;
        } catch (Exception e) {
            return false;
        }
    }

    private void buildUi() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new GridBagLayout());

        // Drop zone spans the full width.
        JPanel dropZone = new JPanel(new GridBagLayout());
        dropZone.setPreferredSize(new Dimension(0, 70));
        dropZone.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(UIManager.getColor("Component.borderColor"), 2),
                new EmptyBorder(8, 10, 8, 10)
        ));
        dropZone.setBackground(UIManager.getColor("Panel.background"));
        JLabel dropLabel = new JLabel("Drop OpenAPI spec here, paste URL/path below, or paste raw JSON/YAML");
        dropZone.add(dropLabel);
        setupDropTarget(dropZone);

        GridBagConstraints full = rowConstraints(0);
        full.gridwidth = GridBagConstraints.REMAINDER;
        full.fill = GridBagConstraints.HORIZONTAL;
        full.weightx = 1.0;
        full.insets = new Insets(0, 0, 8, 0);
        topPanel.add(dropZone, full);

        // Parse-from row: label + field + Browse + Load.
        urlOrPathField = new JTextField();
        JButton browseBtn = new JButton("Browse");
        browseBtn.addActionListener(e -> doBrowse());
        JButton loadBtn = new JButton("Load");
        loadBtn.addActionListener(e -> doLoad());
        addFormRow(topPanel, 1, "Parse from local file or URL:", urlOrPathField, browseBtn, loadBtn);

        // Base URL override row.
        baseUrlOverrideField = new JTextField();
        baseUrlOverrideField.setToolTipText("Override server URL from spec (e.g. https://api.target.com). Stored per identity.");
        baseUrlOverrideField.addFocusListener(new FocusAdapter() {
            @Override public void focusLost(FocusEvent e) {
                captureActiveIdentity();
                updateRequestPreview();
            }
        });
        addFormRow(topPanel, 2, "Base URL override (optional):", baseUrlOverrideField);

        // Auth panel — full width, already grid-aligned internally.
        GridBagConstraints authC = rowConstraints(3);
        authC.gridwidth = GridBagConstraints.REMAINDER;
        authC.fill = GridBagConstraints.HORIZONTAL;
        authC.weightx = 1.0;
        authC.insets = new Insets(6, 0, 6, 0);
        topPanel.add(buildAuthPanel(), authC);

        // Raw spec paste area.
        rawSpecArea = new JTextArea(6, 60);
        rawSpecArea.setLineWrap(true);
        rawSpecArea.setFont(UIManager.getFont("TextArea.font"));
        JScrollPane rawSpecScroll = new JScrollPane(rawSpecArea);
        rawSpecScroll.setBorder(new LineBorder(UIManager.getColor("Component.borderColor"), 1));
        JButton parseRawBtn = new JButton("Parse");
        parseRawBtn.addActionListener(e -> {
            String content = rawSpecArea.getText();
            if (content != null && !content.isBlank()) {
                setStatus("Parsing...");
                parseInBackground(content.trim(), "pasted");
            } else {
                setStatus("Paste OpenAPI spec content (JSON or YAML) above, then click Parse.");
            }
        });

        // "Or paste raw OpenAPI spec (JSON/YAML):" label row.
        GridBagConstraints pasteLabelC = rowConstraints(4);
        pasteLabelC.gridwidth = GridBagConstraints.REMAINDER;
        pasteLabelC.anchor = GridBagConstraints.WEST;
        pasteLabelC.fill = GridBagConstraints.HORIZONTAL;
        pasteLabelC.insets = new Insets(4, 0, 2, 0);
        topPanel.add(new JLabel("Or paste raw OpenAPI spec (JSON/YAML):"), pasteLabelC);

        // Textarea row — full width, fills vertically to take remaining space.
        GridBagConstraints textareaC = rowConstraints(5);
        textareaC.gridwidth = GridBagConstraints.REMAINDER;
        textareaC.fill = GridBagConstraints.BOTH;
        textareaC.weightx = 1.0;
        textareaC.weighty = 1.0;
        textareaC.insets = new Insets(0, 0, 4, 0);
        topPanel.add(rawSpecScroll, textareaC);

        // Parse button aligned under the textarea.
        GridBagConstraints btnC = rowConstraints(6);
        btnC.gridwidth = GridBagConstraints.REMAINDER;
        btnC.anchor = GridBagConstraints.WEST;
        btnC.fill = GridBagConstraints.NONE;
        btnC.insets = new Insets(0, 0, 0, 0);
        topPanel.add(parseRawBtn, btnC);

        JScrollPane topScroll = new JScrollPane(topPanel);
        topScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        topScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        topScroll.setBorder(BorderFactory.createEmptyBorder());
        topScroll.getViewport().setPreferredSize(new Dimension(0, 460));
        add(topScroll, BorderLayout.NORTH);

        // Filter row and table/editor
        JPanel centerPanel = new JPanel(new BorderLayout(0, 5));
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        filterRow.add(new JLabel("Filter (regex, case-sensitive):"));
        filterField = new JTextField(25);
        filterField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                tableModel.setFilter(filterField.getText());
                updateFilterHits();
            }
        });
        filterRow.add(filterField);
        filterHitsLabel = new JLabel("0 hits");
        filterRow.add(filterHitsLabel);
        centerPanel.add(filterRow, BorderLayout.NORTH);

        // Table and request preview
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        endpointTable = new JTable(tableModel);
        endpointTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        endpointTable.setAutoCreateRowSorter(true);
        endpointTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateRequestPreview();
        });
        setupContextMenu();
        setupKeyBinding();
        JScrollPane tableScroll = new JScrollPane(endpointTable);
        split.setTopComponent(tableScroll);

        requestEditor = api.userInterface().createHttpRequestEditor();
        split.setBottomComponent(requestEditor.uiComponent());
        split.setResizeWeight(0.6);
        centerPanel.add(split, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);

        statusLabel = new JLabel(" ");
        add(statusLabel, BorderLayout.SOUTH);
    }

    private void setupDropTarget(JComponent dropZone) {
        dropZone.setDropTarget(new DropTarget() {
            @Override
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    @SuppressWarnings("unchecked")
                    java.util.List<java.io.File> files = (java.util.List<java.io.File>)
                            evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (files != null && !files.isEmpty()) {
                        java.io.File f = files.get(0);
                        if (f.isFile()) {
                            urlOrPathField.setText(f.getAbsolutePath());
                            doLoad();
                        }
                    }
                    evt.dropComplete(true);
                } catch (Exception ex) {
                    logging.logToError("Drop failed: " + ex.getMessage());
                    evt.dropComplete(false);
                }
            }
        });
    }

    private void doBrowse() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setDialogTitle("Select OpenAPI spec (JSON, YAML, TXT)");
        java.awt.Frame parent = api.userInterface().swingUtils().suiteFrame();
        if (chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
            urlOrPathField.setText(chooser.getSelectedFile().getAbsolutePath());
            doLoad();
        }
    }

    private void doLoad() {
        String input = urlOrPathField.getText();
        String rawContent = rawSpecArea != null ? rawSpecArea.getText() : null;
        if ((input == null || input.isBlank()) && (rawContent == null || rawContent.isBlank())) {
            setStatus("Enter a URL or file path, paste raw spec below, or drag & drop a file.");
            return;
        }
        if (input == null || input.isBlank()) {
            setStatus("Parsing...");
            parseInBackground(rawContent.trim(), "pasted");
            return;
        }
        final String source = input.trim();
        setStatus("Loading...");

        if (looksLikeUrl(source)) {
            executor.submit(() -> {
                try {
                    loadFromUrl(source);
                } catch (Throwable t) {
                    logging.logToError("Load from URL failed: " + t.getMessage());
                    java.io.StringWriter sw = new java.io.StringWriter();
                    t.printStackTrace(new java.io.PrintWriter(sw));
                    logging.logToError(sw.toString());
                    SwingUtilities.invokeLater(() -> setStatus("Load failed: " + t.getMessage()));
                }
            });
        } else {
            executor.submit(() -> {
                try {
                    loadFromFile(source);
                } catch (Throwable t) {
                    logging.logToError("Load from file failed: " + t.getMessage());
                    java.io.StringWriter sw = new java.io.StringWriter();
                    t.printStackTrace(new java.io.PrintWriter(sw));
                    logging.logToError(sw.toString());
                    SwingUtilities.invokeLater(() -> setStatus("Load failed: " + t.getMessage()));
                }
            });
        }
    }

    private boolean looksLikeUrl(String s) {
        return s.startsWith("http://") || s.startsWith("https://");
    }

    private void loadFromUrl(String url) {
        try {
            HttpRequest req = applyAuthToFetch(HttpRequest.httpRequestFromUrl(url), getAuthConfig());
            var response = api.http().sendRequest(req);
            var httpResponse = response.response();
            if (httpResponse == null) throw new IOException("No response");
            short status = httpResponse.statusCode();
            if (status < 200 || status >= 300) {
                String msg = "Spec fetch returned HTTP " + status
                        + (status == 401 || status == 403 ? " — check your auth / Extra Headers" : "");
                logging.logToError(msg);
                SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError(msg));
                return;
            }
            byte[] body = httpResponse.body().getBytes();
            String content = new String(body, StandardCharsets.UTF_8);
            parseInBackground(content, url);
        } catch (Exception e) {
            logging.logToError("Failed to load URL: " + e.getMessage());
            SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError("Unable to load from URL: " + e.getMessage()));
        }
    }

    /**
     * Applies the active AuthConfig to an HttpRequest used for fetching the spec itself.
     * Mirrors RequestGenerator's header-injection logic but targets a Montoya HttpRequest
     * rather than raw bytes.
     */
    private HttpRequest applyAuthToFetch(HttpRequest req, AuthConfig auth) {
        if (auth == null || auth.isEmpty()) return req;
        if (auth.hasBearer()) {
            req = req.withAddedHeader("Authorization", "Bearer " + auth.bearerToken());
        }
        if (auth.hasBasic()) {
            req = req.withAddedHeader("Authorization", auth.basicAuthorizationHeaderValue());
        }
        if (auth.hasApiKey()) {
            switch (auth.apiKeyLocation()) {
                case HEADER:
                    req = req.withAddedHeader(auth.apiKeyName(), auth.apiKeyValue());
                    break;
                case COOKIE:
                    req = req.withAddedHeader("Cookie", auth.apiKeyName() + "=" + auth.apiKeyValue());
                    break;
                case QUERY:
                    // Query-string API keys are endpoint-specific; not applied to the spec fetch.
                    break;
            }
        }
        for (AuthConfig.HeaderPair h : auth.extraHeaders()) {
            req = req.withAddedHeader(h.name(), h.value());
        }
        return req;
    }

    private void fallbackToRawPasteOrSetError(String errorMsg) {
        String raw = rawSpecArea != null ? rawSpecArea.getText() : null;
        if (raw != null && !raw.isBlank()) {
            setStatus("File/URL failed. Parsing pasted content instead...");
            parseInBackground(raw.trim(), "pasted");
        } else {
            setStatus(errorMsg);
        }
    }

    private void loadFromFile(String pathStr) {
        try {
            Path path = Paths.get(pathStr);
            if (!Files.exists(path) || !Files.isRegularFile(path)) {
                SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError("File not found: " + pathStr));
                return;
            }
            byte[] bytes = Files.readAllBytes(path);
            String content = new String(bytes, StandardCharsets.UTF_8);
            parseInBackground(content, pathStr);
        } catch (Exception e) {
            logging.logToError("Failed to load file: " + e.getMessage());
            SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError("Unable to read file: " + e.getMessage()));
        }
    }

    /**
     * Parses spec content in a background thread to keep the UI responsive (BApp Store
     * criterion: use threads for slow operations). Updates the UI on the EDT when done.
     */
    private void parseInBackground(String content, String source) {
        executor.submit(() -> {
            try {
                OpenAPIParser.ParseResult result = parser.parse(source, content);
                SwingUtilities.invokeLater(() -> applyParseResult(result, source));
            } catch (Throwable t) {
                logging.logToError("Parse failed: " + t.getMessage());
                java.io.StringWriter sw = new java.io.StringWriter();
                t.printStackTrace(new java.io.PrintWriter(sw));
                logging.logToError(sw.toString());
                SwingUtilities.invokeLater(() -> setStatus("Parse failed: " + t.getMessage()));
            }
        });
    }

    private void applyParseResult(OpenAPIParser.ParseResult result, String source) {
        tableModel.setEndpoints(result.getEndpoints());
        defaultServer = result.getDefaultServer();
        String existingOverride = baseUrlOverrideField.getText();
        if (!defaultServer.isEmpty() && (existingOverride == null || existingOverride.isBlank())) {
            baseUrlOverrideField.setText(defaultServer);
        }
        applySpecSecuritySchemes(result.getSecuritySchemes());
        tableModel.setFilter(filterField.getText());
        updateFilterHits();
        updateRequestPreview();
        captureActiveIdentity();

        if (!result.getMessages().isEmpty()) {
            for (String m : result.getMessages()) {
                logging.logToOutput("OpenAPI parse: " + m);
            }
        }
        if (result.getEndpoints().isEmpty()) {
            String errMsg = result.getMessages().isEmpty()
                    ? "No endpoints parsed. Check spec format."
                    : "Parse failed: " + result.getMessages().get(0);
            if (result.getMessages().size() > 1) {
                errMsg += " (see extension log for more)";
            }
            setStatus(errMsg);
        } else {
            setStatus("Loaded " + result.getEndpoints().size() + " endpoints from " + source);
        }
    }

    private void updateFilterHits() {
        filterHitsLabel.setText(tableModel.getFilterHitCount() + " hits");
    }

    private void updateRequestPreview() {
        int viewRow = endpointTable.getSelectedRow();
        if (viewRow >= 0) {
            int modelRow = endpointTable.convertRowIndexToModel(viewRow);
            ApiEndpoint ep = tableModel.getEndpointAt(modelRow);
            if (ep != null) {
                HttpRequest req = requestGenerator.buildRequest(ep, getBaseUrlOverride(), getAuthConfig());
                requestEditor.setRequest(req);
            }
        } else {
            requestEditor.setRequest(null);
        }
    }

    /** Returns selected rows translated from view indices (possibly sorted) to model indices. */
    private int[] selectedModelRows() {
        int[] viewRows = endpointTable.getSelectedRows();
        int[] modelRows = new int[viewRows.length];
        for (int i = 0; i < viewRows.length; i++) {
            modelRows[i] = endpointTable.convertRowIndexToModel(viewRows[i]);
        }
        return modelRows;
    }

    private String getBaseUrlOverride() {
        String s = baseUrlOverrideField.getText();
        return (s != null && !s.isBlank()) ? s.trim() : null;
    }

    private JPanel buildAuthPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Authentication (applied to active identity)"));

        // Row 0: Identity dropdown + action buttons.
        identityDropdown = new JComboBox<>();
        identityDropdown.setToolTipText("Switch between named auth configurations. Each stores its own bearer/API key/basic/cookies.");
        refreshIdentityDropdown();
        identityDropdown.addActionListener(e -> {
            if (suppressCapture) return;
            int selected = identityDropdown.getSelectedIndex();
            if (selected < 0 || selected == identityStore.activeIndex()) return;
            captureActiveIdentity();
            identityStore.setActive(selected);
            loadActiveIdentityIntoFields();
        });

        JButton newBtn = new JButton("New…");
        newBtn.addActionListener(e -> doNewIdentity());
        JButton renameBtn = new JButton("Rename…");
        renameBtn.addActionListener(e -> doRenameIdentity());
        JButton deleteBtn = new JButton("Delete");
        deleteBtn.addActionListener(e -> doDeleteIdentity());
        addFormRow(panel, 0, "Identity:", identityDropdown, newBtn, renameBtn, deleteBtn);

        // Row 1: spec-auth summary (dimmed). Aligns under the field column so it reads as metadata
        // for the identity, not as a separate section.
        specAuthSummaryLabel = new JLabel(" ");
        specAuthSummaryLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        GridBagConstraints summaryC = rowConstraints(1);
        summaryC.gridx = 1;
        summaryC.gridwidth = GridBagConstraints.REMAINDER;
        summaryC.fill = GridBagConstraints.HORIZONTAL;
        summaryC.weightx = 1.0;
        summaryC.insets = new Insets(0, 6, 4, 0);
        panel.add(specAuthSummaryLabel, summaryC);

        // Row 2: Bearer token.
        bearerField = new JTextField();
        bearerField.setToolTipText("Whitespace/newlines stripped automatically. Sent as 'Authorization: Bearer <token>'.");
        addFormRow(panel, 2, "Bearer token:", bearerField);

        // Row 3: API key — value + name + location on one row using a sub-grid so they align.
        JPanel apiKeySubrow = new JPanel(new GridBagLayout());
        GridBagConstraints s = new GridBagConstraints();
        s.gridy = 0;
        s.insets = new Insets(0, 0, 0, 6);
        s.fill = GridBagConstraints.HORIZONTAL;

        apiKeyValueField = new JTextField();
        s.gridx = 0; s.weightx = 0.55; apiKeySubrow.add(apiKeyValueField, s);

        s.weightx = 0;
        s.gridx = 1; apiKeySubrow.add(new JLabel("name:"), s);
        apiKeyNameField = new JTextField("X-API-Key", 14);
        s.gridx = 2; s.weightx = 0.35; apiKeySubrow.add(apiKeyNameField, s);

        s.weightx = 0;
        s.gridx = 3; apiKeySubrow.add(new JLabel("in:"), s);
        apiKeyLocationCombo = new JComboBox<>(AuthConfig.ApiKeyLocation.values());
        s.gridx = 4; s.insets = new Insets(0, 0, 0, 0); apiKeySubrow.add(apiKeyLocationCombo, s);

        addFormRow(panel, 3, "API key:", apiKeySubrow);

        // Row 4: Basic auth — user + pass on one row with a sub-grid.
        JPanel basicSubrow = new JPanel(new GridBagLayout());
        GridBagConstraints b = new GridBagConstraints();
        b.gridy = 0;
        b.insets = new Insets(0, 0, 0, 6);
        b.fill = GridBagConstraints.HORIZONTAL;

        basicUserField = new JTextField();
        b.gridx = 0; b.weightx = 0.5; basicSubrow.add(basicUserField, b);

        b.weightx = 0;
        b.gridx = 1; basicSubrow.add(new JLabel("pass:"), b);
        basicPassField = new JPasswordField();
        b.gridx = 2; b.weightx = 0.5; b.insets = new Insets(0, 0, 0, 0); basicSubrow.add(basicPassField, b);

        addFormRow(panel, 4, "Basic auth — user:", basicSubrow);

        // Row 5: Extra headers — label across 2 rows: short inline description, then textarea full width.
        extraHeadersArea = new JTextArea(3, 60);
        extraHeadersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        extraHeadersArea.setToolTipText("Example: X-Tenant: acme  (or paste 'Cookie: session=...' for session-based APIs)");
        JScrollPane headersScroll = new JScrollPane(extraHeadersArea);
        headersScroll.setBorder(new LineBorder(UIManager.getColor("Component.borderColor"), 1));

        GridBagConstraints headersLabelC = rowConstraints(5);
        headersLabelC.gridx = 0;
        headersLabelC.anchor = GridBagConstraints.NORTHEAST;
        headersLabelC.insets = new Insets(6, 0, 0, 6);
        panel.add(new JLabel("Extra headers:"), headersLabelC);

        GridBagConstraints headersFieldC = rowConstraints(5);
        headersFieldC.gridx = 1;
        headersFieldC.gridwidth = GridBagConstraints.REMAINDER;
        headersFieldC.fill = GridBagConstraints.HORIZONTAL;
        headersFieldC.weightx = 1.0;
        headersFieldC.insets = new Insets(4, 0, 2, 0);
        panel.add(headersScroll, headersFieldC);

        GridBagConstraints headersHintC = rowConstraints(6);
        headersHintC.gridx = 1;
        headersHintC.gridwidth = GridBagConstraints.REMAINDER;
        headersHintC.fill = GridBagConstraints.HORIZONTAL;
        headersHintC.weightx = 1.0;
        headersHintC.insets = new Insets(0, 0, 2, 0);
        JLabel hint = new JLabel("One per line, 'Name: Value'. Overrides auth fields on collision.");
        hint.setForeground(UIManager.getColor("Label.disabledForeground"));
        panel.add(hint, headersHintC);

        // Wire field listeners for capture + preview refresh.
        ActionListener captureAndRefresh = e -> {
            captureActiveIdentity();
            updateRequestPreview();
        };
        bearerField.addActionListener(captureAndRefresh);
        apiKeyValueField.addActionListener(captureAndRefresh);
        apiKeyNameField.addActionListener(captureAndRefresh);
        apiKeyLocationCombo.addActionListener(captureAndRefresh);
        basicUserField.addActionListener(captureAndRefresh);
        basicPassField.addActionListener(captureAndRefresh);

        FocusAdapter captureOnBlur = new FocusAdapter() {
            @Override public void focusLost(FocusEvent e) {
                captureActiveIdentity();
                updateRequestPreview();
            }
        };
        bearerField.addFocusListener(captureOnBlur);
        apiKeyValueField.addFocusListener(captureOnBlur);
        apiKeyNameField.addFocusListener(captureOnBlur);
        basicUserField.addFocusListener(captureOnBlur);
        basicPassField.addFocusListener(captureOnBlur);
        extraHeadersArea.addFocusListener(captureOnBlur);

        return panel;
    }

    /** GridBagConstraints preset for a standard form row. */
    private static GridBagConstraints rowConstraints(int gridy) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = gridy;
        c.insets = new Insets(3, 0, 3, 6);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    /**
     * Adds a label-in-column-0 + components-in-column-1+ row to a GridBagLayout container.
     * The first trailing component gets weightx=1.0 so it absorbs horizontal resize; later
     * trailing components (e.g. buttons) hug the right side at their preferred width.
     */
    private static void addFormRow(JPanel container, int gridy, String labelText, java.awt.Component... fields) {
        GridBagConstraints labelC = rowConstraints(gridy);
        labelC.gridx = 0;
        labelC.anchor = GridBagConstraints.EAST;
        JLabel lbl = new JLabel(labelText);
        container.add(lbl, labelC);

        for (int i = 0; i < fields.length; i++) {
            GridBagConstraints fc = rowConstraints(gridy);
            fc.gridx = i + 1;
            if (i == 0) {
                fc.fill = GridBagConstraints.HORIZONTAL;
                fc.weightx = 1.0;
            } else {
                fc.fill = GridBagConstraints.NONE;
                fc.weightx = 0;
            }
            if (i == fields.length - 1) {
                fc.gridwidth = GridBagConstraints.REMAINDER;
                fc.insets = new Insets(3, 0, 3, 0);
            }
            container.add(fields[i], fc);
        }
    }

    private void refreshIdentityDropdown() {
        boolean prevSuppress = suppressCapture;
        suppressCapture = true;
        try {
            identityDropdown.removeAllItems();
            for (Identity id : identityStore.identities()) {
                identityDropdown.addItem(id.name());
            }
            identityDropdown.setSelectedIndex(identityStore.activeIndex());
        } finally {
            suppressCapture = prevSuppress;
        }
    }

    /** Writes the active identity's stored values into the auth form fields. */
    void loadActiveIdentityIntoFields() {
        boolean prevSuppress = suppressCapture;
        suppressCapture = true;
        try {
            Identity active = identityStore.active();
            AuthConfig cfg = active.authConfig();
            bearerField.setText(cfg.bearerToken());
            apiKeyValueField.setText(cfg.apiKeyValue());
            apiKeyNameField.setText(cfg.apiKeyName().isEmpty() ? "X-API-Key" : cfg.apiKeyName());
            apiKeyLocationCombo.setSelectedItem(cfg.apiKeyLocation());
            basicUserField.setText(cfg.basicUser());
            basicPassField.setText(cfg.basicPass());
            StringBuilder sb = new StringBuilder();
            for (AuthConfig.HeaderPair h : cfg.extraHeaders()) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(h.name()).append(": ").append(h.value());
            }
            extraHeadersArea.setText(sb.toString());
            if (!active.baseUrlOverride().isEmpty()) {
                baseUrlOverrideField.setText(active.baseUrlOverride());
            }
        } finally {
            suppressCapture = prevSuppress;
        }
        updateRequestPreview();
    }

    /** Snapshots the current auth fields into the active identity and persists. */
    void captureActiveIdentity() {
        if (suppressCapture) return;
        Identity current = identityStore.active();
        Identity snapshot = new Identity(current.name(), getAuthConfig(), getBaseUrlOverride() != null ? getBaseUrlOverride() : "");
        identityStore.replaceActive(snapshot);
    }

    private void doNewIdentity() {
        String name = (String) JOptionPane.showInputDialog(
                this, "Name for new identity:", "New identity",
                JOptionPane.PLAIN_MESSAGE, null, null, "identity-" + (identityStore.size() + 1));
        if (name == null || name.isBlank()) return;
        try {
            captureActiveIdentity();
            identityStore.add(Identity.empty(name.trim()));
            refreshIdentityDropdown();
            loadActiveIdentityIntoFields();
            setStatus("Added identity '" + name.trim() + "'. Fill in its auth fields.");
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Cannot add identity", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void doRenameIdentity() {
        Identity current = identityStore.active();
        String name = (String) JOptionPane.showInputDialog(
                this, "New name for '" + current.name() + "':", "Rename identity",
                JOptionPane.PLAIN_MESSAGE, null, null, current.name());
        if (name == null || name.isBlank() || name.equals(current.name())) return;
        try {
            identityStore.rename(identityStore.activeIndex(), name.trim());
            refreshIdentityDropdown();
            setStatus("Renamed to '" + name.trim() + "'.");
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Cannot rename", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void doDeleteIdentity() {
        if (identityStore.size() <= 1) {
            JOptionPane.showMessageDialog(this, "At least one identity must exist.",
                    "Cannot delete", JOptionPane.WARNING_MESSAGE);
            return;
        }
        Identity current = identityStore.active();
        int choice = JOptionPane.showConfirmDialog(this,
                "Delete identity '" + current.name() + "'? This cannot be undone.",
                "Delete identity", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) return;
        identityStore.remove(identityStore.activeIndex());
        refreshIdentityDropdown();
        loadActiveIdentityIntoFields();
        setStatus("Deleted identity '" + current.name() + "'.");
    }

    /**
     * Updates the spec-auth summary label and pre-fills the API key fields when the spec
     * declares exactly one API-key scheme. Only fills fields that are currently empty —
     * never clobbers user-entered values.
     */
    void applySpecSecuritySchemes(List<SecuritySchemeInfo> schemes) {
        if (schemes == null || schemes.isEmpty()) {
            specAuthSummaryLabel.setText("Spec declares no auth schemes.");
            return;
        }
        StringBuilder summary = new StringBuilder("Spec declares: ");
        for (int i = 0; i < schemes.size(); i++) {
            if (i > 0) summary.append(", ");
            summary.append(schemes.get(i).displayName());
        }
        specAuthSummaryLabel.setText(summary.toString());

        // If exactly one apiKey scheme, pre-fill the apiKey name + location when the value is empty.
        SecuritySchemeInfo singleApiKey = null;
        for (SecuritySchemeInfo s : schemes) {
            if (s.type() == SecuritySchemeInfo.SchemeType.API_KEY) {
                if (singleApiKey != null) { singleApiKey = null; break; }
                singleApiKey = s;
            }
        }
        if (singleApiKey != null && apiKeyValueField.getText().isBlank()) {
            if (singleApiKey.apiKeyName() != null && !singleApiKey.apiKeyName().isBlank()) {
                apiKeyNameField.setText(singleApiKey.apiKeyName());
            }
            String loc = singleApiKey.apiKeyLocation();
            if ("query".equalsIgnoreCase(loc)) {
                apiKeyLocationCombo.setSelectedItem(AuthConfig.ApiKeyLocation.QUERY);
            } else if ("cookie".equalsIgnoreCase(loc)) {
                apiKeyLocationCombo.setSelectedItem(AuthConfig.ApiKeyLocation.COOKIE);
            } else {
                apiKeyLocationCombo.setSelectedItem(AuthConfig.ApiKeyLocation.HEADER);
            }
        }
    }

    private AuthConfig getAuthConfig() {
        return new AuthConfig(
                bearerField.getText(),
                apiKeyValueField.getText(),
                apiKeyNameField.getText(),
                (AuthConfig.ApiKeyLocation) apiKeyLocationCombo.getSelectedItem(),
                basicUserField.getText(),
                new String(basicPassField.getPassword()),
                AuthConfig.parseExtraHeaders(extraHeadersArea.getText())
        );
    }

    /**
     * Populates the auth panel from a Burp HTTP request, and — when possible — auto-detects
     * the OpenAPI spec source from the request's response body or URL path. Invoked from
     * the "Send to OpenAPI-Bifrost" context menu. Runs on the EDT.
     */
    public void importFromRequest(HttpRequestResponse rr) {
        SwingUtilities.invokeLater(() -> applyImport(rr));
    }

    private void applyImport(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null) {
            setStatus("No request to import.");
            return;
        }
        HttpRequest req = rr.request();
        List<String> rawLines = new ArrayList<>();
        for (HttpHeader h : req.headers()) {
            rawLines.add(h.name() + ": " + h.value());
        }
        HeaderClassifier.Extracted ex = HeaderClassifier.fromRawHeaderLines(rawLines);

        bearerField.setText(ex.bearerToken() != null ? ex.bearerToken() : "");
        basicUserField.setText(ex.basicUser() != null ? ex.basicUser() : "");
        basicPassField.setText(ex.basicPass() != null ? ex.basicPass() : "");
        if (ex.apiKeyValue() != null) {
            apiKeyNameField.setText(ex.apiKeyName());
            apiKeyValueField.setText(ex.apiKeyValue());
            apiKeyLocationCombo.setSelectedItem(AuthConfig.ApiKeyLocation.HEADER);
        } else {
            apiKeyValueField.setText("");
        }
        StringBuilder extras = new StringBuilder();
        for (AuthConfig.HeaderPair h : ex.extraHeaders()) {
            if (extras.length() > 0) extras.append("\n");
            extras.append(h.name()).append(": ").append(h.value());
        }
        extraHeadersArea.setText(extras.toString());

        String baseUrl = deriveBaseUrl(req);
        if (baseUrl != null) {
            baseUrlOverrideField.setText(baseUrl);
            logging.logToOutput("Imported base URL: " + baseUrl);
        } else {
            logging.logToOutput("Could not derive base URL — req.httpService() was null. URL: " + safeUrl(req));
        }

        String fullUrl = safeUrl(req);
        HttpResponse response = rr.response();
        String body = response != null ? response.bodyToString() : null;
        boolean haveSpecBody = HeaderClassifier.looksLikeSpecBody(body);
        boolean looksLikeSpecPath = HeaderClassifier.isSpecUrlPath(req.path()) && fullUrl != null;

        if (haveSpecBody || looksLikeSpecPath) {
            if (fullUrl != null) urlOrPathField.setText(fullUrl);
            if (haveSpecBody) {
                rawSpecArea.setText(body);
                setStatus("Imported auth + spec body — parsing now...");
                updateRequestPreview();
                captureActiveIdentity();
                parseInBackground(body.trim(), fullUrl != null ? fullUrl : "pasted");
                return;
            }
            setStatus("Imported auth + spec URL — click Load.");
            updateRequestPreview();
            captureActiveIdentity();
            return;
        }

        // No spec detected in the request. Guess the most common spec path on the same host
        // so the user can just click Load instead of typing the URL themselves.
        if (baseUrl != null && urlOrPathField.getText().isBlank()) {
            String guess = baseUrl + "/openapi.json";
            urlOrPathField.setText(guess);
            setStatus("Imported auth. Guessed spec URL " + guess + " — click Load (or edit if your spec lives elsewhere).");
        } else {
            setStatus("Imported auth from request. Load a spec URL or paste a spec to continue.");
        }
        updateRequestPreview();
        captureActiveIdentity();
    }

    private static String safeUrl(HttpRequest req) {
        try {
            return req.url();
        } catch (Exception e) {
            return null;
        }
    }

    /** Builds scheme://host[:port] from a request's HttpService, omitting default ports. */
    private static String deriveBaseUrl(HttpRequest req) {
        try {
            HttpService svc = req.httpService();
            if (svc == null) return null;
            String scheme = svc.secure() ? "https" : "http";
            int port = svc.port();
            boolean defaultPort = (svc.secure() && port == 443) || (!svc.secure() && port == 80);
            return scheme + "://" + svc.host() + (defaultPort ? "" : ":" + port);
        } catch (Exception e) {
            return null;
        }
    }

    private void setupContextMenu() {
        JPopupMenu popup = new JPopupMenu();
        JMenu openapiMenu = new JMenu("OpenAPI-Bifrost");
        JMenuItem scanItem = new JMenuItem("Actively Scan");
        scanItem.setEnabled(hasScanner);
        if (!hasScanner) {
            scanItem.setToolTipText("Requires Burp Suite Professional");
        }
        scanItem.addActionListener(e -> doActivelyScan());
        JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
        repeaterItem.addActionListener(e -> doSendToRepeater());
        JMenuItem intruderItem = new JMenuItem("Send to Intruder");
        intruderItem.addActionListener(e -> doSendToIntruder());
        JMenuItem compareItem = new JMenuItem("Compare across identities...");
        compareItem.addActionListener(e -> doCompareIdentities());
        openapiMenu.add(scanItem);
        openapiMenu.add(repeaterItem);
        openapiMenu.add(intruderItem);
        openapiMenu.addSeparator();
        openapiMenu.add(compareItem);
        popup.add(openapiMenu);

        endpointTable.setComponentPopupMenu(popup);
        endpointTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = endpointTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !endpointTable.isRowSelected(row)) {
                        endpointTable.setRowSelectionInterval(row, row);
                    }
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = endpointTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !endpointTable.isRowSelected(row)) {
                        endpointTable.setRowSelectionInterval(row, row);
                    }
                }
            }
        });
    }

    private void setupKeyBinding() {
        int modifier = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_I, modifier);
        endpointTable.getInputMap(JComponent.WHEN_FOCUSED).put(ks, "SendToIntruder");
        endpointTable.getActionMap().put("SendToIntruder", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                doSendToIntruder();
            }
        });
    }

    private void doActivelyScan() {
        if (!hasScanner) {
            setStatus("Active Scan requires Burp Suite Professional.");
            return;
        }
        int[] rows = selectedModelRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to scan.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        AuthConfig auth = getAuthConfig();
        try {
            int outOfScope = 0;
            String firstOutOfScopeUrl = null;
            for (ApiEndpoint ep : endpoints) {
                HttpRequest probe = requestGenerator.buildRequest(ep, override, auth);
                if (!api.scope().isInScope(probe.url())) {
                    outOfScope++;
                    if (firstOutOfScopeUrl == null) firstOutOfScopeUrl = probe.url();
                }
            }
            if (outOfScope == endpoints.size()) {
                String msg = "All " + outOfScope + " endpoints are out of scope. Scanner silently drops "
                        + "out-of-scope requests. Add target to scope (e.g. " + firstOutOfScopeUrl + ").";
                logging.logToError(msg);
                setStatus(msg);
                return;
            }
            if (outOfScope > 0) {
                logging.logToOutput(outOfScope + "/" + endpoints.size()
                        + " endpoints out of scope — Scanner will skip those.");
            }

            Audit audit = api.scanner().startAudit(
                    AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            logging.logToOutput("startAudit -> " + (audit != null ? audit.getClass().getSimpleName() : "null"));
            int added = 0;
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override, auth);
                audit.addRequest(req);
                added++;
            }
            logging.logToOutput("Added " + added + " requests. Audit status: " + audit.statusMessage());
            setStatus("Audit started: " + added + " requests (" + outOfScope + " skipped as out of scope) — see Dashboard.");
        } catch (Exception ex) {
            logging.logToError("Actively scan failed: " + ex.getMessage());
            java.io.StringWriter sw = new java.io.StringWriter();
            ex.printStackTrace(new java.io.PrintWriter(sw));
            logging.logToError(sw.toString());
            setStatus("Scan failed: " + ex.getMessage());
        }
    }

    private void doSendToRepeater() {
        int[] rows = selectedModelRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to send to Repeater.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        AuthConfig auth = getAuthConfig();
        try {
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override, auth);
                String tabName = ep.getMethod() + " " + ep.getPath();
                if (tabName.length() > 50) tabName = tabName.substring(0, 47) + "...";
                api.repeater().sendToRepeater(req, tabName);
            }
            setStatus("Sent " + endpoints.size() + " endpoints to Repeater. Right-click in Repeater → Scan to scan.");
        } catch (Exception ex) {
            logging.logToError("Send to Repeater failed: " + ex.getMessage());
            setStatus("Repeater failed: " + ex.getMessage());
        }
    }

    private void doSendToIntruder() {
        int[] rows = selectedModelRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to send to Intruder.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        AuthConfig auth = getAuthConfig();
        try {
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override, auth);
                HttpRequestTemplate template = requestGenerator.buildIntruderTemplate(ep, override, auth);
                String tabName = ep.getMethod() + " " + ep.getPath();
                if (tabName.length() > 70) tabName = tabName.substring(0, 67) + "...";
                api.intruder().sendToIntruder(req.httpService(), template, tabName);
            }
            setStatus("Sent " + endpoints.size() + " endpoints to Intruder.");
        } catch (Exception ex) {
            logging.logToError("Send to Intruder failed: " + ex.getMessage());
            setStatus("Intruder failed: " + ex.getMessage());
        }
    }

    private void doCompareIdentities() {
        int[] rows = selectedModelRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to compare.");
            return;
        }
        List<ApiEndpoint> selected = tableModel.getSelectedEndpoints(rows);
        if (identityStore.size() < 2) {
            JOptionPane.showMessageDialog(this,
                    "Create at least two identities (Auth panel → 'New...') to compare access between them.",
                    "Nothing to compare", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Capture the active identity's latest fields before running — otherwise just-typed
        // tokens wouldn't reach the runner.
        captureActiveIdentity();

        List<Identity> picked = pickIdentitiesForCompare();
        if (picked == null || picked.size() < 2) return;

        // Persist the latest state once more in case the picker dialog stole focus.
        captureActiveIdentity();

        RbacHttpSender sender = new MontoyaRbacHttpSender(api.http(), requestGenerator);
        Frame parent = api.userInterface().swingUtils().suiteFrame();
        RbacComparisonDialog dialog = new RbacComparisonDialog(
                parent, api, selected, picked, sender, 6);
        dialog.setVisible(true);
        dialog.startRun();
        setStatus("RBAC comparison started: " + selected.size() + " endpoints × " + picked.size() + " identities.");
    }

    /** Puts a checkbox next to every identity name; returns those the user enabled, in priority order. */
    private List<Identity> pickIdentitiesForCompare() {
        List<Identity> all = identityStore.identities();
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("Run each selected endpoint with each ticked identity. Order (top→bottom) is priority ascending."));
        panel.add(Box.createVerticalStrut(6));
        List<JCheckBox> boxes = new ArrayList<>();
        for (Identity id : all) {
            JCheckBox cb = new JCheckBox(id.name(), true);
            boxes.add(cb);
            panel.add(cb);
        }
        int choice = JOptionPane.showConfirmDialog(this, panel,
                "Compare identities", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) return null;
        List<Identity> picked = new ArrayList<>();
        for (int i = 0; i < all.size(); i++) {
            if (boxes.get(i).isSelected()) picked.add(all.get(i));
        }
        if (picked.size() < 2) {
            JOptionPane.showMessageDialog(this, "Pick at least two identities to compare.",
                    "Too few identities", JOptionPane.WARNING_MESSAGE);
            return null;
        }
        return picked;
    }

    private void setStatus(String msg) {
        statusLabel.setText(msg);
    }

    public void unload() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
