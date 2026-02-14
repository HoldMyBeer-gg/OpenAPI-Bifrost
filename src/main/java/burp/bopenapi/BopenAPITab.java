package burp.bopenapi;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
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
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main OpenAPI-NG tab panel. Provides the UI for loading OpenAPI specs, viewing parsed
 * endpoints, and sending requests to Scanner, Repeater, or Intruder.
 * <p>
 * Supports loading specs via drag-and-drop, URL, file path (including network drives),
 * or raw paste. Includes base URL override, regex filtering, and request preview.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class BopenAPITab extends JPanel {

    private final MontoyaApi api;
    private final Logging logging;
    private final OpenAPIParser parser = new OpenAPIParser();
    private final RequestGenerator requestGenerator = new RequestGenerator();
    private final EndpointTableModel tableModel = new EndpointTableModel();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private JTextField urlOrPathField;
    private JTextArea rawSpecArea;
    private JTextField baseUrlOverrideField;
    private JTextField filterField;
    private JLabel filterHitsLabel;
    private JTable endpointTable;
    private HttpRequestEditor requestEditor;
    private JLabel statusLabel;
    private String defaultServer = "";
    private boolean hasScanner = false;

    public BopenAPITab(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        try {
            this.hasScanner = api.scanner() != null;
        } catch (Exception e) {
            hasScanner = false;
        }
        buildUi();
    }

    private void buildUi() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new BorderLayout(5, 5));

        // Drop zone
        JPanel dropZone = new JPanel(new GridBagLayout());
        dropZone.setPreferredSize(new Dimension(0, 80));
        dropZone.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(UIManager.getColor("Component.borderColor"), 2),
                new EmptyBorder(10, 10, 10, 10)
        ));
        dropZone.setBackground(UIManager.getColor("Panel.background"));
        JLabel dropLabel = new JLabel("Drop OpenAPI spec here, paste URL/path below, or paste raw JSON/YAML");
        dropZone.add(dropLabel);
        setupDropTarget(dropZone);
        topPanel.add(dropZone, BorderLayout.NORTH);

        // URL/path input row
        JPanel inputRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        inputRow.add(new JLabel("Parse from local file or URL:"));
        urlOrPathField = new JTextField(50);
        inputRow.add(urlOrPathField);
        JButton browseBtn = new JButton("Browse");
        browseBtn.addActionListener(e -> doBrowse());
        inputRow.add(browseBtn);
        JButton loadBtn = new JButton("Load");
        loadBtn.addActionListener(e -> doLoad());
        inputRow.add(loadBtn);
        topPanel.add(inputRow, BorderLayout.CENTER);

        // Base URL override + Raw spec paste
        JPanel southPanel = new JPanel();
        southPanel.setLayout(new BoxLayout(southPanel, BoxLayout.Y_AXIS));
        JPanel overrideRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        overrideRow.add(new JLabel("Base URL override (optional):"));
        baseUrlOverrideField = new JTextField(40);
        baseUrlOverrideField.setToolTipText("Override server URL from spec (e.g. https://api.target.com)");
        overrideRow.add(baseUrlOverrideField);
        southPanel.add(overrideRow);

        JPanel pastePanel = new JPanel(new BorderLayout(5, 5));
        pastePanel.add(new JLabel("Or paste raw OpenAPI spec (JSON/YAML):"), BorderLayout.NORTH);
        rawSpecArea = new JTextArea(6, 60);
        rawSpecArea.setLineWrap(true);
        rawSpecArea.setFont(UIManager.getFont("TextArea.font"));
        JScrollPane rawSpecScroll = new JScrollPane(rawSpecArea);
        rawSpecScroll.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(UIManager.getColor("Component.borderColor"), 1),
                new EmptyBorder(4, 4, 4, 4)
        ));
        pastePanel.add(rawSpecScroll, BorderLayout.CENTER);
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
        JPanel pasteBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 5));
        pasteBtnRow.add(parseRawBtn);
        pastePanel.add(pasteBtnRow, BorderLayout.SOUTH);
        southPanel.add(pastePanel);

        topPanel.add(southPanel, BorderLayout.SOUTH);

        JScrollPane topScroll = new JScrollPane(topPanel);
        topScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        topScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        topScroll.setBorder(BorderFactory.createEmptyBorder());
        topScroll.getViewport().setPreferredSize(new Dimension(0, 280));
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
            var response = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url));
            var httpResponse = response.response();
            if (httpResponse == null) throw new IOException("No response");
            byte[] body = httpResponse.body().getBytes();
            String content = new String(body, StandardCharsets.UTF_8);
            parseInBackground(content, url);
        } catch (Exception e) {
            logging.logToError("Failed to load URL: " + e.getMessage());
            SwingUtilities.invokeLater(() -> fallbackToRawPasteOrSetError("Unable to load from URL: " + e.getMessage()));
        }
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
        tableModel.setFilter(filterField.getText());
        updateFilterHits();
        updateRequestPreview();

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
        int row = endpointTable.getSelectedRow();
        if (row >= 0) {
            ApiEndpoint ep = tableModel.getEndpointAt(row);
            if (ep != null) {
                HttpRequest req = requestGenerator.buildRequest(ep, getBaseUrlOverride());
                requestEditor.setRequest(req);
            }
        } else {
            requestEditor.setRequest(null);
        }
    }

    private String getBaseUrlOverride() {
        String s = baseUrlOverrideField.getText();
        return (s != null && !s.isBlank()) ? s.trim() : null;
    }

    private void setupContextMenu() {
        JPopupMenu popup = new JPopupMenu();
        JMenu bopenMenu = new JMenu("OpenAPI-NG");
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
        bopenMenu.add(scanItem);
        bopenMenu.add(repeaterItem);
        bopenMenu.add(intruderItem);
        popup.add(bopenMenu);

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
        if (!hasScanner) return;
        int[] rows = endpointTable.getSelectedRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to scan.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        try {
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override);
                api.scanner()
                        .startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS))
                        .addRequest(req);
            }
            setStatus("Started active scan for " + endpoints.size() + " endpoints.");
        } catch (Exception ex) {
            logging.logToError("Actively scan failed: " + ex.getMessage());
            setStatus("Scan failed: " + ex.getMessage());
        }
    }

    private void doSendToRepeater() {
        int[] rows = endpointTable.getSelectedRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to send to Repeater.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        try {
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override);
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
        int[] rows = endpointTable.getSelectedRows();
        if (rows.length == 0) {
            setStatus("Select one or more endpoints to send to Intruder.");
            return;
        }
        List<ApiEndpoint> endpoints = tableModel.getSelectedEndpoints(rows);
        String override = getBaseUrlOverride();
        try {
            for (ApiEndpoint ep : endpoints) {
                HttpRequest req = requestGenerator.buildRequest(ep, override);
                HttpRequestTemplate template = requestGenerator.buildIntruderTemplate(ep, override);
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

    private void setStatus(String msg) {
        statusLabel.setText(msg);
    }

    public void unload() {
        executor.shutdown();
    }
}
