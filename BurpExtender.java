import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtender implements BurpExtension, ContextMenuItemsProvider, ExtensionUnloadingHandler {

    private static final String DEFAULT_GATEWAY_URL = "http://127.0.0.1:5001";
    private static final String DEFAULT_API_KEY = "";
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 5000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 120000;

    private static final String PREF_GATEWAY_URL = "hex_workbench.gateway_url";
    private static final String PREF_API_KEY = "hex_workbench.api_key";
    private static final String PREF_CONNECT_TIMEOUT_MS = "hex_workbench.connect_timeout_ms";
    private static final String PREF_READ_TIMEOUT_MS = "hex_workbench.read_timeout_ms";

    private MontoyaApi api;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private String baseUrl = DEFAULT_GATEWAY_URL;
    private final String ingestPath = "/ingest";
    private String apiKey = DEFAULT_API_KEY;
    private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
    private int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;

    private volatile String lastTraceId = null;
    private volatile String lastHeadersJson = null;
    private volatile String lastBody = null;
    private volatile String lastResponseBody = null;
    private volatile int lastStatusCode = 0;

    private JButton deepPivotButton;
    private JTextArea summaryArea;
    private JTextArea riskArea;
    private JTextArea leaderboardArea;
    private JTextArea diffArea;
    private JTextArea fuzzArea;
    private JTextArea exploitArea;
    private JTextArea signalsArea;
    private JTextArea mutationArea;
    private JTextArea multiAuthArea;
    private JTextArea rawArea;
    private JTextArea priorityArea;
    private JTextArea exploitReplayArea;
    private JTextArea corroborationArea;
    private JTextArea reportArea;
    private JTextArea pivotArea;
    private JLabel statusLabel;
    private JButton rerunPivotButton;
    private JTextArea endpointIntelArea;
    private JTextArea nextActionsArea;
    private JTextArea hypothesesArea;


    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Hex Workbench");
        api.extension().registerUnloadingHandler(this);
        loadSettings();

        api.userInterface().registerSuiteTab("Workbench", buildMainPanel());
        api.userInterface().registerSuiteTab("Workbench Settings", buildSettingsPanel());
        api.userInterface().registerContextMenuItemsProvider(this);

        setAllPanels(
                "Hex Workbench ready.",
                "No risk data yet.",
                "No leaderboard data yet.",
                "No diff data yet.",
                "No fuzzing hints yet.",
                "No exploit suggestions yet.",
                "No detection signals yet.",
                "No mutation replay data yet.",
                "No multi-auth replay data yet.",
                "No priority findings yet.",
                "No auto exploit replay data yet.",
                "No cross-user corroboration data yet.",
                "No report findings yet.",
                "No auto pivot data yet.",
                "Raw response will appear here."
        );
        setStatus("Ready");
    }

    private void loadSettings() {
        try {
            String savedGatewayUrl = api.persistence().preferences().getString(PREF_GATEWAY_URL);
            String savedApiKey = api.persistence().preferences().getString(PREF_API_KEY);
            String savedConnectTimeout = api.persistence().preferences().getString(PREF_CONNECT_TIMEOUT_MS);
            String savedReadTimeout = api.persistence().preferences().getString(PREF_READ_TIMEOUT_MS);

            if (savedGatewayUrl != null && !savedGatewayUrl.isBlank()) {
                baseUrl = savedGatewayUrl.trim();
            }
            if (savedApiKey != null) {
                apiKey = savedApiKey.trim();
            }
            connectTimeoutMs = parsePositiveInt(savedConnectTimeout, DEFAULT_CONNECT_TIMEOUT_MS);
            readTimeoutMs = parsePositiveInt(savedReadTimeout, DEFAULT_READ_TIMEOUT_MS);
        } catch (Exception e) {
            baseUrl = DEFAULT_GATEWAY_URL;
            apiKey = DEFAULT_API_KEY;
            connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
            readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        }
    }

    private void saveSettings(String newBaseUrl, String newApiKey, String newConnectTimeoutMs, String newReadTimeoutMs) {
        baseUrl = newBaseUrl.trim();
        apiKey = newApiKey.trim();
        connectTimeoutMs = parsePositiveInt(newConnectTimeoutMs, DEFAULT_CONNECT_TIMEOUT_MS);
        readTimeoutMs = parsePositiveInt(newReadTimeoutMs, DEFAULT_READ_TIMEOUT_MS);
        api.persistence().preferences().setString(PREF_GATEWAY_URL, baseUrl);
        api.persistence().preferences().setString(PREF_API_KEY, apiKey);
        api.persistence().preferences().setString(PREF_CONNECT_TIMEOUT_MS, String.valueOf(connectTimeoutMs));
        api.persistence().preferences().setString(PREF_READ_TIMEOUT_MS, String.valueOf(readTimeoutMs));
    }

    private int parsePositiveInt(String value, int fallback) {
        try {
            int parsed = Integer.parseInt(value == null ? "" : value.trim());
            return parsed > 0 ? parsed : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    private boolean isValidGatewayUrl(String url) {
        if (url == null || url.isBlank()) return false;
        String trimmed = url.trim().toLowerCase();
        return trimmed.startsWith("http://") || trimmed.startsWith("https://");
    }

    private String getIngestUrl() {
        return baseUrl + ingestPath;
    }

    private String getPivotUrl(String traceId) {
        return baseUrl + "/chain/" + traceId + "/pivot";
    }

    private String getDeepPivotUrl(String traceId) {
        return baseUrl + "/chain/" + traceId + "/deep_pivot";
    }

    private Component buildMainPanel() {
        summaryArea = createReadOnlyArea();
        riskArea = createReadOnlyArea();
        leaderboardArea = createReadOnlyArea();
        diffArea = createReadOnlyArea();
        fuzzArea = createReadOnlyArea();
        exploitArea = createReadOnlyArea();
        signalsArea = createReadOnlyArea();
        mutationArea = createReadOnlyArea();
        multiAuthArea = createReadOnlyArea();
        rawArea = createReadOnlyArea();
        priorityArea = createReadOnlyArea();
        exploitReplayArea = createReadOnlyArea();
        corroborationArea = createReadOnlyArea();
        reportArea = createReadOnlyArea();
        pivotArea = createReadOnlyArea();
        endpointIntelArea = createReadOnlyArea();
        nextActionsArea = createReadOnlyArea();
        hypothesesArea = createReadOnlyArea();


        statusLabel = new JLabel("Ready");
        rerunPivotButton = new JButton("Re-run Pivots (Allow Actions)");
        rerunPivotButton.setEnabled(false);
        rerunPivotButton.addActionListener(e -> rerunPivotsWithActions());

        deepPivotButton = new JButton("Deep Pivot (Adaptive)");
        deepPivotButton.setEnabled(false);
        deepPivotButton.addActionListener(e -> runDeepPivot());

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(statusLabel, BorderLayout.WEST);
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(rerunPivotButton);
        buttonPanel.add(deepPivotButton);
        bottomPanel.add(buttonPanel, BorderLayout.EAST);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Summary", wrap(summaryArea));
        tabs.addTab("Priority Findings", wrap(priorityArea));
        tabs.addTab("Risk", wrap(riskArea));
        tabs.addTab("Report Findings", wrap(reportArea));
        tabs.addTab("Leaderboard", wrap(leaderboardArea));
        tabs.addTab("Diff Engine", wrap(diffArea));
        tabs.addTab("Fuzzing Hints", wrap(fuzzArea));
        tabs.addTab("Exploit Suggestions", wrap(exploitArea));
        tabs.addTab("Signals", wrap(signalsArea));
        tabs.addTab("Auto Mutation Replay", wrap(mutationArea));
        tabs.addTab("Auto Multi-Auth Replay", wrap(multiAuthArea));
        tabs.addTab("Cross-User Corroboration", wrap(corroborationArea));
        tabs.addTab("Auto Exploit Replay", wrap(exploitReplayArea));
        tabs.addTab("Auto Pivot", wrap(pivotArea));
        tabs.addTab("Raw", wrap(rawArea));
        tabs.addTab("Endpoint Intel", wrap(endpointIntelArea));
        tabs.addTab("Next Actions", wrap(nextActionsArea));
        tabs.addTab("Hypotheses & Payloads", wrap(hypothesesArea));

        JPanel root = new JPanel(new BorderLayout());
        root.add(tabs, BorderLayout.CENTER);
        root.add(bottomPanel, BorderLayout.SOUTH);
        return root;
    }

    private Component buildSettingsPanel() {
        JPanel panel = new JPanel(new GridLayout(5, 2, 8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JTextField urlField = new JTextField(baseUrl);
        JTextField keyField = new JTextField(apiKey);
        JTextField connectTimeoutField = new JTextField(String.valueOf(connectTimeoutMs));
        JTextField readTimeoutField = new JTextField(String.valueOf(readTimeoutMs));
        JButton saveButton = new JButton("Save");

        saveButton.addActionListener(e -> {
            String newBaseUrl = urlField.getText().trim();
            String newApiKey = keyField.getText().trim();
            String newConnectTimeout = connectTimeoutField.getText().trim();
            String newReadTimeout = readTimeoutField.getText().trim();

            if (!isValidGatewayUrl(newBaseUrl)) {
                JOptionPane.showMessageDialog(panel, "Base URL must start with http:// or https://", "Invalid Base URL", JOptionPane.ERROR_MESSAGE);
                return;
            }
            saveSettings(newBaseUrl, newApiKey, newConnectTimeout, newReadTimeout);
            urlField.setText(baseUrl);
            keyField.setText(apiKey);
            connectTimeoutField.setText(String.valueOf(connectTimeoutMs));
            readTimeoutField.setText(String.valueOf(readTimeoutMs));
            JOptionPane.showMessageDialog(panel, "Workbench settings saved.");
            setStatus("Settings saved");
        });

        panel.add(new JLabel("Base URL:"));
        panel.add(urlField);
        panel.add(new JLabel("API Key:"));
        panel.add(keyField);
        panel.add(new JLabel("Connect Timeout (ms):"));
        panel.add(connectTimeoutField);
        panel.add(new JLabel("Read Timeout (ms):"));
        panel.add(readTimeoutField);
        panel.add(new JLabel(""));
        panel.add(saveButton);
        return panel;
    }

    private JTextArea createReadOnlyArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    private JScrollPane wrap(JComponent component) {
        return new JScrollPane(component);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) return List.of();

        JMenuItem sendItem = new JMenuItem(new AbstractAction("Send to Workbench") {
            @Override
            public void actionPerformed(ActionEvent e) {
                for (HttpRequestResponse rr : selected) {
                    sendToWorkbench(rr);
                }
            }
        });
        return List.of(sendItem);
    }

    private void sendToWorkbench(HttpRequestResponse message) {
        if (!isValidGatewayUrl(baseUrl)) {
            rawArea.setText("ERROR:\nInvalid gateway base URL. It must start with http:// or https://");
            setStatus("Invalid base URL");
            return;
        }
        if (apiKey == null || apiKey.isBlank()) {
            rawArea.setText("ERROR:\nAPI key is empty. Open Workbench Settings and set the correct gateway key.");
            setStatus("Missing API key");
            return;
        }

        setStatus("Sending...");
        executor.submit(() -> {
            try {
                JsonObject payload = new JsonObject();
                payload.addProperty("program", "local-lab");
                payload.addProperty("method", message.request().method());
                payload.addProperty("url", message.request().url());
                payload.addProperty("body", message.request().bodyToString());
                payload.add("headers", headersToJson(message.request().headers()));

                lastHeadersJson = gson.toJson(headersToJson(message.request().headers()));
                lastBody = message.request().bodyToString();

                if (message.response() != null) {
                    payload.addProperty("response", message.response().bodyToString());
                    payload.addProperty("status_code", message.response().statusCode());
                    lastResponseBody = message.response().bodyToString();
                    lastStatusCode = message.response().statusCode();
                } else {
                    payload.addProperty("response", "");
                    payload.addProperty("status_code", 0);
                    lastResponseBody = "";
                    lastStatusCode = 0;
                }

                HttpURLConnection conn = (HttpURLConnection) new URL(getIngestUrl()).openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("X-API-Key", apiKey);
                conn.setDoOutput(true);
                conn.setConnectTimeout(connectTimeoutMs);
                conn.setReadTimeout(readTimeoutMs);

                byte[] bodyBytes = gson.toJson(payload).getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bodyBytes);
                    os.flush();
                }

                int code = conn.getResponseCode();
                String responseText = readResponse(conn);

                if (code != 200) {
                    final String errMsg = "Gateway returned HTTP " + code + "\n" + truncateText(responseText, 200000);
                    SwingUtilities.invokeLater(() -> {
                        rawArea.setText(errMsg);
                        setStatus("Error " + code);
                    });
                    return;
                }

                final String finalResponse = responseText;
                SwingUtilities.invokeLater(() -> {
                    try {
                        if (finalResponse == null || finalResponse.isBlank()) {
                            rawArea.setText("Empty response from gateway.");
                            setStatus("Done (empty)");
                            return;
                        }
                        JsonObject result = gson.fromJson(finalResponse, JsonObject.class);
                        if (result == null) {
                            rawArea.setText("Gateway returned non-JSON.\n\n" + truncateText(finalResponse, 200000));
                            setStatus("Parse error");
                            return;
                        }
                        if (result.has("trace_id") && !result.get("trace_id").isJsonNull()) {
                            lastTraceId = result.get("trace_id").getAsString();
                            rerunPivotButton.setEnabled(true);
                            deepPivotButton.setEnabled(true);
                        } else {
                            rerunPivotButton.setEnabled(false);
                            deepPivotButton.setEnabled(false);
                        }
                        updatePanels(result);
                        setStatus("Done (200)");
                    } catch (Exception parseEx) {
                        rawArea.setText("ERROR PARSING GATEWAY RESPONSE:\n" + parseEx + "\n\nRaw response:\n" + truncateText(finalResponse, 200000));
                        setStatus("Parse error");
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    rawArea.setText("ERROR:\n" + ex);
                    setStatus("Error: " + safeMessage(ex));
                });
            }
        });
    }

    private JsonObject headersToJson(List<HttpHeader> headers) {
        JsonObject obj = new JsonObject();
        for (HttpHeader h : headers) {
            obj.addProperty(h.name(), h.value());
        }
        return obj;
    }

    private String readResponse(HttpURLConnection conn) throws Exception {
        InputStream is;
        int code = conn.getResponseCode();
        if (code >= 200 && code < 400) {
            is = conn.getInputStream();
        } else {
            is = conn.getErrorStream();
        }
        if (is == null) return "";
        try (InputStream stream = is) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String truncateText(String text, int maxChars) {
        if (text == null) return "";
        if (text.length() <= maxChars) return text;
        return text.substring(0, maxChars) + "\n\n...[truncated]...";
    }

    private String safeMessage(Throwable t) {
        if (t == null) return "Unknown error";
        if (t.getMessage() == null || t.getMessage().isBlank()) return t.getClass().getSimpleName();
        return t.getMessage();
    }

    private void updatePanels(JsonObject root) {
        rawArea.setText(truncateText(gson.toJson(root), 200000));
        summaryArea.setText(buildSummary(root));
        priorityArea.setText(buildPriorityFindings(root));
        riskArea.setText(buildRisk(root));
        reportArea.setText(buildReportFindings(root));
        leaderboardArea.setText(buildLeaderboard(root));
        diffArea.setText(buildDiffEngine(root));
        fuzzArea.setText(buildFuzzingHints(root));
        exploitArea.setText(buildExploitSuggestions(root));
        signalsArea.setText(buildSignals(root));
        mutationArea.setText(buildAutoMutationReplay(root));
        multiAuthArea.setText(buildAutoMultiAuthReplay(root));
        corroborationArea.setText(buildCrossUserCorroboration(root));
        exploitReplayArea.setText(buildAutoExploitReplay(root));
        pivotArea.setText(buildAutoPivot(root));
        endpointIntelArea.setText(buildEndpointIntel(root));
        nextActionsArea.setText(buildNextActions(root));
        hypothesesArea.setText(buildHypotheses(root));

        summaryArea.setCaretPosition(0);
        priorityArea.setCaretPosition(0);
        riskArea.setCaretPosition(0);
        reportArea.setCaretPosition(0);
        leaderboardArea.setCaretPosition(0);
        diffArea.setCaretPosition(0);
        fuzzArea.setCaretPosition(0);
        exploitArea.setCaretPosition(0);
        signalsArea.setCaretPosition(0);
        mutationArea.setCaretPosition(0);
        multiAuthArea.setCaretPosition(0);
        corroborationArea.setCaretPosition(0);
        exploitReplayArea.setCaretPosition(0);
        pivotArea.setCaretPosition(0);
        rawArea.setCaretPosition(0);
    }

    private void setAllPanels(String summary, String risk, String leaderboard, String diff, String fuzz,
                              String exploit, String signals, String mutation, String multiAuth,
                              String priority, String exploitReplay, String corroboration,
                              String report, String pivot, String raw) {
        summaryArea.setText(summary);
        riskArea.setText(risk);
        leaderboardArea.setText(leaderboard);
        diffArea.setText(diff);
        fuzzArea.setText(fuzz);
        exploitArea.setText(exploit);
        signalsArea.setText(signals);
        mutationArea.setText(mutation);
        multiAuthArea.setText(multiAuth);
        priorityArea.setText(priority);
        exploitReplayArea.setText(exploitReplay);
        corroborationArea.setText(corroboration);
        reportArea.setText(report);
        pivotArea.setText(pivot);
        rawArea.setText(raw);
    }

    private void setStatus(String text) {
        if (statusLabel != null) statusLabel.setText(text);
    }

    private void rerunPivotsWithActions() {
        if (lastTraceId == null || lastTraceId.isBlank()) {
            JOptionPane.showMessageDialog(null, "No trace ID available. Please send a request first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String pivotUrl = getPivotUrl(lastTraceId);
        setStatus("Re-running pivots with actions allowed...");
        executor.submit(() -> {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(pivotUrl).openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("X-API-Key", apiKey);
                conn.setDoOutput(true);
                conn.setConnectTimeout(connectTimeoutMs);
                conn.setReadTimeout(readTimeoutMs);

                JsonObject body = new JsonObject();
                body.addProperty("allow_action_pivots", true);
                body.addProperty("max_candidates", 5);
                body.addProperty("max_results", 5);
                byte[] bodyBytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bodyBytes);
                    os.flush();
                }

                int code = conn.getResponseCode();
                String responseText = readResponse(conn);
                if (code != 200) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Gateway returned " + code + "\n" + responseText, "Error", JOptionPane.ERROR_MESSAGE));
                    setStatus("Pivot re-run failed (" + code + ")");
                    return;
                }
                JsonObject result = gson.fromJson(responseText, JsonObject.class);
                if (result == null) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Invalid JSON response", "Error", JOptionPane.ERROR_MESSAGE));
                    return;
                }
                JsonObject pivotExec = result.getAsJsonObject("pivot_execution");
                if (pivotExec == null) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "No pivot_execution in response", "Error", JOptionPane.ERROR_MESSAGE));
                    return;
                }
                SwingUtilities.invokeLater(() -> showPivotResultsDialog(pivotExec));
                setStatus("Pivot re-run completed");
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE));
                setStatus("Error: " + safeMessage(ex));
            }
        });
    }

    private void runDeepPivot() {
        if (lastTraceId == null || lastTraceId.isBlank()) {
            JOptionPane.showMessageDialog(null, "No trace ID available. Please send a request first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String deepPivotUrl = getDeepPivotUrl(lastTraceId);
        setStatus("Running deep pivot...");
        executor.submit(() -> {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(deepPivotUrl).openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("X-API-Key", apiKey);
                conn.setDoOutput(true);
                conn.setConnectTimeout(connectTimeoutMs);
                conn.setReadTimeout(readTimeoutMs);

                JsonObject body = new JsonObject();
                body.addProperty("allow_action_pivots", true);
                body.addProperty("max_depth", 5);
                body.addProperty("min_score_threshold", 20);
                byte[] bodyBytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bodyBytes);
                    os.flush();
                }

                int code = conn.getResponseCode();
                String responseText = readResponse(conn);
                if (code != 200) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Deep pivot failed: " + code + "\n" + responseText, "Error", JOptionPane.ERROR_MESSAGE));
                    setStatus("Deep pivot failed");
                    return;
                }
                JsonObject result = gson.fromJson(responseText, JsonObject.class);
                SwingUtilities.invokeLater(() -> showDeepPivotDialog(result));
                setStatus("Deep pivot completed");
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE));
                setStatus("Deep pivot error");
            }
        });
    }

    private void showPivotResultsDialog(JsonObject pivotExec) {
        JDialog dialog = new JDialog((Frame) null, "Action Pivot Results", true);
        dialog.setSize(900, 600);
        dialog.setLayout(new BorderLayout());

        PivotTableModel model = new PivotTableModel(pivotExec);
        JTable table = new JTable(model);
        table.setDefaultRenderer(Object.class, new VerdictColorRenderer());
        table.setAutoCreateRowSorter(true);
        JScrollPane scrollPane = new JScrollPane(table);

        JButton promoteButton = new JButton("Promote to Seed");
        JButton exportCsv = new JButton("Export CSV");
        JButton exportJson = new JButton("Export JSON");
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(promoteButton);
        buttonPanel.add(exportCsv);
        buttonPanel.add(exportJson);

        promoteButton.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow == -1) {
                JOptionPane.showMessageDialog(dialog, "Select a pivot result first.");
                return;
            }
            String method = (String) table.getValueAt(selectedRow, 0);
            String url = (String) table.getValueAt(selectedRow, 1);
            String responseBody = model.getResponseBody(selectedRow);
            int statusCode = model.getStatusCode(selectedRow);
            promotePivotToSeed(method, url, lastHeadersJson, lastBody, responseBody, statusCode);
            dialog.dispose();
        });

        exportCsv.addActionListener(e -> exportPivotToCSV(model));
        exportJson.addActionListener(e -> exportPivotToJSON(model));

        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }

    private void showDeepPivotDialog(JsonObject result) {
        JDialog dialog = new JDialog((Frame) null, "Deep Pivot Chain", true);
        dialog.setSize(800, 500);
        dialog.setLayout(new BorderLayout());

        JTextArea textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        StringBuilder sb = new StringBuilder();
        sb.append("Deep pivot chain (length: ").append(result.get("chain_length").getAsInt()).append(")\n\n");
        JsonArray chain = result.getAsJsonArray("chain");
        for (JsonElement e : chain) {
            JsonObject step = e.getAsJsonObject();
            sb.append("Depth ").append(step.get("depth").getAsInt()).append(":\n");
            sb.append("  Method: ").append(getString(step, "method")).append("\n");
            sb.append("  URL: ").append(getString(step, "url")).append("\n");
            sb.append("  Status: ").append(getString(step, "status_code")).append("\n");
            sb.append("  Verdict: ").append(getString(step, "verdict")).append("\n");
            sb.append("  Score: ").append(getString(step, "score")).append("\n");
            sb.append("  Pivot value: ").append(getString(step, "pivot_value")).append("\n");
            sb.append("  Reason: ").append(getString(step, "neighbor_reason")).append("\n\n");
        }
        textArea.setText(sb.toString());
        JScrollPane scroll = new JScrollPane(textArea);
        dialog.add(scroll, BorderLayout.CENTER);
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(ev -> dialog.dispose());
        dialog.add(closeButton, BorderLayout.SOUTH);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }

    private void promotePivotToSeed(String method, String url, String headersJson, String body, String responseBody, int statusCode) {
        JsonObject payload = new JsonObject();
        payload.addProperty("program", "local-lab");
        payload.addProperty("method", method);
        payload.addProperty("url", url);
        payload.addProperty("body", body != null ? body : "");
        JsonObject headers = gson.fromJson(headersJson, JsonObject.class);
        payload.add("headers", headers);
        payload.addProperty("response", responseBody != null ? responseBody : "");
        payload.addProperty("status_code", statusCode);

        setStatus("Promoting pivot to seed...");
        executor.submit(() -> {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(getIngestUrl()).openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("X-API-Key", apiKey);
                conn.setDoOutput(true);
                conn.setConnectTimeout(connectTimeoutMs);
                conn.setReadTimeout(readTimeoutMs);

                byte[] bodyBytes = gson.toJson(payload).getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bodyBytes);
                    os.flush();
                }

                int code = conn.getResponseCode();
                String responseText = readResponse(conn);
                if (code == 200) {
                    JsonObject result = gson.fromJson(responseText, JsonObject.class);
                    SwingUtilities.invokeLater(() -> {
                        updatePanels(result);
                        setStatus("Promoted pivot analyzed");
                    });
                } else {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Promote failed: " + code + "\n" + responseText, "Error", JOptionPane.ERROR_MESSAGE));
                    setStatus("Promote failed");
                }
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE));
                setStatus("Promote error");
            }
        });
    }

    private void exportPivotToCSV(PivotTableModel model) {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".csv")) file = new File(file.getAbsolutePath() + ".csv");
            try (PrintWriter pw = new PrintWriter(file)) {
                for (int col = 0; col < model.getColumnCount(); col++) {
                    if (col > 0) pw.print(',');
                    pw.print("\"" + model.getColumnName(col) + "\"");
                }
                pw.println();
                for (int row = 0; row < model.getRowCount(); row++) {
                    for (int col = 0; col < model.getColumnCount(); col++) {
                        if (col > 0) pw.print(',');
                        Object val = model.getValueAt(row, col);
                        String str = val == null ? "" : val.toString().replace("\"", "\"\"");
                        pw.print("\"" + str + "\"");
                    }
                    pw.println();
                }
                JOptionPane.showMessageDialog(null, "Exported to " + file.getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportPivotToJSON(PivotTableModel model) {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".json")) file = new File(file.getAbsolutePath() + ".json");
            List<JsonObject> rows = new ArrayList<>();
            for (int row = 0; row < model.getRowCount(); row++) {
                JsonObject obj = new JsonObject();
                obj.addProperty("method", (String) model.getValueAt(row, 0));
                obj.addProperty("url", (String) model.getValueAt(row, 1));
                obj.addProperty("status_code", (Integer) model.getValueAt(row, 2));
                obj.addProperty("verdict", (String) model.getValueAt(row, 3));
                obj.addProperty("score", (Integer) model.getValueAt(row, 4));
                obj.addProperty("field_diff", (String) model.getValueAt(row, 5));
                rows.add(obj);
            }
            JsonArray array = new JsonArray();
            for (JsonObject o : rows) array.add(o);
            try (FileWriter fw = new FileWriter(file)) {
                fw.write(gson.toJson(array));
                JOptionPane.showMessageDialog(null, "Exported to " + file.getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    class PivotTableModel extends AbstractTableModel {
        private final String[] columns = {"Method", "URL", "Status", "Verdict", "Score", "Field Diff"};
        private final List<Object[]> data = new ArrayList<>();
        private final List<String> responseBodies = new ArrayList<>();
        private final List<Integer> statusCodes = new ArrayList<>();

        public PivotTableModel(JsonObject pivotExec) {
            JsonArray results = pivotExec.getAsJsonArray("results");
            if (results != null) {
                for (JsonElement e : results) {
                    JsonObject r = e.getAsJsonObject();
                    String method = getString(r, "method");
                    String url = getString(r, "url");
                    int status = r.has("status_code") && !r.get("status_code").isJsonNull() ? r.get("status_code").getAsInt() : 0;
                    String verdict = "N/A";
                    int score = 0;
                    String fieldDiff = "";
                    String responseBody = "";
                    if (r.has("analysis") && !r.get("analysis").isJsonNull()) {
                        JsonObject analysis = r.getAsJsonObject("analysis");
                        verdict = getString(analysis, "verdict");
                        score = analysis.has("score") ? analysis.get("score").getAsInt() : 0;
                        if (analysis.has("field_diff")) fieldDiff = analysis.get("field_diff").toString();
                    }
                    if (r.has("error")) {
                        verdict = "ERROR";
                        fieldDiff = getString(r, "error");
                    }
                    if (r.has("body")) responseBody = getString(r, "body");
                    data.add(new Object[]{method, url, status, verdict, score, fieldDiff});
                    responseBodies.add(responseBody);
                    statusCodes.add(status);
                }
            }
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }
        @Override public Object getValueAt(int row, int col) { return data.get(row)[col]; }
        @Override public Class<?> getColumnClass(int col) {
            if (col == 2 || col == 4) return Integer.class;
            return String.class;
        }
        public String getResponseBody(int row) { return responseBodies.get(row); }
        public int getStatusCode(int row) { return statusCodes.get(row); }
    }

    class VerdictColorRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                String verdict = (String) table.getValueAt(row, 3);
                if (verdict != null) {
                    if (verdict.equals("HIGH PROBABILITY IDOR")) c.setBackground(new Color(255, 200, 200));
                    else if (verdict.equals("AUTH BOUNDARY DIFFERENCE")) c.setBackground(new Color(255, 255, 200));
                    else if (verdict.equals("POSSIBLE AUTH/OBJECT ISSUE")) c.setBackground(new Color(200, 200, 255));
                    else if (verdict.equals("ERROR")) c.setBackground(new Color(255, 150, 150));
                    else c.setBackground(Color.WHITE);
                } else c.setBackground(Color.WHITE);
            }
            return c;
        }
    }

    // ------------------------------------------------------------------
    // Helper methods for JSON extraction (unchanged from original)
    // ------------------------------------------------------------------
    private void appendLine(StringBuilder sb, String label, String value) {
        if (value == null || value.isBlank() || "N/A".equals(value)) return;
        sb.append(label).append(": ").append(value).append("\n");
    }

    private JsonObject getObject(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || !obj.get(key).isJsonObject()) return null;
        return obj.getAsJsonObject(key);
    }

    private JsonArray getArray(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || !obj.get(key).isJsonArray()) return null;
        return obj.getAsJsonArray(key);
    }

    private String getString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return "N/A";
        return asString(obj.get(key));
    }

    private String asString(JsonElement element) {
        if (element == null || element.isJsonNull()) return "N/A";
        if (element.isJsonPrimitive()) {
            return element.getAsJsonPrimitive().isString() ? element.getAsString() : element.toString();
        }
        return element.toString();
    }

    private String joinArray(JsonArray arr) {
        if (arr == null || arr.size() == 0) return "N/A";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < arr.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(asString(arr.get(i)));
        }
        return sb.toString();
    }

    private String joinReasons(JsonArray arr) {
        if (arr == null || arr.size() == 0) return "N/A";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < arr.size(); i++) {
            if (i > 0) sb.append("; ");
            sb.append(asString(arr.get(i)));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Build methods (exactly as in your original code)
    // ------------------------------------------------------------------
    private String buildSummary(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Summary\n");
        sb.append("=======\n");
        sb.append("\nHigh-Level Intelligence\n");
        sb.append("-----------------------\n");

        appendLine(sb, "Risk Score", getString(root, "risk_score"));
        appendLine(sb, "Exploitability", getString(root, "exploitability"));
        appendLine(sb, "Confidence", getString(root, "confidence"));

        JsonArray topFindings = getArray(root, "report_ready_findings");
        if (topFindings != null && topFindings.size() > 0) {
            sb.append("Top Findings\n");
            for (int i = 0; i < Math.min(3, topFindings.size()); i++) {
                JsonObject f = topFindings.get(i).getAsJsonObject();
                sb.append(" - ")
                        .append(getString(f, "title"))
                        .append(" [")
                        .append(getString(f, "severity"))
                        .append("]\n");
            }
        }

        JsonObject exploitReplay = getObject(root, "auto_exploit_replay");
        if (exploitReplay != null) {
            appendLine(sb, "Exploit Confirmed", getString(exploitReplay, "confirmed"));
            appendLine(sb, "Exploit Stable", getString(exploitReplay, "stable_only"));
        }

        JsonObject corr = getObject(root, "true_cross_user_corroboration");
        if (corr != null) {
            appendLine(sb, "Cross-User Findings", getString(corr, "strong_finding_count"));
        }

        sb.append("\n");

        appendLine(sb, "Trace ID", getString(root, "trace_id"));
        appendLine(sb, "Path", getString(root, "path"));
        appendLine(sb, "Query", getString(root, "query"));
        appendLine(sb, "Risk Score", getString(root, "risk_score"));

        JsonObject timings = getObject(root, "timings");
        if (timings != null) {
            sb.append("\nTimings\n");
            sb.append("-------\n");
            appendLine(sb, "Total (ms)", getString(timings, "total_ms"));
            appendLine(sb, "Parse Request (ms)", getString(timings, "parse_request_ms"));
            appendLine(sb, "Build State (ms)", getString(timings, "build_state_ms"));

            JsonObject replayTimings = getObject(timings, "replay");
            if (replayTimings != null) {
                appendLine(sb, "Replay / Auto Replay (ms)", getString(replayTimings, "auto_replay_ms"));
                appendLine(sb, "Replay / Mutation (ms)", getString(replayTimings, "auto_mutation_replay_ms"));
                appendLine(sb, "Replay / Multi-Auth (ms)", getString(replayTimings, "auto_multi_auth_replay_ms"));
            }

            JsonObject analysisTimings = getObject(timings, "analysis");
            if (analysisTimings != null) {
                appendLine(sb, "Analysis / Initial Signals (ms)", getString(analysisTimings, "initial_signal_build_ms"));
                appendLine(sb, "Analysis / Graph Context (ms)", getString(analysisTimings, "graph_context_ms"));
                appendLine(sb, "Analysis / Signal Enrichment (ms)", getString(analysisTimings, "signal_enrichment_ms"));
                appendLine(sb, "Analysis / Attack Chain (ms)", getString(analysisTimings, "attack_chain_ms"));
                appendLine(sb, "Analysis / Auto Exploit Replay (ms)", getString(analysisTimings, "auto_exploit_replay_ms"));
                appendLine(sb, "Analysis / Final Enrichment (ms)", getString(analysisTimings, "final_enrichment_ms"));
            }
        }

        JsonArray candidateInputs = getArray(root, "candidate_inputs");
        if (candidateInputs != null && candidateInputs.size() > 0) {
            sb.append("\nCandidate Inputs\n");
            sb.append("----------------\n");

            for (JsonElement e : candidateInputs) {
                JsonObject obj = e.getAsJsonObject();

                sb.append("- ")
                        .append(getString(obj, "name"))
                        .append(" [")
                        .append(getString(obj, "source"))
                        .append("] class=")
                        .append(getString(obj, "classification"))
                        .append(", value=")
                        .append(getString(obj, "sample_value"));

                String segmentKind = getString(obj, "segment_kind");
                String segmentIndex = getString(obj, "path_segment_index");

                if (!"N/A".equals(segmentKind)) {
                    sb.append(", segment_kind=").append(segmentKind);
                }
                if (!"N/A".equals(segmentIndex)) {
                    sb.append(", path_index=").append(segmentIndex);
                }

                sb.append("\n");

                JsonArray mutations = getArray(obj, "mutation_presets");
                if (mutations != null && mutations.size() > 0) {
                    sb.append("  mutations: ").append(joinArray(mutations)).append("\n");
                }
            }
        } else {
            sb.append("\nNo candidate inputs detected.\n");
        }

        return sb.toString();
    }

    private String buildPriorityFindings(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Priority Findings\n");
        sb.append("=================\n");

        JsonArray findings = getArray(root, "priority_findings");
        if (findings == null || findings.size() == 0) {
            sb.append("No priority findings available.\n");
        } else {
            for (JsonElement e : findings) {
                sb.append("- ").append(asString(e)).append("\n");
            }
        }

        JsonObject topNarrative = getObject(root, "top_narrative");
        if (topNarrative != null) {
            sb.append("\nTop Narrative\n");
            sb.append("-------------\n");
            appendLine(sb, "Title", getString(topNarrative, "title"));
            appendLine(sb, "Severity", getString(topNarrative, "severity"));
            appendLine(sb, "Summary", getString(topNarrative, "summary"));
        }

        JsonObject topFinding = getObject(root, "top_report_finding");
        if (topFinding != null) {
            sb.append("\nTop Report Finding\n");
            sb.append("------------------\n");
            appendLine(sb, "Title", getString(topFinding, "title"));
            appendLine(sb, "Severity", getString(topFinding, "severity"));
            appendLine(sb, "Confidence", getString(topFinding, "confidence"));
            appendLine(sb, "Category", getString(topFinding, "category"));
            appendLine(sb, "Summary", getString(topFinding, "summary"));
            appendLine(sb, "Impact", getString(topFinding, "impact"));
        }

        JsonObject evidence = getObject(root, "evidence_summary");
        if (evidence != null) {
            sb.append("\nEvidence Summary\n");
            sb.append("----------------\n");

            JsonObject mutation = getObject(evidence, "mutation");
            if (mutation != null) {
                sb.append("Mutation: tested=")
                        .append(getString(mutation, "tested"))
                        .append(", meaningful=")
                        .append(getString(mutation, "meaningful"))
                        .append("\n");
            }

            JsonObject multiAuth = getObject(evidence, "multi_auth");
            if (multiAuth != null) {
                sb.append("Multi-Auth: tested=")
                        .append(getString(multiAuth, "tested"))
                        .append(", meaningful=")
                        .append(getString(multiAuth, "meaningful"))
                        .append(", high_confidence=")
                        .append(getString(multiAuth, "high_confidence"))
                        .append(", same_object_difference=")
                        .append(getString(multiAuth, "same_object_difference"))
                        .append("\n");
            }

            JsonObject corroboration = getObject(evidence, "corroboration");
            if (corroboration != null) {
                sb.append("Corroboration: performed=")
                        .append(getString(corroboration, "performed"))
                        .append(", strong=")
                        .append(getString(corroboration, "strong"))
                        .append(", auth_boundary=")
                        .append(getString(corroboration, "auth_boundary"))
                        .append(", shared=")
                        .append(getString(corroboration, "shared"))
                        .append("\n");
            }

            JsonObject exploit = getObject(evidence, "exploit");
            if (exploit != null) {
                sb.append("Exploit Replay: tested=")
                        .append(getString(exploit, "tested"))
                        .append(", confirmed=")
                        .append(getString(exploit, "confirmed"))
                        .append(", stable_only=")
                        .append(getString(exploit, "stable_only"))
                        .append("\n");
            }
        }

        return sb.toString();
    }

    private String buildReportFindings(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Report Findings\n");
        sb.append("===============\n");

        JsonArray findings = getArray(root, "report_ready_findings");
        if (findings == null || findings.size() == 0) {
            sb.append("No report findings available.\n");
            return sb.toString();
        }

        for (JsonElement e : findings) {
            JsonObject f = e.getAsJsonObject();

            appendLine(sb, "Title", getString(f, "title"));
            appendLine(sb, "Severity", getString(f, "severity"));
            appendLine(sb, "Confidence", getString(f, "confidence"));
            appendLine(sb, "Category", getString(f, "category"));
            appendLine(sb, "Summary", getString(f, "summary"));
            appendLine(sb, "Impact", getString(f, "impact"));

            JsonArray evidence = getArray(f, "evidence");
            if (evidence != null && evidence.size() > 0) {
                sb.append("Evidence\n");
                for (JsonElement ev : evidence) {
                    sb.append(" - ").append(asString(ev)).append("\n");
                }
            }

            JsonArray notes = getArray(f, "reproduction_notes");
            if (notes != null && notes.size() > 0) {
                sb.append("Reproduction Notes\n");
                for (JsonElement n : notes) {
                    sb.append(" - ").append(asString(n)).append("\n");
                }
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    private String buildCrossUserCorroboration(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Cross-User Corroboration\n");
        sb.append("========================\n");

        JsonObject corr = getObject(root, "true_cross_user_corroboration");
        if (corr == null || !"true".equals(getString(corr, "performed"))) {
            sb.append("No corroboration performed.\n");
            if (corr != null) {
                appendLine(sb, "Reason", getString(corr, "reason"));
            }
            return sb.toString();
        }

        appendLine(sb, "Profiles Used", joinArray(getArray(corr, "profiles_used")));
        appendLine(sb, "Meaningful Count", getString(corr, "meaningful_count"));
        appendLine(sb, "Strong Finding Count", getString(corr, "strong_finding_count"));
        appendLine(sb, "Auth Boundary Count", getString(corr, "auth_boundary_count"));
        appendLine(sb, "Shared/Public Count", getString(corr, "shared_or_public_count"));
        sb.append("\n");

        JsonArray comparisons = getArray(corr, "comparisons");
        if (comparisons == null || comparisons.size() == 0) {
            sb.append("No comparisons available.\n");
            return sb.toString();
        }

        for (JsonElement e : comparisons) {
            JsonObject obj = e.getAsJsonObject();

            appendLine(sb, "Input", getString(obj, "input_name"));
            appendLine(sb, "Mutation", getString(obj, "mutation"));
            appendLine(sb, "URL", getString(obj, "mutated_url"));
            appendLine(sb, "Base Profile", getString(obj, "base_profile"));
            appendLine(sb, "Other Profile", getString(obj, "other_profile"));

            JsonObject cmp = getObject(obj, "comparison");
            if (cmp != null) {
                appendLine(sb, "Verdict", getString(cmp, "verdict"));
                appendLine(sb, "Confidence", getString(cmp, "confidence"));

                JsonArray reasons = getArray(cmp, "reasons");
                if (reasons != null && reasons.size() > 0) {
                    sb.append("Reasons: ").append(joinReasons(reasons)).append("\n");
                }

                JsonObject markerComparison = getObject(cmp, "identity_marker_comparison");
                if (markerComparison != null) {
                    JsonArray changed = getArray(markerComparison, "changed");
                    JsonArray same = getArray(markerComparison, "same");

                    if (changed != null && changed.size() > 0) {
                        sb.append("Changed Identity Markers\n");
                        for (JsonElement c : changed) {
                            JsonObject x = c.getAsJsonObject();
                            sb.append(" - ")
                                    .append(getString(x, "field"))
                                    .append(": ")
                                    .append(getString(x, "base"))
                                    .append(" -> ")
                                    .append(getString(x, "other"))
                                    .append("\n");
                        }
                    }

                    if (same != null && same.size() > 0) {
                        sb.append("Same Identity Markers\n");
                        for (JsonElement s : same) {
                            JsonObject x = s.getAsJsonObject();
                            sb.append(" - ")
                                    .append(getString(x, "field"))
                                    .append(": ")
                                    .append(getString(x, "value"))
                                    .append("\n");
                        }
                    }
                }
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    private String buildAutoExploitReplay(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Auto Exploit Replay\n");
        sb.append("===================\n");

        JsonObject replay = getObject(root, "auto_exploit_replay");
        if (replay == null || !"true".equals(getString(replay, "performed"))) {
            sb.append("No auto exploit replay performed.\n");
            if (replay != null) {
                appendLine(sb, "Reason", getString(replay, "reason"));
            }
            return sb.toString();
        }

        appendLine(sb, "Tested", getString(replay, "tested"));
        appendLine(sb, "Confirmed", getString(replay, "confirmed"));
        appendLine(sb, "Stable Only", getString(replay, "stable_only"));
        sb.append("\n");

        JsonArray results = getArray(replay, "results");
        if (results == null || results.size() == 0) {
            sb.append("No exploit replay results.\n");
            return sb.toString();
        }

        for (JsonElement e : results) {
            JsonObject obj = e.getAsJsonObject();

            appendLine(sb, "Type", getString(obj, "type"));
            appendLine(sb, "Target", getString(obj, "target"));
            appendLine(sb, "Confirmed", getString(obj, "confirmed"));
            appendLine(sb, "Stable", getString(obj, "stable"));
            appendLine(sb, "Strong Hits", getString(obj, "strong_hits"));
            appendLine(sb, "Stable Hits", getString(obj, "stable_hits"));

            JsonArray attempts = getArray(obj, "attempts");
            if (attempts != null && attempts.size() > 0) {
                sb.append("Attempts\n");

                for (JsonElement a : attempts) {
                    JsonObject attempt = a.getAsJsonObject();

                    appendLine(sb, "  Status", getString(attempt, "status"));
                    appendLine(sb, "  Length", getString(attempt, "length"));
                    appendLine(sb, "  Fingerprint", getString(attempt, "fingerprint"));
                    appendLine(sb, "  Strong Confirmation", getString(attempt, "strong_confirmation"));

                    JsonObject analysis = getObject(attempt, "analysis");
                    if (analysis != null) {
                        appendLine(sb, "  Verdict", getString(analysis, "verdict"));
                        appendLine(sb, "  Score", getString(analysis, "score"));

                        JsonArray reasons = getArray(analysis, "reasons");
                        if (reasons != null && reasons.size() > 0) {
                            sb.append("  Reasons: ").append(joinReasons(reasons)).append("\n");
                        }
                    }

                    String error = getString(attempt, "error");
                    if (!"N/A".equals(error)) {
                        appendLine(sb, "  Error", error);
                    }

                    sb.append("\n");
                }
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    private String buildRisk(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Risk\n");
        sb.append("====\n");

        appendLine(sb, "Score", getString(root, "risk_score"));

        JsonArray reasons = getArray(root, "reasons");
        if (reasons != null && reasons.size() > 0) {
            sb.append("\nReasons\n");
            sb.append("-------\n");
            for (JsonElement e : reasons) {
                sb.append("- ").append(asString(e)).append("\n");
            }
        } else {
            sb.append("\nNo reasons available.\n");
        }

        JsonArray attackHints = getArray(root, "attack_chain_hints");
        if (attackHints != null && attackHints.size() > 0) {
            sb.append("\nAttack Chain Hints\n");
            sb.append("------------------\n");
            for (JsonElement e : attackHints) {
                sb.append("- ").append(asString(e)).append("\n");
            }
        }

        JsonArray graphHints = getArray(root, "endpoint_graph_hints");
        if (graphHints != null && graphHints.size() > 0) {
            sb.append("\nEndpoint Graph Hints\n");
            sb.append("--------------------\n");
            for (JsonElement e : graphHints) {
                sb.append("- ").append(asString(e)).append("\n");
            }
        }

        return sb.toString();
    }

    private String buildLeaderboard(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Leaderboard\n");
        sb.append("===========\n");

        JsonArray board = getArray(root, "leaderboard");
        if (board == null || board.size() == 0) {
            sb.append("No leaderboard data available.\n");
            return sb.toString();
        }

        int rank = 1;
        for (JsonElement e : board) {
            JsonObject row = e.getAsJsonObject();
            sb.append(rank++)
                    .append(". ")
                    .append(getString(row, "method"))
                    .append(" ")
                    .append(getString(row, "path"))
                    .append(" (hits=")
                    .append(getString(row, "hits"))
                    .append(")\n");
        }

        return sb.toString();
    }

    private String buildDiffEngine(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Diff Engine\n");
        sb.append("===========\n");

        JsonArray diffs = getArray(root, "diff_engine");
        if (diffs == null || diffs.size() == 0) {
            sb.append("No diffs detected.\n");
            return sb.toString();
        }

        for (JsonElement e : diffs) {
            JsonObject diff = e.getAsJsonObject();
            sb.append("- [")
                    .append(getString(diff, "severity"))
                    .append("] ")
                    .append(getString(diff, "type"))
                    .append(": ")
                    .append(getString(diff, "detail"))
                    .append("\n");
        }

        JsonObject autoReplay = getObject(root, "auto_replay");
        if (autoReplay != null) {
            sb.append("\nAuto Replay Snapshot\n");
            sb.append("-------------------\n");
            appendLine(sb, "Replay Status", getString(autoReplay, "status_code"));
            appendLine(sb, "Replay Length", getString(autoReplay, "length"));
            appendLine(sb, "Replay Fingerprint", getString(autoReplay, "fingerprint"));
            appendLine(sb, "Replay Error", getString(autoReplay, "error"));
        }

        return sb.toString();
    }

    private String buildFuzzingHints(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Fuzzing Hints\n");
        sb.append("=============\n");

        JsonArray hints = getArray(root, "fuzzing_hints");
        if (hints == null || hints.size() == 0) {
            sb.append("No fuzzing hints available.\n");
        } else {
            for (JsonElement e : hints) {
                sb.append("- ").append(asString(e)).append("\n");
            }
        }

        JsonArray candidateInputs = getArray(root, "candidate_inputs");
        if (candidateInputs != null && candidateInputs.size() > 0) {
            sb.append("\nMutation Presets\n");
            sb.append("----------------\n");
            for (JsonElement e : candidateInputs) {
                JsonObject obj = e.getAsJsonObject();
                JsonArray mutations = getArray(obj, "mutation_presets");
                if (mutations != null && mutations.size() > 0) {
                    sb.append("- ")
                            .append(getString(obj, "name"))
                            .append(" [")
                            .append(getString(obj, "source"))
                            .append("] -> ")
                            .append(joinArray(mutations))
                            .append("\n");
                }
            }
        }

        return sb.toString();
    }

    private String buildExploitSuggestions(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Exploit Suggestions\n");
        sb.append("===================\n");

        JsonArray suggestions = getArray(root, "exploit_suggestions");
        if (suggestions == null || suggestions.size() == 0) {
            sb.append("No exploit suggestions available.\n");
            return sb.toString();
        }

        for (JsonElement e : suggestions) {
            JsonObject obj = e.getAsJsonObject();

            sb.append(getString(obj, "title")).append("\n");
            appendLine(sb, "  Priority", getString(obj, "priority"));
            appendLine(sb, "  Category", getString(obj, "category"));
            appendLine(sb, "  Why", getString(obj, "why"));

            JsonArray checks = getArray(obj, "checks");
            if (checks != null && checks.size() > 0) {
                sb.append("  Checks\n");
                for (JsonElement c : checks) {
                    sb.append("   - ").append(asString(c)).append("\n");
                }
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    private String buildSignals(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Detection Signals\n");
        sb.append("=================\n");

        JsonArray signals = getArray(root, "detection_signals");
        if (signals == null || signals.size() == 0) {
            sb.append("No detection signals.\n");
        } else {
            for (JsonElement e : signals) {
                JsonObject obj = e.getAsJsonObject();
                sb.append("- [")
                        .append(getString(obj, "severity"))
                        .append("] ")
                        .append(getString(obj, "type"))
                        .append(": ")
                        .append(getString(obj, "detail"))
                        .append("\n");
            }
        }

        JsonObject attackChain = getObject(root, "attack_chain");
        if (attackChain != null) {
            sb.append("\nAttack Chain Seed\n");
            sb.append("-----------------\n");

            JsonObject seed = getObject(attackChain, "seed");
            if (seed != null) {
                appendLine(sb, "Node ID", getString(seed, "node_id"));
                appendLine(sb, "Normalized Path", getString(seed, "normalized_path"));
                appendLine(sb, "Method", getString(seed, "method"));
                appendLine(sb, "Stage", getString(seed, "stage"));

                JsonArray families = getArray(seed, "families");
                if (families != null && families.size() > 0) {
                    appendLine(sb, "Families", joinArray(families));
                }
            }

            JsonArray hypotheses = getArray(attackChain, "chain_hypotheses");
            if (hypotheses != null && hypotheses.size() > 0) {
                sb.append("\nAttack Chain Hypotheses\n");
                sb.append("-----------------------\n");
                for (JsonElement e : hypotheses) {
                    JsonObject obj = e.getAsJsonObject();
                    sb.append("- ").append(getString(obj, "name")).append("\n");

                    JsonArray steps = getArray(obj, "steps");
                    if (steps != null) {
                        for (JsonElement step : steps) {
                            sb.append("    • ").append(asString(step)).append("\n");
                        }
                    }
                }
            }
        }

        return sb.toString();
    }

    private String buildAutoMutationReplay(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Auto Mutation Replay\n");
        sb.append("====================\n");

        JsonObject replay = getObject(root, "auto_mutation_replay");
        if (replay == null || !"true".equals(getString(replay, "performed"))) {
            sb.append("No mutation replay performed.\n");
            if (replay != null) {
                appendLine(sb, "Reason", getString(replay, "reason"));
            }
            return sb.toString();
        }

        appendLine(sb, "Tested Count", getString(replay, "tested_count"));
        appendLine(sb, "Meaningful Count", getString(replay, "meaningful_count"));
        sb.append("\n");

        JsonArray results = getArray(replay, "results");
        if (results == null || results.size() == 0) {
            sb.append("No mutation results.\n");
            return sb.toString();
        }

        for (JsonElement e : results) {
            JsonObject obj = e.getAsJsonObject();

            sb.append("Input: ").append(getString(obj, "input_name"))
                    .append(" (").append(getString(obj, "source")).append(")\n");

            appendLine(sb, "  Mutation", getString(obj, "mutation"));
            appendLine(sb, "  Status", getString(obj, "status_code"));
            appendLine(sb, "  Length", getString(obj, "length"));
            appendLine(sb, "  URL", getString(obj, "mutated_url"));

            JsonObject analysis = getObject(obj, "analysis");
            if (analysis != null) {
                appendLine(sb, "  Score", getString(analysis, "score"));
                appendLine(sb, "  Verdict", getString(analysis, "verdict"));

                JsonArray reasons = getArray(analysis, "reasons");
                if (reasons != null && reasons.size() > 0) {
                    sb.append("  Reasons: ").append(joinReasons(reasons)).append("\n");
                }

                JsonObject fieldDiff = getObject(analysis, "field_diff");
                if (fieldDiff != null) {
                    JsonArray changed = getArray(fieldDiff, "changed");
                    JsonArray added = getArray(fieldDiff, "added");
                    JsonArray removed = getArray(fieldDiff, "removed");

                    if ((changed != null && changed.size() > 0)
                            || (added != null && added.size() > 0)
                            || (removed != null && removed.size() > 0)) {
                        sb.append("  Field Diff\n");

                        if (changed != null) {
                            for (JsonElement c : changed) {
                                JsonObject x = c.getAsJsonObject();
                                sb.append("    changed: ")
                                        .append(getString(x, "field"))
                                        .append(" -> ")
                                        .append(getString(x, "after"))
                                        .append("\n");
                            }
                        }

                        if (added != null) {
                            for (JsonElement c : added) {
                                JsonObject x = c.getAsJsonObject();
                                sb.append("    added: ")
                                        .append(getString(x, "field"))
                                        .append(" = ")
                                        .append(getString(x, "value"))
                                        .append("\n");
                            }
                        }

                        if (removed != null) {
                            for (JsonElement c : removed) {
                                JsonObject x = c.getAsJsonObject();
                                sb.append("    removed: ")
                                        .append(getString(x, "field"))
                                        .append("\n");
                            }
                        }
                    }
                }
            }

            if ("true".equals(getString(obj, "status_changed"))) {
                sb.append("  ⚠ Status Changed\n");
            }
            if ("true".equals(getString(obj, "length_changed"))) {
                sb.append("  ⚠ Length Changed\n");
            }
            if ("true".equals(getString(obj, "fingerprint_changed"))) {
                sb.append("  ⚠ Fingerprint Changed\n");
            }

            String error = getString(obj, "error");
            if (!"N/A".equals(error)) {
                sb.append("  Error: ").append(error).append("\n");
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    private String buildAutoMultiAuthReplay(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Auto Multi-Auth Replay\n");
        sb.append("======================\n");

        JsonObject replay = getObject(root, "auto_multi_auth_replay");
        if (replay == null || !"true".equals(getString(replay, "performed"))) {
            sb.append("No multi-auth replay performed.\n");
            if (replay != null) {
                appendLine(sb, "Reason", getString(replay, "reason"));
            }
            return sb.toString();
        }

        appendLine(sb, "Profiles Used", joinArray(getArray(replay, "profiles_used")));
        appendLine(sb, "Tested Count", getString(replay, "tested_count"));
        appendLine(sb, "Meaningful Count", getString(replay, "meaningful_count"));
        appendLine(sb, "High Confidence", getString(replay, "high_confidence_count"));
        sb.append("\n");

        JsonArray results = getArray(replay, "results");
        if (results == null || results.size() == 0) {
            sb.append("No multi-auth results.\n");
            return sb.toString();
        }

        for (JsonElement e : results) {
            JsonObject obj = e.getAsJsonObject();

            sb.append("Profile: ").append(getString(obj, "profile_label")).append("\n");
            appendLine(sb, "  Input", getString(obj, "input_name"));
            appendLine(sb, "  Source", getString(obj, "source"));
            appendLine(sb, "  Mutation", getString(obj, "mutation"));
            appendLine(sb, "  Status", getString(obj, "status_code"));
            appendLine(sb, "  Length", getString(obj, "length"));
            appendLine(sb, "  URL", getString(obj, "mutated_url"));

            JsonObject analysis = getObject(obj, "analysis");
            if (analysis != null) {
                appendLine(sb, "  Score", getString(analysis, "score"));
                appendLine(sb, "  Verdict", getString(analysis, "verdict"));

                JsonArray reasons = getArray(analysis, "reasons");
                if (reasons != null && reasons.size() > 0) {
                    sb.append("  Reasons: ").append(joinReasons(reasons)).append("\n");
                }

                JsonObject fieldDiff = getObject(analysis, "field_diff");
                if (fieldDiff != null) {
                    JsonArray changed = getArray(fieldDiff, "changed");
                    JsonArray added = getArray(fieldDiff, "added");
                    JsonArray removed = getArray(fieldDiff, "removed");

                    if ((changed != null && changed.size() > 0)
                            || (added != null && added.size() > 0)
                            || (removed != null && removed.size() > 0)) {
                        sb.append("  Field Diff\n");

                        if (changed != null) {
                            for (JsonElement c : changed) {
                                JsonObject x = c.getAsJsonObject();
                                sb.append("    changed: ")
                                        .append(getString(x, "field"))
                                        .append(" -> ")
                                        .append(getString(x, "after"))
                                        .append("\n");
                            }
                        }

                        if (added != null) {
                            for (JsonElement c : added) {
                                JsonObject x = c.getAsJsonObject();
                                sb.append("    added: ")
                                        .append(getString(x, "field"))
                                        .append(" = ")
                                        .append(getString(x, "value"))
                                        .append("\n");
                            }
                        }

                        if (removed != null) {
                            for (JsonElement c : removed) {
                                JsonObject x = c.getAsJsonObject();
                                sb.append("    removed: ")
                                        .append(getString(x, "field"))
                                        .append("\n");
                            }
                        }
                    }
                }
            }

            if ("true".equals(getString(obj, "status_changed"))) {
                sb.append("  ⚠ Status Changed\n");
            }
            if ("true".equals(getString(obj, "length_changed"))) {
                sb.append("  ⚠ Length Changed\n");
            }
            if ("true".equals(getString(obj, "fingerprint_changed"))) {
                sb.append("  ⚠ Fingerprint Changed\n");
            }

            String error = getString(obj, "error");
            if (!"N/A".equals(error)) {
                sb.append("  Error: ").append(error).append("\n");
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    private String buildAutoPivot(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        sb.append("Auto Pivot Results\n");
        sb.append("==================\n\n");

        JsonObject pivot = getObject(root, "auto_pivot");
        if (pivot == null) {
            sb.append("No auto pivot data available.\n");
            return sb.toString();
        }
        if (!"true".equals(getString(pivot, "performed"))) {
            sb.append("Pivot execution was not performed.\n");
            return sb.toString();
        }

        appendLine(sb, "Candidate Count", getString(pivot, "candidate_count"));
        appendLine(sb, "Executed Count", getString(pivot, "executed_count"));
        appendLine(sb, "Meaningful Count", getString(pivot, "meaningful_count"));
        sb.append("\n");

        JsonArray results = getArray(pivot, "results");
        if (results == null || results.size() == 0) {
            sb.append("No pivot results.\n");
            return sb.toString();
        }

        for (JsonElement e : results) {
            JsonObject r = e.getAsJsonObject();
            appendLine(sb, "Method", getString(r, "method"));
            appendLine(sb, "URL", getString(r, "url"));
            appendLine(sb, "Status Code", getString(r, "status_code"));
            if (r.has("preview_only") && r.get("preview_only").getAsBoolean()) {
                sb.append("  [PREVIEW ONLY] ").append(getString(r, "preview_reason")).append("\n");
            }
            if (r.has("error")) {
                appendLine(sb, "Error", getString(r, "error"));
            } else {
                JsonObject analysis = getObject(r, "analysis");
                if (analysis != null) {
                    appendLine(sb, "Verdict", getString(analysis, "verdict"));
                    appendLine(sb, "Score", getString(analysis, "score"));
                    JsonObject fieldDiff = getObject(analysis, "field_diff");
                    if (fieldDiff != null) {
                        sb.append("Field Diff: ").append(fieldDiff.toString()).append("\n");
                    }
                } else {
                    appendLine(sb, "Verdict", "N/A");
                    appendLine(sb, "Score", "N/A");
                }
            }
            sb.append("\n");
        }
        return sb.toString();
    }

private String buildEndpointIntel(JsonObject root) {
    StringBuilder sb = new StringBuilder();
    sb.append("Endpoint Intelligence\n");
    sb.append("=====================\n\n");
    JsonObject intel = getObject(root, "endpoint_intelligence");
    if (intel == null) {
        sb.append("No endpoint intelligence data.\n");
        return sb.toString();
    }
    appendLine(sb, "Path", getString(intel, "path"));
    appendLine(sb, "Method", getString(intel, "method"));
    appendLine(sb, "Normalized Path", getString(intel, "normalized_path"));
    appendLine(sb, "Family", getString(intel, "family"));
    appendLine(sb, "Status Code", getString(intel, "status_code"));
    appendLine(sb, "Content Length", getString(intel, "content_length"));
    appendLine(sb, "Has JSON", getString(intel, "has_json"));
    appendLine(sb, "Mentions Error", getString(intel, "mentions_error"));
    appendLine(sb, "Mentions Admin", getString(intel, "mentions_admin"));
    appendLine(sb, "Mentions UserId", getString(intel, "mentions_userid"));
    appendLine(sb, "Has Object ID Surface", getString(intel, "has_object_id_surface"));
    appendLine(sb, "Is Action Endpoint", getString(intel, "is_action_endpoint"));
    sb.append("\nEndpoint Score: ").append(getString(root, "endpoint_score")).append("\n");
    sb.append("Auth State: ").append(getString(root, "auth_state")).append("\n");
    return sb.toString();
}

private String buildNextActions(JsonObject root) {
    StringBuilder sb = new StringBuilder();
    sb.append("Next Actions (from Phase 3)\n");
    sb.append("============================\n\n");
    JsonArray actions = getArray(root, "next_actions");
    if (actions == null || actions.size() == 0) {
        sb.append("No recommended actions.\n");
    } else {
        for (JsonElement e : actions) {
            JsonObject act = e.getAsJsonObject();
            sb.append("- ").append(getString(act, "action"))
              .append(" [").append(getString(act, "priority")).append("]\n");
            sb.append("  Reason: ").append(getString(act, "reason")).append("\n");
        }
    }
    sb.append("\nDecision Engine Output\n");
    sb.append("----------------------\n");
    JsonObject decision = getObject(root, "decision_engine");
    if (decision != null) {
        appendLine(sb, "Executed Actions", joinArray(getArray(decision, "executed_actions")));
        appendLine(sb, "Skipped Actions", joinArray(getArray(decision, "skipped")));
    } else {
        sb.append("No decision engine data.\n");
    }
    return sb.toString();
}

private String buildHypotheses(JsonObject root) {
    StringBuilder sb = new StringBuilder();
    sb.append("Hypotheses & Smart Payloads\n");
    sb.append("============================\n\n");
    JsonArray hypotheses = getArray(root, "hypotheses");
    if (hypotheses == null || hypotheses.size() == 0) {
        sb.append("No hypotheses generated.\n");
    } else {
        for (JsonElement e : hypotheses) {
            JsonObject hyp = e.getAsJsonObject();
            sb.append("Type: ").append(getString(hyp, "type")).append("\n");
            sb.append("Confidence: ").append(getString(hyp, "confidence")).append("\n");
            sb.append("Evidence: ").append(getString(hyp, "evidence")).append("\n\n");
        }
    }
    sb.append("Smart Payloads\n");
    sb.append("--------------\n");
    JsonArray payloads = getArray(root, "smart_payloads");
    if (payloads != null && payloads.size() > 0) {
        for (JsonElement p : payloads) {
            sb.append("- ").append(asString(p)).append("\n");
        }
    } else {
        sb.append("No smart payloads.\n");
    }
    return sb.toString();
}

    @Override
    public void extensionUnloaded() {
        executor.shutdownNow();
    }
}
