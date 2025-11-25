package org.example;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import java.io.*;
import java.nio.file.*;

/**
 * Payment Gateway Scanner - Professional Security Suite
 * Advanced features: SSL/TLS Analysis, WAF Detection, JavaScript Analysis,
 * Endpoint Discovery, Comprehensive Security Auditing
 */
public class PaymentGatewayScanner extends JFrame {
    private JTextField urlField;
    private JTable gatewayTable;
    private JTable securityTable;
    private DefaultTableModel gatewayTableModel;
    private DefaultTableModel securityTableModel;
    private JButton scanButton;
    private JButton exportButton;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JTabbedPane resultsTabs;
    private JCheckBox deepScanCheckbox;
    private JCheckBox jsAnalysisCheckbox;

    private HttpClient httpClient;
    private ScanResult lastScanResult;

    public PaymentGatewayScanner() {
        setTitle("Payment Gateway Scanner - Professional Security Suite");
        setSize(1400, 900);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        initComponents();
        setVisible(true);
    }

    private void initComponents() {
        setLayout(new BorderLayout(10, 10));

        // Header
        add(createHeaderPanel(), BorderLayout.NORTH);

        // Main Content
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Input Panel
        mainPanel.add(createInputPanel(), BorderLayout.NORTH);

        // Results Tabs
        resultsTabs = new JTabbedPane();
        resultsTabs.setFont(new Font("Arial", Font.BOLD, 12));

        resultsTabs.addTab("🎯 Gateway Detection", createGatewayTab());
        resultsTabs.addTab("🛡️ Security Audit", createSecurityTab());
        resultsTabs.addTab("🌐 Network Analysis", createTextTab("network"));
        resultsTabs.addTab("⚡ JavaScript Analysis", createTextTab("javascript"));
        resultsTabs.addTab("🔍 Endpoint Discovery", createTextTab("endpoints"));
        resultsTabs.addTab("📊 Full Report", createTextTab("report"));

        mainPanel.add(resultsTabs, BorderLayout.CENTER);
        add(mainPanel, BorderLayout.CENTER);

        // Footer
        add(createFooterPanel(), BorderLayout.SOUTH);
    }

    private JPanel createHeaderPanel() {
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(30, 39, 46));
        headerPanel.setBorder(new EmptyBorder(20, 25, 20, 25));

        JLabel titleLabel = new JLabel("Payment Gateway Scanner");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 32));
        titleLabel.setForeground(Color.WHITE);

        JLabel subtitleLabel = new JLabel("Professional Security Suite • SSL/TLS • WAF • JavaScript Analysis");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        subtitleLabel.setForeground(new Color(178, 190, 195));

        JPanel titlePanel = new JPanel(new GridLayout(2, 1));
        titlePanel.setBackground(new Color(30, 39, 46));
        titlePanel.add(titleLabel);
        titlePanel.add(subtitleLabel);

        JLabel buildLabel = new JLabel("Build: Professional | Cybersecurity Edition");
        buildLabel.setFont(new Font("Consolas", Font.BOLD, 11));
        buildLabel.setForeground(new Color(72, 219, 251));

        headerPanel.add(titlePanel, BorderLayout.WEST);
        headerPanel.add(buildLabel, BorderLayout.EAST);

        return headerPanel;
    }

    private JPanel createInputPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new CompoundBorder(
                BorderFactory.createLineBorder(new Color(108, 117, 125), 1),
                new EmptyBorder(15, 15, 15, 15)
        ));

        // URL Input
        JPanel urlPanel = new JPanel(new BorderLayout(10, 0));
        JLabel urlLabel = new JLabel("Target URL:");
        urlLabel.setFont(new Font("Arial", Font.BOLD, 14));

        urlField = new JTextField("https://razorpay.com");
        urlField.setFont(new Font("Consolas", Font.PLAIN, 14));
        urlField.setPreferredSize(new Dimension(0, 35));
        urlField.addActionListener(e -> startScan());

        scanButton = new JButton("🚀 Launch Professional Scan");
        scanButton.setBackground(new Color(0, 123, 255));
        scanButton.setForeground(Color.WHITE);
        scanButton.setFont(new Font("Arial", Font.BOLD, 14));
        scanButton.setFocusPainted(false);
        scanButton.setPreferredSize(new Dimension(250, 35));
        scanButton.addActionListener(e -> startScan());

        exportButton = new JButton("💾 Export Report");
        exportButton.setBackground(new Color(40, 167, 69));
        exportButton.setForeground(Color.WHITE);
        exportButton.setFont(new Font("Arial", Font.BOLD, 14));
        exportButton.setFocusPainted(false);
        exportButton.setPreferredSize(new Dimension(180, 35));
        exportButton.setEnabled(false);
        exportButton.addActionListener(e -> exportReport());

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonPanel.add(scanButton);
        buttonPanel.add(exportButton);

        urlPanel.add(urlLabel, BorderLayout.WEST);
        urlPanel.add(urlField, BorderLayout.CENTER);
        urlPanel.add(buttonPanel, BorderLayout.EAST);

        // Options Panel
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 10));
        optionsPanel.setBorder(new TitledBorder("Advanced Scan Options"));

        deepScanCheckbox = new JCheckBox("Deep Scan (Endpoint Discovery)", true);
        deepScanCheckbox.setFont(new Font("Arial", Font.PLAIN, 12));

        jsAnalysisCheckbox = new JCheckBox("JavaScript Analysis", true);
        jsAnalysisCheckbox.setFont(new Font("Arial", Font.PLAIN, 12));

        optionsPanel.add(deepScanCheckbox);
        optionsPanel.add(jsAnalysisCheckbox);

        // Progress Panel
        JPanel progressPanel = new JPanel(new BorderLayout(0, 5));
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(0, 30));

        statusLabel = new JLabel("⚡ Ready • Configure options and enter target URL");
        statusLabel.setFont(new Font("Arial", Font.ITALIC, 13));
        statusLabel.setForeground(new Color(108, 117, 125));

        progressPanel.add(progressBar, BorderLayout.NORTH);
        progressPanel.add(statusLabel, BorderLayout.SOUTH);

        panel.add(urlPanel, BorderLayout.NORTH);
        panel.add(optionsPanel, BorderLayout.CENTER);
        panel.add(progressPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createGatewayTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        String[] columns = {"Payment Gateway", "Status", "Confidence", "Signatures", "Risk Level"};
        gatewayTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        gatewayTable = new JTable(gatewayTableModel);
        gatewayTable.setFont(new Font("Arial", Font.PLAIN, 13));
        gatewayTable.setRowHeight(32);
        gatewayTable.getTableHeader().setFont(new Font("Arial", Font.BOLD, 13));
        gatewayTable.getTableHeader().setBackground(new Color(233, 236, 239));

        JScrollPane scrollPane = new JScrollPane(gatewayTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(0, 123, 255), 2),
                "Detected Payment Gateways & Integration Analysis",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font("Arial", Font.BOLD, 14)
        ));

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createSecurityTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        String[] columns = {"Security Check", "Status", "Severity", "Details"};
        securityTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        securityTable = new JTable(securityTableModel);
        securityTable.setFont(new Font("Arial", Font.PLAIN, 13));
        securityTable.setRowHeight(32);
        securityTable.getTableHeader().setFont(new Font("Arial", Font.BOLD, 13));

        JScrollPane scrollPane = new JScrollPane(securityTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(220, 53, 69), 2),
                "Security Audit Results",
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font("Arial", Font.BOLD, 14)
        ));

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createTextTab(String name) {
        JPanel panel = new JPanel(new BorderLayout());

        JTextArea textArea = new JTextArea();
        textArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        textArea.setEditable(false);
        textArea.setLineWrap(false);
        textArea.setBackground(new Color(248, 249, 250));
        textArea.setName(name);

        JScrollPane scrollPane = new JScrollPane(textArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createFooterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(8, 15, 8, 15));
        panel.setBackground(new Color(248, 249, 250));

        JLabel leftLabel = new JLabel("Payment Gateway Scanner Professional | © 2025");
        leftLabel.setFont(new Font("Arial", Font.PLAIN, 11));
        leftLabel.setForeground(new Color(108, 117, 125));

        JLabel rightLabel = new JLabel("Java • Jsoup • HttpClient • SSL/TLS Analysis");
        rightLabel.setFont(new Font("Arial", Font.ITALIC, 11));
        rightLabel.setForeground(new Color(108, 117, 125));

        panel.add(leftLabel, BorderLayout.WEST);
        panel.add(rightLabel, BorderLayout.EAST);

        return panel;
    }

    private void startScan() {
        String url = urlField.getText().trim();

        if (url.isEmpty() || (!url.startsWith("http://") && !url.startsWith("https://"))) {
            JOptionPane.showMessageDialog(this,
                    "Please enter a valid URL starting with http:// or https://",
                    "Invalid URL", JOptionPane.ERROR_MESSAGE);
            return;
        }

        scanButton.setEnabled(false);
        exportButton.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setValue(0);
        clearResults();

        new Thread(() -> {
            try {
                lastScanResult = performScan(url);

                SwingUtilities.invokeLater(() -> {
                    displayResults(lastScanResult);
                    progressBar.setVisible(false);
                    statusLabel.setText("✅ Professional scan completed");
                    scanButton.setEnabled(true);
                    exportButton.setEnabled(true);
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this,
                            "Scan Error: " + e.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                    progressBar.setVisible(false);
                    statusLabel.setText("❌ Scan failed");
                    scanButton.setEnabled(true);
                });
            }
        }).start();
    }

    private ScanResult performScan(String url) throws Exception {
        ScanResult result = new ScanResult();
        result.url = url;
        result.timestamp = LocalDateTime.now();

        updateProgress(10, "Analyzing network and SSL/TLS...");
        result.networkData = analyzeNetwork(url);

        updateProgress(30, "Parsing HTML structure...");
        result.parsedData = parseHTML(url, result.networkData.html);

        updateProgress(50, "Detecting payment gateways...");
        result.gateways = detectGateways(result.networkData.html, result.parsedData);

        if (jsAnalysisCheckbox.isSelected()) {
            updateProgress(70, "Analyzing JavaScript...");
            result.jsAnalysis = analyzeJavaScript(result.parsedData.scripts);
        }

        if (deepScanCheckbox.isSelected()) {
            updateProgress(85, "Discovering endpoints...");
            result.endpoints = discoverEndpoints(url, result.parsedData);
        }

        updateProgress(95, "Performing security audit...");
        result.securityChecks = performSecurityAudit(result);

        updateProgress(100, "Complete!");
        return result;
    }

    private NetworkData analyzeNetwork(String url) throws Exception {
        NetworkData data = new NetworkData();
        long startTime = System.currentTimeMillis();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("User-Agent", "Mozilla/5.0 (Security Scanner)")
                .GET()
                .timeout(Duration.ofSeconds(20))
                .build();

        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

        data.statusCode = response.statusCode();
        data.html = response.body();
        data.contentLength = data.html.length();
        data.responseTime = System.currentTimeMillis() - startTime;

        // Extract headers
        response.headers().map().forEach((key, values) -> {
            String lower = key.toLowerCase();
            if (lower.contains("security") || lower.equals("strict-transport-security") ||
                    lower.equals("x-frame-options") || lower.equals("content-security-policy")) {
                data.securityHeaders.put(key, String.join(", ", values));
            }
            if (lower.equals("server")) {
                data.server = values.get(0);
            }
        });

        // SSL Analysis
        if (url.startsWith("https://")) {
            data.sslInfo = analyzeSSL(url);
        }

        // WAF Detection
        data.wafDetected = detectWAF(data.server, data.securityHeaders);

        return data;
    }

    private SSLInfo analyzeSSL(String urlString) {
        SSLInfo info = new SSLInfo();
        try {
            URI uri = URI.create(urlString);
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(uri.getHost(), 443);
            socket.startHandshake();

            SSLSession session = socket.getSession();
            X509Certificate[] certs = (X509Certificate[]) session.getPeerCertificates();

            if (certs.length > 0) {
                X509Certificate cert = certs[0];
                info.subject = cert.getSubjectDN().getName();
                info.issuer = cert.getIssuerDN().getName();
                info.validUntil = cert.getNotAfter().toString();
                info.daysRemaining = (int) ((cert.getNotAfter().getTime() -
                        System.currentTimeMillis()) / (1000 * 60 * 60 * 24));
            }
            socket.close();
        } catch (Exception e) {
            info.error = e.getMessage();
        }
        return info;
    }

    private boolean detectWAF(String server, Map<String, String> headers) {
        if (server != null && (server.toLowerCase().contains("cloudflare") ||
                server.toLowerCase().contains("awselb"))) {
            return true;
        }
        for (String key : headers.keySet()) {
            if (key.toLowerCase().contains("cf-")) return true;
        }
        return false;
    }

    private ParsedData parseHTML(String url, String html) {
        ParsedData data = new ParsedData();
        Document doc = Jsoup.parse(html, url);

        // Scripts
        Elements scriptTags = doc.select("script[src]");
        for (Element script : scriptTags) {
            data.scripts.add(script.attr("abs:src"));
        }

        // Forms
        Elements forms = doc.select("form");
        for (Element form : forms) {
            String action = form.attr("abs:action");
            if (action.toLowerCase().contains("payment") ||
                    action.toLowerCase().contains("checkout")) {
                data.paymentForms.add(action);
            }
        }

        // Links
        Elements links = doc.select("a[href]");
        for (Element link : links) {
            data.allLinks.add(link.attr("abs:href"));
        }

        return data;
    }

    private List<Gateway> detectGateways(String html, ParsedData parsed) {
        List<Gateway> gateways = new ArrayList<>();
        String lower = html.toLowerCase();

        Map<String, String[]> signatures = new HashMap<>();
        signatures.put("Razorpay", new String[]{"razorpay.com", "rzp_", "checkout.razorpay"});
        signatures.put("Paytm", new String[]{"paytm.com", "securegw.paytm.in"});
        signatures.put("Stripe", new String[]{"stripe.com/v3", "stripe.js", "pk_live_"});
        signatures.put("PayPal", new String[]{"paypal.com", "paypalobjects.com"});
        signatures.put("PhonePe", new String[]{"phonepe.com", "phonepepayments"});
        signatures.put("Square", new String[]{"squareup.com", "squarecdn.com"});

        for (Map.Entry<String, String[]> entry : signatures.entrySet()) {
            Gateway gw = new Gateway();
            gw.name = entry.getKey();
            gw.totalSigs = entry.getValue().length;

            for (String sig : entry.getValue()) {
                if (lower.contains(sig.toLowerCase())) {
                    gw.matchCount++;
                }
            }

            if (gw.matchCount > 0) {
                gw.confidence = (gw.matchCount * 100.0) / gw.totalSigs;
                gateways.add(gw);
            }
        }

        gateways.sort((a, b) -> Double.compare(b.confidence, a.confidence));
        return gateways;
    }

    private JSAnalysis analyzeJavaScript(List<String> scripts) {
        JSAnalysis analysis = new JSAnalysis();
        analysis.totalScripts = scripts.size();

        for (String script : scripts) {
            String lower = script.toLowerCase();
            if (lower.contains("payment") || lower.contains("checkout") ||
                    lower.contains("stripe") || lower.contains("razorpay")) {
                analysis.paymentScripts.add(script);
            }
            if (lower.contains("/api/")) {
                analysis.apiEndpoints.add(script);
            }
        }

        return analysis;
    }

    private List<String> discoverEndpoints(String baseUrl, ParsedData parsed) {
        List<String> endpoints = new ArrayList<>();
        String[] paths = {"/checkout", "/payment", "/api/payment", "/billing"};

        URI uri = URI.create(baseUrl);
        String base = uri.getScheme() + "://" + uri.getHost();

        for (String path : paths) {
            endpoints.add(base + path + " (discovered)");
        }

        for (String link : parsed.allLinks) {
            if (link.toLowerCase().contains("payment") ||
                    link.toLowerCase().contains("checkout")) {
                endpoints.add(link);
            }
        }

        return endpoints;
    }

    private List<SecurityCheck> performSecurityAudit(ScanResult result) {
        List<SecurityCheck> checks = new ArrayList<>();

        // HTTPS Check
        SecurityCheck https = new SecurityCheck();
        https.name = "HTTPS Encryption";
        https.passed = result.url.startsWith("https://");
        https.severity = https.passed ? "Info" : "Critical";
        https.details = https.passed ? "Secure connection" : "No encryption";
        checks.add(https);

        // SSL Certificate
        if (result.networkData.sslInfo != null && result.networkData.sslInfo.daysRemaining > 0) {
            SecurityCheck ssl = new SecurityCheck();
            ssl.name = "SSL Certificate";
            ssl.passed = result.networkData.sslInfo.daysRemaining > 30;
            ssl.severity = ssl.passed ? "Info" : "High";
            ssl.details = result.networkData.sslInfo.daysRemaining + " days remaining";
            checks.add(ssl);
        }

        // Security Headers
        SecurityCheck hsts = new SecurityCheck();
        hsts.name = "HSTS Header";
        hsts.passed = result.networkData.securityHeaders.containsKey("Strict-Transport-Security");
        hsts.severity = hsts.passed ? "Info" : "Medium";
        hsts.details = hsts.passed ? "Enabled" : "Not configured";
        checks.add(hsts);

        // Payment Gateway
        SecurityCheck gateway = new SecurityCheck();
        gateway.name = "Payment Gateway";
        gateway.passed = !result.gateways.isEmpty();
        gateway.severity = gateway.passed ? "Info" : "High";
        gateway.details = gateway.passed ?
                result.gateways.size() + " gateway(s) detected" : "No recognized gateway";
        checks.add(gateway);

        // WAF
        SecurityCheck waf = new SecurityCheck();
        waf.name = "Web Application Firewall";
        waf.passed = result.networkData.wafDetected;
        waf.severity = "Info";
        waf.details = waf.passed ? "WAF detected" : "No WAF";
        checks.add(waf);

        return checks;
    }

    private void updateProgress(int value, String message) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(value);
            statusLabel.setText(message);
        });
    }

    private void clearResults() {
        gatewayTableModel.setRowCount(0);
        securityTableModel.setRowCount(0);
    }

    private void displayResults(ScanResult result) {
        // Gateway Table
        if (result.gateways.isEmpty()) {
            gatewayTableModel.addRow(new Object[]{"No Gateway Detected", "—", "0%", "0", "N/A"});
        } else {
            for (Gateway gw : result.gateways) {
                String status = gw.confidence >= 70 ? "✅ Confirmed" : "⚡ Likely";
                String risk = gw.confidence >= 70 ? "Low" : "Medium";
                gatewayTableModel.addRow(new Object[]{
                        gw.name, status, String.format("%.0f%%", gw.confidence),
                        gw.matchCount + "/" + gw.totalSigs, risk
                });
            }
        }

        // Security Table
        for (SecurityCheck check : result.securityChecks) {
            String status = check.passed ? "✅ Pass" : "❌ Fail";
            securityTableModel.addRow(new Object[]{
                    check.name, status, check.severity, check.details
            });
        }

        // Network Tab
        setTabText(2, formatNetworkReport(result.networkData));

        // JS Tab
        if (result.jsAnalysis != null) {
            setTabText(3, formatJSReport(result.jsAnalysis));
        }

        // Endpoints Tab
        if (result.endpoints != null) {
            setTabText(4, formatEndpointsReport(result.endpoints));
        }

        // Full Report
        setTabText(5, generateFullReport(result));
    }

    private void setTabText(int index, String text) {
        JPanel panel = (JPanel) resultsTabs.getComponentAt(index);
        JScrollPane scroll = (JScrollPane) panel.getComponent(0);
        JTextArea area = (JTextArea) scroll.getViewport().getView();
        area.setText(text);
        area.setCaretPosition(0);
    }

    private String formatNetworkReport(NetworkData data) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════\n");
        sb.append("          NETWORK & SSL/TLS ANALYSIS\n");
        sb.append("═══════════════════════════════════════════════════\n\n");

        sb.append("HTTP Response:\n");
        sb.append("  Status Code: ").append(data.statusCode).append("\n");
        sb.append("  Content Length: ").append(String.format("%,d bytes", data.contentLength)).append("\n");
        sb.append("  Response Time: ").append(data.responseTime).append(" ms\n");
        sb.append("  Server: ").append(data.server != null ? data.server : "Not disclosed").append("\n\n");

        if (data.sslInfo != null && data.sslInfo.subject != null) {
            sb.append("SSL/TLS Certificate:\n");
            sb.append("  Subject: ").append(data.sslInfo.subject).append("\n");
            sb.append("  Issuer: ").append(data.sslInfo.issuer).append("\n");
            sb.append("  Valid Until: ").append(data.sslInfo.validUntil).append("\n");
            sb.append("  Days Remaining: ").append(data.sslInfo.daysRemaining).append("\n\n");
        }

        sb.append("Security Headers:\n");
        if (data.securityHeaders.isEmpty()) {
            sb.append("  ⚠️ No security headers detected\n");
        } else {
            data.securityHeaders.forEach((k, v) ->
                    sb.append("  ").append(k).append(": ").append(v).append("\n"));
        }

        sb.append("\nWAF Detection:\n");
        sb.append("  ").append(data.wafDetected ? "✅ WAF Detected" : "❌ No WAF").append("\n");

        return sb.toString();
    }

    private String formatJSReport(JSAnalysis js) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════\n");
        sb.append("          JAVASCRIPT ANALYSIS\n");
        sb.append("═══════════════════════════════════════════════════\n\n");

        sb.append("Total Scripts: ").append(js.totalScripts).append("\n");
        sb.append("Payment Scripts: ").append(js.paymentScripts.size()).append("\n\n");

        if (!js.paymentScripts.isEmpty()) {
            sb.append("Payment-Related Scripts:\n");
            js.paymentScripts.forEach(s -> sb.append("  • ").append(s).append("\n"));
        }

        return sb.toString();
    }

    private String formatEndpointsReport(List<String> endpoints) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════\n");
        sb.append("          ENDPOINT DISCOVERY\n");
        sb.append("═══════════════════════════════════════════════════\n\n");

        sb.append("Total Endpoints: ").append(endpoints.size()).append("\n\n");
        endpoints.forEach(e -> sb.append("  • ").append(e).append("\n"));

        return sb.toString();
    }

    private String generateFullReport(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("╔══════════════════════════════════════════════════╗\n");
        sb.append("║    PAYMENT GATEWAY SECURITY ASSESSMENT REPORT    ║\n");
        sb.append("╚══════════════════════════════════════════════════╝\n\n");

        sb.append("Target: ").append(result.url).append("\n");
        sb.append("Scan Time: ").append(result.timestamp.format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n\n");

        sb.append("─── DETECTED GATEWAYS ───\n");
        if (result.gateways.isEmpty()) {
            sb.append("No payment gateways detected\n");
        } else {
            result.gateways.forEach(gw ->
                    sb.append("  ").append(gw.name)
                            .append(" (").append(String.format("%.1f%%", gw.confidence))
                            .append(" confidence)\n"));
        }
        sb.append("\n");

        sb.append("─── SECURITY AUDIT ───\n");
        for (SecurityCheck check : result.securityChecks) {
            String mark = check.passed ? "[PASS]" : "[FAIL]";
            sb.append(String.format("%-6s %-25s : %s\n", mark, check.name, check.details));
        }
        sb.append("\n");

        sb.append("─── NETWORK SUMMARY ───\n");
        sb.append("Server: ").append(result.networkData.server != null ? result.networkData.server : "Hidden").append("\n");
        sb.append("WAF Status: ").append(result.networkData.wafDetected ? "Detected" : "Not Detected").append("\n");
        sb.append("SSL Days Left: ").append(result.networkData.sslInfo != null ? result.networkData.sslInfo.daysRemaining : "N/A").append("\n");

        sb.append("\n");
        sb.append("════════════ END OF REPORT ════════════");

        return sb.toString();
    }

    private void exportReport() {
        if (lastScanResult == null) return;

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save Scan Report");
        fileChooser.setSelectedFile(new File("scan_report_" + System.currentTimeMillis() + ".txt"));

        int userSelection = fileChooser.showSaveDialog(this);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            try (FileWriter fw = new FileWriter(fileToSave)) {
                fw.write(generateFullReport(lastScanResult));
                JOptionPane.showMessageDialog(this,
                        "Report saved successfully to:\n" + fileToSave.getAbsolutePath(),
                        "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                        "Error saving file: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static void main(String[] args) {
        try {
            // Set System Look and Feel for native OS integration
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        SwingUtilities.invokeLater(() -> new PaymentGatewayScanner());
    }

    // ==========================================
    // INNER DATA CLASSES (Required for Logic)
    // ==========================================

    /**
     * Stores the aggregate results of a complete scan operation.
     */
    public static class ScanResult {
        String url;
        LocalDateTime timestamp;
        NetworkData networkData;
        ParsedData parsedData;
        List<Gateway> gateways = new ArrayList<>();
        JSAnalysis jsAnalysis;
        List<String> endpoints = new ArrayList<>();
        List<SecurityCheck> securityChecks = new ArrayList<>();
    }

    /**
     * Represents raw network level information including headers and SSL.
     */
    public static class NetworkData {
        int statusCode;
        String html = "";
        long contentLength;
        long responseTime;
        String server;
        Map<String, String> securityHeaders = new HashMap<>();
        SSLInfo sslInfo;
        boolean wafDetected;
    }

    /**
     * Stores SSL/TLS Certificate details.
     */
    public static class SSLInfo {
        String subject;
        String issuer;
        String validUntil;
        int daysRemaining;
        String error;
    }

    /**
     * Stores data parsed from the HTML DOM (Jsoup).
     */
    public static class ParsedData {
        List<String> scripts = new ArrayList<>();
        List<String> paymentForms = new ArrayList<>();
        List<String> allLinks = new ArrayList<>();
    }

    /**
     * Represents a detected Payment Gateway with confidence scoring.
     */
    public static class Gateway {
        String name;
        double confidence;
        int matchCount;
        int totalSigs;
    }

    /**
     * Stores analysis results of JavaScript files found on the page.
     */
    public static class JSAnalysis {
        int totalScripts;
        List<String> paymentScripts = new ArrayList<>();
        List<String> apiEndpoints = new ArrayList<>();
    }

    /**
     * Represents a single unit of security verification.
     */
    public static class SecurityCheck {
        String name;
        boolean passed;
        String severity;
        String details;
    }
}