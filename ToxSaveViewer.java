import javax.swing.*;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.nio.charset.StandardCharsets;
import javax.swing.filechooser.FileNameExtensionFilter;

public class ToxSaveViewer extends JFrame {

    // ============================================================
    // Change this single value to make the entire UI larger or smaller.
    //   1.0 = base size, 1.8 = 80% larger, 2.5 = 150% larger, 0.8 = smaller
    // ============================================================
    private static final float GLOBAL_SCALE = 1.8f;

    private static int scale(int base) {
        return Math.round(base * GLOBAL_SCALE);
    }

    private List<Section> sections = new ArrayList<>();
    private byte[] fileData;
    private ChartPanel chartPanel;
    private JPanel legendPanel;
    private JTextArea detailsArea;
    private JLabel fileLabel;

    public ToxSaveViewer() {
        setTitle("Tox Save File Viewer");
        setSize(scale(820), scale(640));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, scale(8), scale(8)));
        JButton openBtn = new JButton("Open Tox Save File");
        fileLabel = new JLabel("No file loaded");
        topPanel.add(openBtn);
        topPanel.add(fileLabel);

        chartPanel = new ChartPanel();
        legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, scale(8), scale(8)));

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBorder(BorderFactory.createEmptyBorder(scale(10), scale(10), scale(10), scale(10)));
        centerPanel.add(chartPanel, BorderLayout.CENTER);
        centerPanel.add(legendPanel, BorderLayout.SOUTH);

        detailsArea = new JTextArea(20, 100);
        detailsArea.setFont(UIManager.getFont("TextArea.font"));
        detailsArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(detailsArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Section Details (Hover or click a bar / legend item)"));

        JPanel mainPanel = new JPanel(new BorderLayout(scale(10), scale(10)));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(scale(10), scale(10), scale(10), scale(10)));
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(centerPanel, BorderLayout.CENTER);
        mainPanel.add(scrollPane, BorderLayout.SOUTH);

        add(mainPanel);

        openBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setFileFilter(new FileNameExtensionFilter("Tox Save Files (*.tox)", "tox"));
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                loadFile(fc.getSelectedFile());
            }
        });
    }

    private void loadFile(File f) {
        try (FileInputStream fis = new FileInputStream(f)) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[16384];
            while ((nRead = fis.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            fileData = buffer.toByteArray();

            parseData(fileData);
            fileLabel.setText(f.getName() + " (" + fileData.length + " bytes)");
            chartPanel.setData(fileData, sections);
            chartPanel.setHighlightType(-1);
            updateLegend();
            detailsArea.setText("");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error loading file: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void parseData(byte[] b) {
        sections = new ArrayList<>();
        if (b.length < 8) {
            throw new RuntimeException("File too small");
        }

        long magic1 = readLE32(b, 0);
        long magic2 = readLE32(b, 4);

        if (magic1 != 0 || magic2 != 0x15ed1b1fL) {
            String mHex = String.format("%02X %02X %02X %02X %02X %02X %02X %02X",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
            throw new RuntimeException("Invalid header. File is either encrypted or not a Tox save file.\n" +
                    "Expected: 00 00 00 00 1F 1B ED 15\n" +
                    "Got: " + mHex);
        }

        int pos = 8;
        while (pos + 8 <= b.length) {
            long lengthLong = readLE32(b, pos);
            int type = readLE16(b, pos + 4);
            int cookie = readLE16(b, pos + 6);

            if (cookie != 0x01ce) {
                System.err.println("Warning: Invalid section cookie at offset " + pos);
                break;
            }

            if (lengthLong < 0 || pos + 8 + lengthLong > b.length) {
                System.err.println("Warning: Truncated or invalid section at offset " + pos);
                break;
            }

            int length = (int) lengthLong;

            Section s = new Section();
            s.offset = pos;
            s.length = length;
            s.type = type;
            s.data = new byte[length];
            if (length > 0) {
                System.arraycopy(b, pos + 8, s.data, 0, length);
            }

            SectionType st = SectionType.fromId(type);
            s.typeName = st.name;
            s.color = st.color;

            sections.add(s);
            pos += 8 + length;
        }
    }

    // ------------------------------------------------------------------
    //  Detailed content decoding per section type
    // ------------------------------------------------------------------

    private String buildDetails(Section s) {
        StringBuilder info = new StringBuilder();
        info.append("Type: ").append(s.typeName).append(" (").append(s.type).append(")\n");
        info.append("Offset: ").append(s.offset).append(" bytes\n");
        info.append("Data Size: ").append(s.length).append(" bytes\n");
        info.append("Total Size: ").append(s.length + 8).append(" bytes\n");
        info.append("\n========== PARSED CONTENT ==========\n");
        info.append(describeSection(s));
        info.append("\n========== RAW HEX DUMP ==========\n");
        info.append(getHexDump(s.data));
        return info.toString();
    }

    // Legend items use the SAME output as the bars. If a type appears more
    // than once, every occurrence is listed with the identical format.
    private String buildDetailsForType(SectionType st) {
        List<Section> matches = new ArrayList<>();
        for (Section s : sections) {
            if (s.type == st.id) matches.add(s);
        }
        if (matches.isEmpty()) {
            return "No section of type " + st.name + " is present in this file.";
        }
        if (matches.size() == 1) {
            return buildDetails(matches.get(0));
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < matches.size(); i++) {
            sb.append("########## Occurrence ").append(i + 1)
              .append(" of ").append(matches.size()).append(" ##########\n");
            sb.append(buildDetails(matches.get(i)));
            sb.append("\n\n");
        }
        return sb.toString();
    }

    private String describeSection(Section s) {
        byte[] d = s.data;
        switch (s.type) {
            case 1:  return describeNospamKeys(d);
            case 2:  return describeNodeList(d, "DHT node");
            case 3:  return describeFriends(d);
            case 4:  return describeText(d, "Self name");
            case 5:  return describeText(d, "Status message");
            case 6:  return describeUserStatus(d);
            case 7:  return describeGroups(d);
            case 10: return describeNodeList(d, "TCP relay");
            case 11: return describeNodeList(d, "Path node");
            case 20: return describeConferences(d);
            case 255: return "(End-of-save marker, no payload)";
            default: return "(Unknown section type)";
        }
    }

    private String describeText(byte[] d, String label) {
        if (d.length == 0) return label + ": (empty)";
        String text = new String(d, StandardCharsets.UTF_8);
        return label + ": \"" + text + "\"\n(" + d.length + " UTF-8 bytes)";
    }

    private String describeUserStatus(byte[] d) {
        if (d.length < 1) return "(empty)";
        int st = d[0] & 0xFF;
        String name;
        switch (st) {
            case 0:  name = "NONE (appears Online)"; break;
            case 1:  name = "AWAY"; break;
            case 2:  name = "BUSY"; break;
            default: name = "Unknown (" + st + ")"; break;
        }
        return "User status: " + name;
    }

    private String describeNospamKeys(byte[] d) {
        if (d.length < 68) {
            return "(Expected at least 68 bytes for keys, got " + d.length + ")\n";
        }
        long nospam = readLE32(d, 0);
        byte[] nospamBytes = Arrays.copyOfRange(d, 0, 4);
        byte[] pub = Arrays.copyOfRange(d, 4, 36);
        byte[] sec = Arrays.copyOfRange(d, 36, 68);

        StringBuilder sb = new StringBuilder();
        sb.append("Nospam:      0x").append(String.format("%08X", nospam))
          .append("   (decimal ").append(nospam).append(")\n");
        sb.append("Public key:  ").append(hex(pub)).append("\n");
        sb.append("Secret key:  ").append(hex(sec)).append("   <-- sensitive\n");
        sb.append("\nDerived Tox ID:\n  ").append(computeToxId(pub, nospamBytes)).append("\n");
        if (d.length > 68) {
            sb.append("\n(").append(d.length - 68).append(" extra bytes beyond standard keys)\n");
        }
        return sb.toString();
    }

    private String computeToxId(byte[] pub, byte[] nospamBytes) {
        byte[] id = new byte[38];
        System.arraycopy(pub, 0, id, 0, 32);
        System.arraycopy(nospamBytes, 0, id, 32, 4);
        int checksum = checksum16(id, 36);
        id[36] = (byte) (checksum & 0xFF);
        id[37] = (byte) ((checksum >> 8) & 0xFF);
        return hex(id);
    }

    private int checksum16(byte[] data, int len) {
        int checksum = 0;
        for (int i = 0; i + 1 < len; i += 2) {
            int value = (data[i] & 0xFF) | ((data[i + 1] & 0xFF) << 8);
            checksum ^= value;
        }
        return checksum & 0xFFFF;
    }

    private String describeNodeList(byte[] d, String label) {
        int pos = 0;
        List<String> nodes = new ArrayList<>();
        while (pos < d.length) {
            int family = d[pos] & 0xFF;
            if (family == 2 && pos + 39 <= d.length) {
                byte[] ip = Arrays.copyOfRange(d, pos + 1, pos + 5);
                int port = ((d[pos + 5] & 0xFF) << 8) | (d[pos + 6] & 0xFF);
                byte[] key = Arrays.copyOfRange(d, pos + 7, pos + 39);
                nodes.add(formatIpv4(ip) + ":" + port + "   key=" + hex(key));
                pos += 39;
            } else if (isIpv6Family(family) && pos + 51 <= d.length) {
                byte[] ip = Arrays.copyOfRange(d, pos + 1, pos + 17);
                int port = ((d[pos + 17] & 0xFF) << 8) | (d[pos + 18] & 0xFF);
                byte[] key = Arrays.copyOfRange(d, pos + 19, pos + 51);
                nodes.add(formatIpv6(ip) + ":" + port + "   key=" + hex(key));
                pos += 51;
            } else {
                break;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append(nodes.size()).append(" ").append(label).append("(s) saved\n");
        for (int i = 0; i < nodes.size(); i++) {
            sb.append("  [").append(i).append("] ").append(nodes.get(i)).append("\n");
        }
        if (pos < d.length) {
            sb.append("(Note: ").append(d.length - pos).append(" trailing bytes not parsed as nodes)\n");
        }
        return sb.toString();
    }

    private boolean isIpv6Family(int family) {
        return family == 10 || family == 23 || family == 28 || family == 30;
    }

    private String formatIpv4(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    private String formatIpv6(byte[] ip) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x%02x", ip[i], ip[i + 1]));
        }
        return "[" + sb + "]";
    }

    private String describeFriends(byte[] d) {
        return "Friend list (" + d.length + " bytes).\n" +
               "Contains one record per friend: status, public key, name, status message,\n" +
               "user status, DHT node cache, and file-transfer state. This is a nested\n" +
               "binary structure; see the raw hex dump below for the full data.";
    }

    private String describeGroups(byte[] d) {
        return "Group chats (" + d.length + " bytes).\n" +
               "Stores saved group/conference membership and state. Nested binary\n" +
               "structure; see raw hex dump below.";
    }

    private String describeConferences(byte[] d) {
        return "Conferences (" + d.length + " bytes).\n" +
               "Stores saved audio/text conference state. Nested binary structure;\n" +
               "see raw hex dump below.";
    }

    private String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private int readLE16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private long readLE32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8) | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }

    private void updateLegend() {
        legendPanel.removeAll();
        legendPanel.add(new JLabel("Legend:"));
        Cursor hand = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);

        for (SectionType t : SectionType.values()) {
            if (t == SectionType.UNKNOWN) continue;
            boolean used = false;
            for (Section s : sections) if (s.type == t.id) { used = true; break; }
            if (!used) continue;

            JPanel item = new JPanel(new FlowLayout(FlowLayout.LEFT, scale(4), 0));
            item.setOpaque(false);
            item.setCursor(hand);

            JPanel colorBox = new JPanel();
            colorBox.setBackground(t.color);
            colorBox.setBorder(BorderFactory.createLineBorder(Color.BLACK));
            colorBox.setPreferredSize(new Dimension(scale(16), scale(16)));
            colorBox.setCursor(hand);

            JLabel label = new JLabel(t.name);
            label.setCursor(hand);

            item.add(colorBox);
            item.add(label);

            final SectionType st = t;
            MouseAdapter ma = new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    chartPanel.setHighlightType(st.id);
                    detailsArea.setText(buildDetailsForType(st));
                    detailsArea.setCaretPosition(0);
                }
                @Override
                public void mouseExited(MouseEvent e) {
                    chartPanel.setHighlightType(-1);
                }
                @Override
                public void mouseClicked(MouseEvent e) {
                    chartPanel.setHighlightType(st.id);
                    detailsArea.setText(buildDetailsForType(st));
                    detailsArea.setCaretPosition(0);
                }
            };
            item.addMouseListener(ma);
            colorBox.addMouseListener(ma);
            label.addMouseListener(ma);

            legendPanel.add(item);
        }
        legendPanel.revalidate();
        legendPanel.repaint();
    }

    private String getHexDump(byte[] data) {
        if (data == null || data.length == 0) return "(empty)\n";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 16) {
            sb.append(String.format("%08X: ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    sb.append(String.format("%02X ", data[i + j] & 0xFF));
                } else {
                    sb.append("   ");
                }
            }
            sb.append(" ");
            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    int c = data[i + j] & 0xFF;
                    sb.append((c >= 32 && c < 127) ? (char) c : '.');
                } else {
                    sb.append(" ");
                }
            }
            sb.append("\n");
            if (i > 512) {
                sb.append("... (hex dump truncated, parsed content above is complete)\n");
                break;
            }
        }
        return sb.toString();
    }

    class Section {
        int offset;
        int length;
        int type;
        String typeName;
        Color color;
        byte[] data;
        int x, w;
    }

    enum SectionType {
        NOSPAMKEYS(1, "NOSPAM & KEYS", new Color(255, 99, 71)),
        DHT(2, "DHT NODES", new Color(60, 179, 113)),
        FRIENDS(3, "FRIENDS", new Color(70, 130, 180)),
        NAME(4, "NAME", new Color(255, 215, 0)),
        STATUSMESSAGE(5, "STATUS MSG", new Color(186, 85, 211)),
        STATUS(6, "STATUS", new Color(0, 191, 255)),
        GROUPS(7, "GROUPS", new Color(255, 140, 0)),
        TCP_RELAY(10, "TCP RELAYS", new Color(147, 112, 219)),
        PATH_NODE(11, "PATH NODE", new Color(169, 169, 169)),
        CONFERENCES(20, "CONFERENCES", new Color(0, 128, 128)),
        END(255, "END", new Color(0, 0, 0)),
        UNKNOWN(-1, "UNKNOWN", new Color(255, 255, 255));

        final int id;
        final String name;
        final Color color;

        SectionType(int id, String name, Color color) {
            this.id = id;
            this.name = name;
            this.color = color;
        }

        public static SectionType fromId(int id) {
            for (SectionType t : values()) {
                if (t.id == id) return t;
            }
            return UNKNOWN;
        }
    }

    class ChartPanel extends JPanel {
        List<Section> sections;
        byte[] fileData;
        private final int pad = scale(20);
        private int highlightType = -1;

        public ChartPanel() {
            setBackground(Color.LIGHT_GRAY);
            setPreferredSize(new Dimension(scale(700), scale(260)));

            MouseAdapter ma = new MouseAdapter() {
                @Override
                public void mouseMoved(MouseEvent e) {
                    handleMouseMove(e.getX(), e.getY());
                }
                @Override
                public void mouseClicked(MouseEvent e) {
                    handleMouseMove(e.getX(), e.getY());
                }
            };
            addMouseMotionListener(ma);
            addMouseListener(ma);
        }

        public void setData(byte[] data, List<Section> sections) {
            this.fileData = data;
            this.sections = sections;
            repaint();
        }

        public void setHighlightType(int type) {
            if (this.highlightType != type) {
                this.highlightType = type;
                repaint();
            }
        }

        private void handleMouseMove(int mx, int my) {
            setHighlightType(-1);

            Section hovered = null;
            if (sections != null) {
                int availableHeight = getHeight() - pad * 2;
                for (Section s : sections) {
                    if (mx >= s.x && mx < s.x + s.w && my >= pad && my < pad + availableHeight) {
                        hovered = s;
                        break;
                    }
                }
            }
            if (hovered != null) {
                setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                detailsArea.setText(buildDetails(hovered));
                detailsArea.setCaretPosition(0);
            } else {
                setCursor(Cursor.getDefaultCursor());
            }
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (fileData == null || fileData.length == 0) return;

            Graphics2D g2d = (Graphics2D) g;
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            int availableWidth = getWidth() - pad * 2;
            int availableHeight = getHeight() - pad * 2;

            if (availableWidth <= 0 || availableHeight <= 0) return;

            double pixelScale = availableWidth / (double) fileData.length;
            boolean highlighting = highlightType >= 0;

            for (Section s : sections) {
                int x = pad + (int) (s.offset * pixelScale);
                int w = (int) ((s.length + 8) * pixelScale);
                if (w == 0 && (s.length + 8) > 0) w = 1;

                s.x = x;
                s.w = w;

                boolean isMatch = s.type == highlightType;
                boolean dim = highlighting && !isMatch;

                g2d.setColor(dim ? new Color(210, 210, 210) : s.color);
                g2d.fillRect(x, pad, w, availableHeight);

                g2d.setColor(dim ? Color.GRAY : Color.BLACK);
                g2d.drawRect(x, pad, w, availableHeight);

                FontMetrics fm = g2d.getFontMetrics();
                if (!dim && w > fm.stringWidth(s.typeName) + 10) {
                    g2d.setColor(Color.BLACK);
                    int textY = pad + (availableHeight + fm.getAscent() - fm.getDescent()) / 2;
                    g2d.drawString(s.typeName, x + 5, textY);
                }

                if (isMatch) {
                    g2d.setColor(new Color(255, 200, 0));
                    g2d.setStroke(new BasicStroke(3f));
                    g2d.drawRect(x + 1, pad + 1, Math.max(w - 2, 1), availableHeight - 2);
                    g2d.setStroke(new BasicStroke(1f));
                }
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

                int screenRes = Toolkit.getDefaultToolkit().getScreenResolution();
                float dpiScale = Math.max(1.0f, screenRes / 96.0f);
                float fontScale = dpiScale * GLOBAL_SCALE;

                Font scaledDefault = new Font(Font.SANS_SERIF, Font.PLAIN, 14).deriveFont(14f * fontScale);
                Font scaledMono = new Font(Font.MONOSPACED, Font.PLAIN, 14).deriveFont(14f * fontScale);

                UIManager.put("Label.font", scaledDefault);
                UIManager.put("Button.font", scaledDefault);
                UIManager.put("Panel.font", scaledDefault);
                UIManager.put("TextArea.font", scaledMono);
                UIManager.put("TitledBorder.font", scaledDefault);

            } catch (Exception e) {
                e.printStackTrace();
            }

            ToxSaveViewer viewer = new ToxSaveViewer();

            if (args.length > 0) {
                File fileToOpen = new File(args[0]);
                if (fileToOpen.exists() && fileToOpen.isFile()) {
                    viewer.loadFile(fileToOpen);
                } else {
                    System.err.println("Specified file does not exist: " + args[0]);
                }
            }

            viewer.setVisible(true);
        });
    }
}
