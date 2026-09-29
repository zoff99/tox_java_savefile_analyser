import javax.swing.*;
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
import java.util.List;
import java.nio.charset.StandardCharsets;
import javax.swing.filechooser.FileNameExtensionFilter;

public class ToxSaveViewer extends JFrame {

    private List<Section> sections = new ArrayList<>();
    private byte[] fileData;
    private ChartPanel chartPanel;
    private JPanel legendPanel;
    private JTextArea detailsArea;
    private JLabel fileLabel;

    public ToxSaveViewer() {
        setTitle("Tox Save File Viewer");
        setSize(1200, 900);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton openBtn = new JButton("Open Tox Save File");
        fileLabel = new JLabel("No file loaded");
        topPanel.add(openBtn);
        topPanel.add(fileLabel);

        chartPanel = new ChartPanel();
        legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        centerPanel.add(chartPanel, BorderLayout.CENTER);
        centerPanel.add(legendPanel, BorderLayout.SOUTH);

        detailsArea = new JTextArea(15, 80);
        detailsArea.setFont(UIManager.getFont("TextArea.font"));
        detailsArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(detailsArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Section Details (Hover or click a bar)"));

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
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

    private int readLE16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off+1] & 0xFF) << 8);
    }

    private long readLE32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off+1] & 0xFFL) << 8) | ((b[off+2] & 0xFFL) << 16) | ((b[off+3] & 0xFFL) << 24);
    }

    private void updateLegend() {
        legendPanel.removeAll();
        legendPanel.add(new JLabel("Legend:"));
        for (SectionType t : SectionType.values()) {
            if (t == SectionType.UNKNOWN) continue;
            boolean used = false;
            for (Section s : sections) if (s.type == t.id) { used = true; break; }
            if (!used) continue;

            JPanel colorBox = new JPanel();
            colorBox.setBackground(t.color);
            colorBox.setBorder(BorderFactory.createLineBorder(Color.BLACK));
            colorBox.setPreferredSize(new Dimension(16, 16));
            legendPanel.add(colorBox);
            legendPanel.add(new JLabel(t.name));
        }
        legendPanel.revalidate();
        legendPanel.repaint();
    }

    private String getHexDump(byte[] data) {
        if (data == null || data.length == 0) return "Empty data\n";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 16) {
            sb.append(String.format("%08X: ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    sb.append(String.format("%02X ", data[i+j] & 0xFF));
                } else {
                    sb.append("   ");
                }
            }
            sb.append(" ");
            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    int c = data[i+j] & 0xFF;
                    sb.append((c >= 32 && c < 127) ? (char)c : '.');
                } else {
                    sb.append(" ");
                }
            }
            sb.append("\n");
            if (i > 512) {
                sb.append("... (truncated)\n");
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

        public ChartPanel() {
            setBackground(Color.LIGHT_GRAY);
            setPreferredSize(new Dimension(1000, 300));

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

        private void handleMouseMove(int mx, int my) {
            Section hovered = null;
            if (sections != null) {
                int padding = 20;
                int availableHeight = getHeight() - padding * 2;
                for (Section s : sections) {
                    if (mx >= s.x && mx < s.x + s.w && my >= padding && my < padding + availableHeight) {
                        hovered = s;
                        break;
                    }
                }
            }
            if (hovered != null) {
                setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                StringBuilder info = new StringBuilder();
                info.append("Type: ").append(hovered.typeName).append(" (").append(hovered.type).append(")\n");
                info.append("Offset: ").append(hovered.offset).append(" bytes\n");
                info.append("Data Size: ").append(hovered.length).append(" bytes\n");
                info.append("Total Size: ").append(hovered.length + 8).append(" bytes\n\n");

                boolean isAscii = true;
                for (byte b : hovered.data) {
                    int c = b & 0xFF;
                    if (c < 32 && c != 9 && c != 10 && c != 13) {
                        isAscii = false;
                        break;
                    }
                }
                if (isAscii && hovered.data.length > 0 && hovered.data.length < 1024) {
                    info.append("String Content: ").append(new String(hovered.data, StandardCharsets.UTF_8)).append("\n\n");
                }

                info.append("Content Preview (Hex/Ascii):\n");
                info.append(getHexDump(hovered.data));
                detailsArea.setText(info.toString());
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

            int padding = 20;
            int availableWidth = getWidth() - padding * 2;
            int availableHeight = getHeight() - padding * 2;

            if (availableWidth <= 0 || availableHeight <= 0) return;

            double pixelScale = availableWidth / (double) fileData.length;

            for (Section s : sections) {
                int x = padding + (int) (s.offset * pixelScale);
                int w = (int) ((s.length + 8) * pixelScale);
                if (w == 0 && (s.length + 8) > 0) w = 1;

                s.x = x;
                s.w = w;

                g2d.setColor(s.color);
                g2d.fillRect(x, padding, w, availableHeight);

                g2d.setColor(Color.BLACK);
                g2d.drawRect(x, padding, w, availableHeight);

                FontMetrics fm = g2d.getFontMetrics();
                if (w > fm.stringWidth(s.typeName) + 10) {
                    g2d.setColor(Color.BLACK);
                    int textY = padding + (availableHeight + fm.getAscent() - fm.getDescent()) / 2;
                    g2d.drawString(s.typeName, x + 5, textY);
                }
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                
                // Dynamically scale UI elements for High DPI / OS Zoom settings
                int screenRes = Toolkit.getDefaultToolkit().getScreenResolution();
                float scale = Math.max(1.25f, screenRes / 96.0f); 
                
                Font defaultFont = new Font(Font.SANS_SERIF, Font.PLAIN, 14);
                Font monoFont = new Font(Font.MONOSPACED, Font.PLAIN, 14);
                
                Font scaledDefault = defaultFont.deriveFont(defaultFont.getSize2D() * scale);
                Font scaledMono = monoFont.deriveFont(monoFont.getSize2D() * scale);
                
                UIManager.put("Label.font", scaledDefault);
                UIManager.put("Button.font", scaledDefault);
                UIManager.put("Panel.font", scaledDefault);
                UIManager.put("TextArea.font", scaledMono);
                UIManager.put("TitledBorder.font", scaledDefault);
                
            } catch (Exception e) {
                e.printStackTrace();
            }
            new ToxSaveViewer().setVisible(true);
        });
    }
}
