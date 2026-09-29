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
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Toolkit;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
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

    private static final Color[] PALETTE = {
        new Color(230, 25, 75),  new Color(60, 180, 75),  new Color(255, 225, 25),
        new Color(0, 130, 200),  new Color(245, 130, 48), new Color(145, 30, 180),
        new Color(70, 240, 240), new Color(240, 50, 230), new Color(210, 245, 60),
        new Color(250, 190, 190),new Color(0, 128, 128),  new Color(230, 190, 255),
        new Color(170, 110, 40), new Color(128, 0, 0),    new Color(170, 255, 195),
        new Color(255, 250, 200)
    };

    // Saved_Friend layout from Messenger.c (friend_size() == 2216 bytes)
    private static final int FRIEND_SIZE = 2216;
    private static final int OFF_STATUS = 0;
    private static final int OFF_REAL_PK = 1;
    private static final int OFF_INFO = 33;
    private static final int OFF_INFO_SIZE = 1058;
    private static final int OFF_NAME = 1060;
    private static final int OFF_NAME_LEN = 1188;
    private static final int OFF_STATUSMSG = 1190;
    private static final int OFF_STATUSMSG_LEN = 2198;
    private static final int OFF_USERSTATUS = 2200;
    private static final int OFF_NOSPAM = 2204;
    private static final int OFF_LASTSEEN = 2208;

    private List<Section> sections = new ArrayList<>();
    private byte[] fileData;
    private ChartPanel chartPanel;
    private ZoomPanel zoomPanel;
    private JPanel legendPanel;
    private JTextArea detailsArea;
    private JLabel fileLabel;
    private Section selectedSection;

    public ToxSaveViewer() {
        setTitle("Tox Save File Viewer");
        setSize(scale(780), scale(640));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, scale(8), scale(8)));
        JButton openBtn = new JButton("Open Tox Save File");
        fileLabel = new JLabel("No file loaded");
        topPanel.add(openBtn);
        topPanel.add(fileLabel);

        chartPanel = new ChartPanel();
        zoomPanel = new ZoomPanel();
        legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, scale(8), scale(8)));

        JPanel chartsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.weightx = 1;

        gbc.gridy = 0; gbc.weighty = 0.52; gbc.fill = GridBagConstraints.BOTH;
        chartsPanel.add(chartPanel, gbc);

        gbc.gridy = 1; gbc.weighty = 0.48; gbc.fill = GridBagConstraints.BOTH;
        chartsPanel.add(zoomPanel, gbc);

        gbc.gridy = 2; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL;
        chartsPanel.add(legendPanel, gbc);

        detailsArea = new JTextArea(18, 100);
        detailsArea.setFont(UIManager.getFont("TextArea.font"));
        detailsArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(detailsArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Details (hover the bars above, then hover the zoom blocks)"));
        scrollPane.setPreferredSize(new Dimension(scale(760), scale(230)));

        JPanel mainPanel = new JPanel(new BorderLayout(scale(10), scale(10)));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(scale(10), scale(10), scale(10), scale(10)));
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(chartsPanel, BorderLayout.CENTER);
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
            selectSection(largestSection());
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
                break;
            }
            if (lengthLong < 0 || pos + 8 + lengthLong > b.length) {
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
            buildSubItems(s);
            sections.add(s);
            pos += 8 + length;
        }
    }

    // ------------------------------------------------------------------
    //  Selection / linking between chart, zoom and legend
    // ------------------------------------------------------------------

    private void selectSection(Section s) {
        selectedSection = s;
        zoomPanel.setSection(s);
        if (s != null) {
            chartPanel.setHighlightType(s.type);
            detailsArea.setText(buildDetails(s));
            detailsArea.setCaretPosition(0);
        } else {
            chartPanel.setHighlightType(-1);
        }
    }

    private Section largestSection() {
        Section best = null;
        for (Section s : sections) {
            if (best == null || s.length > best.length) best = s;
        }
        return best;
    }

    private Section findFirstSectionOfType(int type) {
        for (Section s : sections) if (s.type == type) return s;
        return null;
    }

    // ------------------------------------------------------------------
    //  Sub-item construction (the coloured zoom blocks)
    // ------------------------------------------------------------------

    private SubItem makeItem(int offsetInFile, int length, String label, Color color, String details) {
        SubItem it = new SubItem();
        it.offsetInFile = offsetInFile;
        it.length = length;
        it.label = label;
        it.color = color;
        it.details = details;
        return it;
    }

    private void buildSubItems(Section s) {
        s.subItems = new ArrayList<>();
        byte[] d = s.data;
        int base = s.offset + 8;
        switch (s.type) {
            case 1: buildNospamKeySubItems(s); break;
            case 2: s.subItems.add(makeItem(base, d.length, "DHT state", s.color, describeDht(s))); break;
            case 3: buildFriendSubItems(s); break;
            case 4: s.subItems.add(makeItem(base, d.length, "name", s.color, describeText(d, "Self name"))); break;
            case 5: s.subItems.add(makeItem(base, d.length, "status msg", s.color, describeText(d, "Status message"))); break;
            case 6: s.subItems.add(makeItem(base, d.length, "status", s.color, describeUserStatus(d))); break;
            case 7: s.subItems.add(makeItem(base, d.length, "groups", s.color, describeGroups(s))); break;
            case 10: buildNodeSubItems(s, "TCP relay"); break;
            case 11: buildNodeSubItems(s, "Path node"); break;
            case 20: s.subItems.add(makeItem(base, d.length, "conferences", s.color, describeConferences(s))); break;
            case 255: s.subItems.add(makeItem(base, 0, "end", Color.BLACK, "End-of-save marker (no payload)")); break;
            default: s.subItems.add(makeItem(base, d.length, "data", Color.WHITE, "(unknown section)")); break;
        }
    }

    private void buildNospamKeySubItems(Section s) {
        byte[] d = s.data;
        int base = s.offset + 8;
        if (d.length >= 68) {
            long nospam = readLE32(d, 0);
            byte[] nospamBytes = Arrays.copyOfRange(d, 0, 4);
            byte[] pub = Arrays.copyOfRange(d, 4, 36);
            byte[] sec = Arrays.copyOfRange(d, 36, 68);
            String toxId = computeToxId(pub, nospamBytes);
            s.subItems.add(makeItem(base, 4, "nospam", new Color(245, 130, 48),
                "Nospam: 0x" + String.format("%08X", nospam) + "   (decimal " + nospam + ")"));
            s.subItems.add(makeItem(base + 4, 32, "public key", new Color(0, 130, 200),
                "Public key:\n" + hex(pub) + "\n\nDerived Tox ID:\n" + toxId));
            s.subItems.add(makeItem(base + 36, 32, "secret key", new Color(220, 20, 60),
                "Secret key  <-- SENSITIVE:\n" + hex(sec)));
        } else {
            s.subItems.add(makeItem(base, d.length, "keys", s.color, "(unexpected size " + d.length + ")"));
        }
    }

    private void buildFriendSubItems(Section s) {
        byte[] d = s.data;
        int base = s.offset + 8;
        int num = d.length / FRIEND_SIZE;
        for (int i = 0; i < num; i++) {
            int off = i * FRIEND_SIZE;
            int status = d[off + OFF_STATUS] & 0xFF;
            byte[] pk = Arrays.copyOfRange(d, off + OFF_REAL_PK, off + OFF_REAL_PK + 32);
            if (status >= 3) {
                int nl = readBE16(d, off + OFF_NAME_LEN);
                String name = trimNulls(new String(d, off + OFF_NAME, clampLen(nl, 128, d.length - off - OFF_NAME), StandardCharsets.UTF_8));
                int sl = readBE16(d, off + OFF_STATUSMSG_LEN);
                String sm = trimNulls(new String(d, off + OFF_STATUSMSG, clampLen(sl, 1007, d.length - off - OFF_STATUSMSG), StandardCharsets.UTF_8));
                int us = d[off + OFF_USERSTATUS] & 0xFF;
                long ls = readBE64(d, off + OFF_LASTSEEN);
                StringBuilder det = new StringBuilder();
                det.append("Friend #").append(i).append("   [CONFIRMED]\n");
                det.append("Name:           ").append(name.isEmpty() ? "(empty)" : name).append("\n");
                det.append("Status message: ").append(sm.isEmpty() ? "(empty)" : sm).append("\n");
                det.append("User status:    ").append(userStatusName(us)).append("\n");
                det.append("Public key:     ").append(hex(pk)).append("\n");
                det.append("Last seen:      ").append(formatTime(ls)).append("\n");
                s.subItems.add(makeItem(base + off, FRIEND_SIZE, name.isEmpty() ? ("friend#" + i) : name,
                        PALETTE[i % PALETTE.length], det.toString()));
            } else {
                int il = readBE16(d, off + OFF_INFO_SIZE);
                String info = trimNulls(new String(d, off + OFF_INFO, clampLen(il, 1024, d.length - off - OFF_INFO), StandardCharsets.UTF_8));
                byte[] nospam = Arrays.copyOfRange(d, off + OFF_NOSPAM, off + OFF_NOSPAM + 4);
                String toxId = computeToxId(pk, nospam);
                StringBuilder det = new StringBuilder();
                det.append("Friend #").append(i).append("   [")
                   .append(status == 1 ? "FRIEND_ADDED" : "FRIEND_REQUESTED").append(" - pending]\n");
                det.append("Request message: ").append(info.isEmpty() ? "(empty)" : info).append("\n");
                det.append("Public key:      ").append(hex(pk)).append("\n");
                det.append("Full Tox ID:     ").append(toxId).append("\n");
                s.subItems.add(makeItem(base + off, FRIEND_SIZE, "pending#" + i,
                        new Color(169, 169, 169), det.toString()));
            }
        }
        int leftover = d.length % FRIEND_SIZE;
        if (leftover > 0) {
            s.subItems.add(makeItem(base + num * FRIEND_SIZE, leftover, "pad", Color.GRAY,
                "Trailing " + leftover + " bytes (not a full friend record)"));
        }
    }

    private void buildNodeSubItems(Section s, String label) {
        byte[] d = s.data;
        int base = s.offset + 8;
        int pos = 0;
        int idx = 0;
        while (pos < d.length) {
            int family = d[pos] & 0xFF;
            if (family == 2 && pos + 39 <= d.length) {
                byte[] ip = Arrays.copyOfRange(d, pos + 1, pos + 5);
                int port = readBE16(d, pos + 5);
                byte[] key = Arrays.copyOfRange(d, pos + 7, pos + 39);
                String ipstr = formatIpv4(ip);
                s.subItems.add(makeItem(base + pos, 39, ipstr, PALETTE[idx % PALETTE.length],
                    label + " #" + idx + "\nAddress:    " + ipstr + ":" + port +
                    "\nFamily:     IPv4\nPublic key: " + hex(key)));
                pos += 39; idx++;
            } else if (isIpv6Family(family) && pos + 51 <= d.length) {
                byte[] ip = Arrays.copyOfRange(d, pos + 1, pos + 17);
                int port = readBE16(d, pos + 17);
                byte[] key = Arrays.copyOfRange(d, pos + 19, pos + 51);
                String ipstr = formatIpv6(ip);
                s.subItems.add(makeItem(base + pos, 51, ipstr, PALETTE[idx % PALETTE.length],
                    label + " #" + idx + "\nAddress:    " + ipstr + ":" + port +
                    "\nFamily:     IPv6\nPublic key: " + hex(key)));
                pos += 51; idx++;
            } else {
                if (d.length - pos > 0) {
                    s.subItems.add(makeItem(base + pos, d.length - pos, "other", Color.GRAY,
                        "Unparsed trailing data (" + (d.length - pos) + " bytes)"));
                }
                break;
            }
        }
    }

    // ------------------------------------------------------------------
    //  Text descriptions per section
    // ------------------------------------------------------------------

    private String buildDetails(Section s) {
        StringBuilder info = new StringBuilder();
        info.append("Type: ").append(s.typeName).append(" (").append(s.type).append(")\n");
        info.append("Offset: ").append(s.offset).append(" bytes\n");
        info.append("Data Size: ").append(s.length).append(" bytes\n");
        info.append("Parts: ").append(s.subItems.size()).append("\n");
        info.append("\n========== PARSED CONTENT ==========\n");
        info.append(describeSection(s));
        info.append("\n========== RAW HEX DUMP ==========\n");
        info.append(getHexDump(s.data));
        return info.toString();
    }

    private String buildSubItemDetails(Section s, SubItem it, int idx) {
        StringBuilder sb = new StringBuilder();
        sb.append("Section: ").append(s.typeName).append("\n");
        sb.append("Part ").append(idx + 1).append(" of ").append(s.subItems.size()).append("\n");
        sb.append("Offset: ").append(it.offsetInFile).append("   Size: ").append(it.length).append(" bytes\n");
        sb.append("\n").append(it.details).append("\n");
        return sb.toString();
    }

    private String describeSection(Section s) {
        switch (s.type) {
            case 1:  return describeNospamKeys(s.data);
            case 2:  return describeDht(s);
            case 3:  return describeFriends(s);
            case 4:  return describeText(s.data, "Self name");
            case 5:  return describeText(s.data, "Status message");
            case 6:  return describeUserStatus(s.data);
            case 7:  return describeGroups(s);
            case 10: return describeNodeList(s.data, "TCP relay");
            case 11: return describeNodeList(s.data, "Path node");
            case 20: return describeConferences(s);
            case 255: return "(End-of-save marker, no payload)";
            default: return "(Unknown section type)";
        }
    }

    private String describeText(byte[] d, String label) {
        if (d.length == 0) return label + ": (empty)";
        String text = trimNulls(new String(d, StandardCharsets.UTF_8));
        return label + ": \"" + text + "\"\n(" + d.length + " UTF-8 bytes)";
    }

    private String describeUserStatus(byte[] d) {
        if (d.length < 1) return "(empty)";
        return "User status: " + userStatusName(d[0] & 0xFF);
    }

    private String describeDht(Section s) {
        return "DHT state (" + s.length + " bytes).\n" +
               "Saved DHT routing data: close nodes and DHT friend entries used to\n" +
               "reconnect to the network quickly. Binary structure; see hex dump.";
    }

    private String describeFriends(Section s) {
        byte[] d = s.data;
        int num = d.length / FRIEND_SIZE;
        StringBuilder sb = new StringBuilder();
        sb.append(num).append(" friend record(s)  (each ").append(FRIEND_SIZE).append(" bytes)\n\n");
        for (int i = 0; i < num; i++) {
            int off = i * FRIEND_SIZE;
            int status = d[off + OFF_STATUS] & 0xFF;
            byte[] pk = Arrays.copyOfRange(d, off + OFF_REAL_PK, off + OFF_REAL_PK + 32);
            if (status >= 3) {
                int nl = readBE16(d, off + OFF_NAME_LEN);
                String name = trimNulls(new String(d, off + OFF_NAME, clampLen(nl, 128, d.length - off - OFF_NAME), StandardCharsets.UTF_8));
                int sl = readBE16(d, off + OFF_STATUSMSG_LEN);
                String sm = trimNulls(new String(d, off + OFF_STATUSMSG, clampLen(sl, 1007, d.length - off - OFF_STATUSMSG), StandardCharsets.UTF_8));
                int us = d[off + OFF_USERSTATUS] & 0xFF;
                long ls = readBE64(d, off + OFF_LASTSEEN);
                sb.append("[").append(i).append("] CONFIRMED  name=\"").append(name)
                  .append("\"  status=").append(userStatusName(us))
                  .append("  lastSeen=").append(formatTime(ls)).append("\n");
                sb.append("      msg=\"").append(sm).append("\"\n");
                sb.append("      pubkey=").append(hex(pk)).append("\n");
            } else {
                int il = readBE16(d, off + OFF_INFO_SIZE);
                String info = trimNulls(new String(d, off + OFF_INFO, clampLen(il, 1024, d.length - off - OFF_INFO), StandardCharsets.UTF_8));
                byte[] nospam = Arrays.copyOfRange(d, off + OFF_NOSPAM, off + OFF_NOSPAM + 4);
                sb.append("[").append(i).append("] ").append(status == 1 ? "ADDED" : "REQUESTED")
                  .append("(pending)  msg=\"").append(info).append("\"\n");
                sb.append("      pubkey=").append(hex(pk)).append("\n");
                sb.append("      toxId=").append(computeToxId(pk, nospam)).append("\n");
            }
        }
        return sb.toString();
    }

    private String describeGroups(Section s) {
        byte[] d = s.data;
        StringBuilder sb = new StringBuilder();
        sb.append("Group chats (NGC), msgpack-encoded (" + d.length + " bytes).\n");
        if (d.length > 0) {
            int b0 = d[0] & 0xFF;
            if (b0 >= 0x90 && b0 <= 0x9f) {
                sb.append("Best effort: msgpack array with " + (b0 & 0x0f) + " group(s).\n");
            } else if (b0 == 0xdc && d.length >= 3) {
                sb.append("Best effort: msgpack array with " + readBE16(d, 1) + " group(s).\n");
            } else {
                sb.append("(First byte 0x" + String.format("%02X", b0) + "; could not detect array header.)\n");
            }
        }
        sb.append("See raw hex dump below.");
        return sb.toString();
    }

    private String describeConferences(Section s) {
        return "Conferences (classic audio/text) (" + s.length + " bytes).\n" +
               "Saved conference state. See raw hex dump below.";
    }

    private String describeNospamKeys(byte[] d) {
        if (d.length < 68) return "(Expected at least 68 bytes, got " + d.length + ")";
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
        return sb.toString();
    }

    private String describeNodeList(byte[] d, String label) {
        int pos = 0;
        int count = 0;
        StringBuilder sb = new StringBuilder();
        while (pos < d.length) {
            int family = d[pos] & 0xFF;
            if (family == 2 && pos + 39 <= d.length) {
                byte[] ip = Arrays.copyOfRange(d, pos + 1, pos + 5);
                int port = readBE16(d, pos + 5);
                byte[] key = Arrays.copyOfRange(d, pos + 7, pos + 39);
                sb.append("  [").append(count).append("] ").append(formatIpv4(ip)).append(":").append(port)
                  .append("   key=").append(hex(key)).append("\n");
                pos += 39; count++;
            } else if (isIpv6Family(family) && pos + 51 <= d.length) {
                byte[] ip = Arrays.copyOfRange(d, pos + 1, pos + 17);
                int port = readBE16(d, pos + 17);
                byte[] key = Arrays.copyOfRange(d, pos + 19, pos + 51);
                sb.append("  [").append(count).append("] ").append(formatIpv6(ip)).append(":").append(port)
                  .append("   key=").append(hex(key)).append("\n");
                pos += 51; count++;
            } else {
                break;
            }
        }
        return count + " " + label + "(s)\n" + sb.toString();
    }

    // ------------------------------------------------------------------
    //  Tox ID + helpers
    // ------------------------------------------------------------------

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
            checksum ^= (data[i] & 0xFF) | ((data[i + 1] & 0xFF) << 8);
        }
        return checksum & 0xFFFF;
    }

    private String userStatusName(int st) {
        switch (st) {
            case 0: return "NONE/Online";
            case 1: return "AWAY";
            case 2: return "BUSY";
            default: return "Unknown(" + st + ")";
        }
    }

    private String formatTime(long unixSeconds) {
        if (unixSeconds <= 0) return "(never)";
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            return sdf.format(new Date(unixSeconds * 1000L)) + "  (unix " + unixSeconds + ")";
        } catch (Exception e) {
            return "unix " + unixSeconds;
        }
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

    private String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private String trimNulls(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '\0') end--;
        return s.substring(0, end);
    }

    private int clampLen(int requested, int maxField, int available) {
        int len = Math.min(requested, maxField);
        len = Math.min(len, available);
        return Math.max(len, 0);
    }

    private int readLE16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private long readLE32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8) | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }

    private int readBE16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private long readBE32(byte[] b, int off) {
        return ((b[off] & 0xFFL) << 24) | ((b[off + 1] & 0xFFL) << 16) | ((b[off + 2] & 0xFFL) << 8) | (b[off + 3] & 0xFFL);
    }

    private long readBE64(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[off + i] & 0xFF);
        return v;
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
                    Section s = findFirstSectionOfType(st.id);
                    if (s != null) selectSection(s);
                }
                @Override
                public void mouseClicked(MouseEvent e) {
                    Section s = findFirstSectionOfType(st.id);
                    if (s != null) selectSection(s);
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
                if (i + j < data.length) sb.append(String.format("%02X ", data[i + j] & 0xFF));
                else sb.append("   ");
            }
            sb.append(" ");
            for (int j = 0; j < 16; j++) {
                if (i + j < data.length) {
                    int c = data[i + j] & 0xFF;
                    sb.append((c >= 32 && c < 127) ? (char) c : '.');
                } else sb.append(" ");
            }
            sb.append("\n");
            if (i > 512) {
                sb.append("... (hex dump truncated)\n");
                break;
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    //  Model classes
    // ------------------------------------------------------------------

    class Section {
        int offset;
        int length;
        int type;
        String typeName;
        Color color;
        byte[] data;
        int x, w;
        List<SubItem> subItems = new ArrayList<>();
    }

    class SubItem {
        int offsetInFile;
        int length;
        String label;
        Color color;
        String details;
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
            for (SectionType t : values()) if (t.id == id) return t;
            return UNKNOWN;
        }
    }

    // ------------------------------------------------------------------
    //  Top chart: one bar per section
    // ------------------------------------------------------------------

    class ChartPanel extends JPanel {
        List<Section> sections;
        byte[] fileData;
        private final int pad = scale(20);
        private int highlightType = -1;
        private Section lastHovered;

        public ChartPanel() {
            setBackground(Color.LIGHT_GRAY);
            setPreferredSize(new Dimension(scale(700), scale(180)));
            MouseAdapter ma = new MouseAdapter() {
                @Override
                public void mouseMoved(MouseEvent e) { handleMouseMove(e.getX(), e.getY()); }
                @Override
                public void mouseClicked(MouseEvent e) { handleMouseMove(e.getX(), e.getY()); }
            };
            addMouseMotionListener(ma);
            addMouseListener(ma);
        }

        public void setData(byte[] data, List<Section> sections) {
            this.fileData = data;
            this.sections = sections;
            this.lastHovered = null;
            repaint();
        }

        public void setHighlightType(int type) {
            if (this.highlightType != type) {
                this.highlightType = type;
                repaint();
            }
        }

        private void handleMouseMove(int mx, int my) {
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
                if (hovered != lastHovered) {
                    lastHovered = hovered;
                    selectSection(hovered);
                }
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

    // ------------------------------------------------------------------
    //  Zoom chart: sub-blocks of the selected section
    // ------------------------------------------------------------------

    class ZoomPanel extends JPanel {
        Section section;
        List<SubItem> items;
        int hoveredIndex = -1;

        public ZoomPanel() {
            setBackground(new Color(245, 245, 245));
            setPreferredSize(new Dimension(scale(700), scale(150)));
            MouseAdapter ma = new MouseAdapter() {
                @Override
                public void mouseMoved(MouseEvent e) { handleZoomMouse(e.getX(), e.getY()); }
                @Override
                public void mouseClicked(MouseEvent e) { handleZoomMouse(e.getX(), e.getY()); }
                @Override
                public void mouseExited(MouseEvent e) {
                    hoveredIndex = -1;
                    if (section != null) {
                        detailsArea.setText(buildDetails(section));
                        detailsArea.setCaretPosition(0);
                    }
                    repaint();
                }
            };
            addMouseMotionListener(ma);
            addMouseListener(ma);
        }

        public void setSection(Section s) {
            this.section = s;
            this.items = (s != null) ? s.subItems : null;
            this.hoveredIndex = -1;
            repaint();
        }

        private int zoomPad() { return scale(15); }
        private int zoomTopY() { return zoomPad() + scale(18); }
        private int zoomBarH() { return Math.max(getHeight() - zoomTopY() - zoomPad(), scale(24)); }

        private void handleZoomMouse(int mx, int my) {
            if (items == null || items.isEmpty()) {
                if (section != null) {
                    detailsArea.setText(buildDetails(section));
                    detailsArea.setCaretPosition(0);
                }
                return;
            }
            int idx = -1;
            int topY = zoomTopY();
            int barH = zoomBarH();
            for (int i = 0; i < items.size(); i++) {
                SubItem it = items.get(i);
                if (mx >= it.x && mx < it.x + it.w && my >= topY && my < topY + barH) {
                    idx = i;
                    break;
                }
            }
            if (idx != hoveredIndex) {
                hoveredIndex = idx;
                repaint();
            }
            if (idx >= 0) {
                setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                detailsArea.setText(buildSubItemDetails(section, items.get(idx), idx));
                detailsArea.setCaretPosition(0);
            } else {
                setCursor(Cursor.getDefaultCursor());
                detailsArea.setText(buildDetails(section));
                detailsArea.setCaretPosition(0);
            }
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2d = (Graphics2D) g;
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            int pad = zoomPad();
            g2d.setColor(Color.DARK_GRAY);

            if (section == null) {
                g2d.drawString("Zoom: hover a section bar above to inspect its contents", pad, getHeight() / 2);
                return;
            }

            g2d.drawString("Zoom: " + section.typeName + "  (" + section.length + " bytes, " +
                    (items == null ? 0 : items.size()) + " parts)", pad, pad + scale(4));

            if (items == null || items.isEmpty()) return;

            int topY = zoomTopY();
            int barH = zoomBarH();
            int availW = getWidth() - pad * 2;
            if (availW <= 0) return;

            long total = 0;
            for (SubItem it : items) total += it.length;
            if (total == 0) total = 1;

            int x = pad;
            for (int i = 0; i < items.size(); i++) {
                SubItem it = items.get(i);
                int w = (int) (availW * (it.length / (double) total));
                if (w == 0 && it.length > 0) w = 1;
                it.x = x;
                it.w = w;
                boolean hovered = (i == hoveredIndex);

                g2d.setColor(it.color);
                g2d.fillRect(x, topY, w, barH);
                if (hovered) {
                    g2d.setColor(new Color(255, 200, 0));
                    g2d.setStroke(new BasicStroke(3f));
                    g2d.drawRect(x, topY, w, barH);
                    g2d.setStroke(new BasicStroke(1f));
                } else {
                    g2d.setColor(Color.BLACK);
                    g2d.drawRect(x, topY, w, barH);
                }

                FontMetrics fm = g2d.getFontMetrics();
                if (w > fm.stringWidth(it.label) + 8) {
                    g2d.setColor(Color.BLACK);
                    int ty = topY + (barH + fm.getAscent() - fm.getDescent()) / 2;
                    g2d.drawString(it.label, x + 4, ty);
                }
                x += w;
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
