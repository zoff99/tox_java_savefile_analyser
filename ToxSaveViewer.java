import javax.swing.*;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.nio.charset.StandardCharsets;
import javax.swing.filechooser.FileNameExtensionFilter;

public class ToxSaveViewer extends JFrame {

    private static final float GLOBAL_SCALE = 1.8f;
    private static final int MAIN_CHART_HEIGHT = 56;
    private static final int ZOOM_CHART_HEIGHT = 68;

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

    private static final int FAM_IPV4 = 2;
    private static final int FAM_IPV6 = 10;
    private static final int FAM_TCP_IPV4 = 130;
    private static final int FAM_TCP_IPV6 = 138;

    private static final long DHT_STATE_COOKIE_GLOBAL = 0x159000dL;
    private static final int DHT_STATE_COOKIE_TYPE = 0x11ce;
    private static final int DHT_STATE_TYPE_NODES = 4;

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

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, scale(8), scale(4)));
        JButton openBtn = new JButton("Open Tox Save File");
        fileLabel = new JLabel("No file loaded");
        topPanel.add(openBtn);
        topPanel.add(fileLabel);

        chartPanel = new ChartPanel();
        zoomPanel = new ZoomPanel();
        legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, scale(8), scale(8)));

        JPanel northPanel = new JPanel();
        northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));
        topPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        chartPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        zoomPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        legendPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        northPanel.add(topPanel);
        northPanel.add(chartPanel);
        northPanel.add(zoomPanel);
        northPanel.add(legendPanel);

        detailsArea = new JTextArea(18, 100);
        detailsArea.setFont(UIManager.getFont("TextArea.font"));
        detailsArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(detailsArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Details (hover the bars above, then hover the zoom blocks)"));

        JPanel mainPanel = new JPanel(new BorderLayout(scale(8), scale(8)));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(scale(8), scale(8), scale(8), scale(8)));
        mainPanel.add(northPanel, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);

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

            if (cookie != 0x01ce) break;
            if (lengthLong < 0 || pos + 8 + lengthLong > b.length) break;

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

    private void selectSection(Section s) {
        if (s == selectedSection) {
            zoomPanel.setSection(s);
            return;
        }
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
            case 2: buildDhtSubItems(s); break;
            case 3: buildFriendSubItems(s); break;
            case 4: s.subItems.add(makeItem(base, d.length, "name", s.color, describeText(d, "Self name"))); break;
            case 5: s.subItems.add(makeItem(base, d.length, "status msg", s.color, describeText(d, "Status message"))); break;
            case 6: s.subItems.add(makeItem(base, d.length, "status", s.color, describeUserStatus(d))); break;
            case 7: buildGroupSubItems(s); break;
            case 10: buildNodeSubItems(s, "TCP relay", false); break;
            case 11: buildNodeSubItems(s, "Path node", false); break;
            case 20: buildConferenceSubItems(s); break;
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

    private void buildDhtSubItems(Section s) {
        byte[] d = s.data;
        int base = s.offset + 8;
        int pos = 0;

        if (d.length >= 4 && readLE32(d, 0) == DHT_STATE_COOKIE_GLOBAL) {
            pos = 4;
            s.subItems.add(makeItem(base, 4, "DHT cookie", new Color(200, 200, 200),
                "DHT_STATE_COOKIE_GLOBAL = 0x159000d\n(verifies this is a DHT state blob)"));
        } else {
            s.subItems.add(makeItem(base, d.length, "DHT data", s.color, describeDht(s)));
            return;
        }

        while (pos + 8 <= d.length) {
            long lenLong = readLE32(d, pos);
            int type = readLE16(d, pos + 4);
            int cookie = readLE16(d, pos + 6);
            if (cookie != DHT_STATE_COOKIE_TYPE || lenLong < 0 || pos + 8 + lenLong > d.length) {
                break;
            }
            int len = (int) lenLong;
            if (type == DHT_STATE_TYPE_NODES) {
                s.subItems.add(makeItem(base + pos, 8, "nodes header", new Color(160, 160, 160),
                    "DHT sub-section header\ncookie=0x11ce, type=4 (NODES), length=" + len));
                buildNodeSubItemsAt(s, d, pos + 8, len, base + pos + 8, "DHT node");
            } else {
                byte[] blob = Arrays.copyOfRange(d, pos + 8, pos + 8 + len);
                s.subItems.add(makeItem(base + pos, 8 + len, "subsec#" + type, Color.GRAY,
                    "Unknown DHT sub-section type " + type + " (" + len + " bytes)\n" + getHexDump(blob)));
            }
            pos += 8 + len;
        }
        if (pos < d.length) {
            s.subItems.add(makeItem(base + pos, d.length - pos, "tail", Color.GRAY,
                "Trailing " + (d.length - pos) + " bytes not parsed"));
        }
    }

    private void buildNodeSubItems(Section s, String label, boolean tcpEnabled) {
        buildNodeSubItemsAt(s, s.data, 0, s.data.length, s.offset + 8, label);
    }

    private void buildNodeSubItemsAt(Section s, byte[] d, int off, int len, int fileBase, String label) {
        int pos = off;
        int end = Math.min(off + len, d.length);
        int idx = 0;
        while (pos < end) {
            int family = d[pos] & 0xFF;
            int nodeSize;
            String famName;
            if (family == FAM_IPV4) { nodeSize = 39; famName = "UDP IPv4"; }
            else if (family == FAM_IPV6) { nodeSize = 51; famName = "UDP IPv6"; }
            else if (family == FAM_TCP_IPV4) { nodeSize = 39; famName = "TCP IPv4"; }
            else if (family == FAM_TCP_IPV6) { nodeSize = 51; famName = "TCP IPv6"; }
            else break;

            if (pos + nodeSize > end) break;

            boolean v6 = (family == FAM_IPV6 || family == FAM_TCP_IPV6);
            String ip;
            int port;
            byte[] key;
            if (v6) {
                ip = formatIpv6(Arrays.copyOfRange(d, pos + 1, pos + 17));
                port = readBE16(d, pos + 17);
                key = Arrays.copyOfRange(d, pos + 19, pos + 51);
            } else {
                ip = formatIpv4(Arrays.copyOfRange(d, pos + 1, pos + 5));
                port = readBE16(d, pos + 5);
                key = Arrays.copyOfRange(d, pos + 7, pos + 39);
            }

            StringBuilder det = new StringBuilder();
            det.append(label).append(" #").append(idx).append("\n");
            det.append("Address:    ").append(ip).append(":").append(port).append("\n");
            det.append("Transport:  ").append(famName).append("  (family byte ").append(family).append(")\n");
            det.append("Public key: ").append(hex(key)).append("\n");

            s.subItems.add(makeItem(fileBase + pos, nodeSize, ip, PALETTE[idx % PALETTE.length], det.toString()));
            pos += nodeSize;
            idx++;
        }
        if (pos < end) {
            s.subItems.add(makeItem(fileBase + pos, end - pos, "tail", Color.GRAY,
                "Trailing " + (end - pos) + " bytes not parsed as nodes"));
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
            
            StringBuilder det = new StringBuilder();
            det.append("Friend #").append(i).append(" (Total: 2216 bytes)\n");
            det.append(String.format("  [%4d bytes] Status: %s\n", 1, getFriendStatusName(status)));
            det.append(String.format("  [%4d bytes] Public Key: %s\n", 32, hex(pk)));
            
            if (status == 1 || status == 2) {
                int infoSize = readBE16(d, off + OFF_INFO_SIZE);
                if (infoSize > 1024) infoSize = 1024;
                String info = trimNulls(new String(d, off + OFF_INFO, infoSize, StandardCharsets.UTF_8));
                long nospam = readLE32(d, off + OFF_NOSPAM);
                byte[] nospamBytes = Arrays.copyOfRange(d, off + OFF_NOSPAM, off + OFF_NOSPAM + 4);
                
                det.append("\n--- Pending Request Details ---\n");
                det.append(String.format("  [%4d bytes] Request Message: \"%s\"\n", 1024, info.isEmpty() ? "(empty)" : info));
                det.append(String.format("  [%4d bytes] Padding (after info)\n", 1));
                det.append(String.format("  [%4d bytes] Info Size: %d\n", 2, infoSize));
                det.append(String.format("  [%4d bytes] Nospam: 0x%08X (%d)\n", 4, nospam, nospam));
                det.append(String.format("  [%4d bytes] Derived Tox ID (38 bytes): %s\n", 38, computeToxId(pk, nospamBytes)));
                
                det.append("\n(Note: Name, Status Message, User Status, and Last Seen are zeroed/empty for pending requests)\n");
                
                String label = (status == 1 ? "OUT: " : "IN: ") + (info.isEmpty() ? "friend#" + i : info.substring(0, Math.min(15, info.length())));
                s.subItems.add(makeItem(base + off, FRIEND_SIZE, label, new Color(255, 165, 0), det.toString()));
                
            } else if (status == 3) {
                int nameLen = readBE16(d, off + OFF_NAME_LEN);
                if (nameLen > 128) nameLen = 128;
                String name = trimNulls(new String(d, off + OFF_NAME, nameLen, StandardCharsets.UTF_8));
                
                int msgLen = readBE16(d, off + OFF_STATUSMSG_LEN);
                if (msgLen > 1007) msgLen = 1007;
                String msg = trimNulls(new String(d, off + OFF_STATUSMSG, msgLen, StandardCharsets.UTF_8));
                
                int userStatus = d[off + OFF_USERSTATUS] & 0xFF;
                long lastSeen = readBE64(d, off + OFF_LASTSEEN);
                
                det.append("\n--- Confirmed Friend Details ---\n");
                det.append(String.format("  [%4d bytes] Padding (after info)\n", 1));
                det.append(String.format("  [%4d bytes] Info Size: 0 (ignored)\n", 2));
                det.append(String.format("  [%4d bytes] Name: \"%s\"\n", 128, name.isEmpty() ? "(empty)" : name));
                det.append(String.format("  [%4d bytes] Name Length: %d\n", 2, nameLen));
                det.append(String.format("  [%4d bytes] Status Message: \"%s\"\n", 1007, msg.isEmpty() ? "(empty)" : msg));
                det.append(String.format("  [%4d bytes] Padding (after status message)\n", 1));
                det.append(String.format("  [%4d bytes] Status Message Length: %d\n", 2, msgLen));
                det.append(String.format("  [%4d bytes] User Status: %s\n", 1, userStatusName(userStatus)));
                det.append(String.format("  [%4d bytes] Padding (after user status)\n", 3));
                det.append(String.format("  [%4d bytes] Nospam: (ignored for confirmed)\n", 4));
                det.append(String.format("  [%4d bytes] Last Seen: %s\n", 8, formatTime(lastSeen)));
                
                s.subItems.add(makeItem(base + off, FRIEND_SIZE, name.isEmpty() ? ("friend#" + i) : name, PALETTE[i % PALETTE.length], det.toString()));
                
            } else {
                det.append("\n--- Empty Slot ---\n");
                det.append("  (All remaining 2215 bytes are zeroed)\n");
                s.subItems.add(makeItem(base + off, FRIEND_SIZE, "empty#" + i, Color.GRAY, det.toString()));
            }
        }
        
        int leftover = d.length % FRIEND_SIZE;
        if (leftover > 0) {
            s.subItems.add(makeItem(base + num * FRIEND_SIZE, leftover, "pad", Color.GRAY,
                "Trailing " + leftover + " bytes (not a full friend record)"));
        }
    }

    private String getFriendStatusName(int status) {
        switch (status) {
            case 0: return "EMPTY / DELETED";
            case 1: return "OUTGOING REQUEST SENT";
            case 2: return "INCOMING REQUEST RECEIVED";
            case 3: return "CONFIRMED (OFFLINE/SAVED)";
            default: return "UNKNOWN (" + status + ")";
        }
    }

    private void buildGroupSubItems(Section s) {
        byte[] d = s.data;
        int base = s.offset + 8;

        try {
            MsgPack mp = new MsgPack(d);
            long countLong = mp.readArraySize();
            int count = (int) countLong;

            for (int g = 0; g < count; g++) {
                int groupStart = mp.getPosition();
                GroupInfo gi = parseOneGroup(mp);
                if (gi == null) {
                    s.subItems.add(makeItem(base + groupStart, d.length - groupStart, "group?", Color.GRAY,
                        "Could not parse group #" + g + " (msgpack error)"));
                    break;
                }
                int size = mp.getPosition() - groupStart;
                String label = gi.name.isEmpty() ? ("group#" + g) : gi.name;
                s.subItems.add(makeItem(base + groupStart, size, label, PALETTE[g % PALETTE.length], gi.details));
            }
            if (mp.hasMore()) {
                int pos = mp.getPosition();
                s.subItems.add(makeItem(base + pos, d.length - pos, "tail", Color.GRAY,
                    "Trailing " + (d.length - pos) + " bytes"));
            }
        } catch (Exception e) {
            s.subItems.add(makeItem(base, d.length, "groups", s.color, describeGroups(s) + "\n\nError: " + e.getMessage()));
        }
    }

    private static class GroupInfo {
        String name = "";
        String details = "";
    }

    private GroupInfo parseOneGroup(MsgPack mp) {
        try {
            if (!mp.readArraySizeFixed(7)) return null;

            GroupInfo gi = new GroupInfo();
            StringBuilder det = new StringBuilder();

            if (!mp.readArraySizeFixed(8)) return null;
            boolean disconnected = mp.readBoolean();
            int nameLen = (int) mp.readUint();
            int privacy = (int) mp.readUint();
            int maxPeers = (int) mp.readUint();
            int pwdLen = (int) mp.readUint();
            long version = mp.readUint();
            long topicLock = mp.readUint();
            int voice = (int) mp.readUint();

            if (!mp.readArraySizeFixed(5)) return null;
            byte[] sig = mp.readBinFixed(64);               
            byte[] founderPk = mp.readBinFixed(64);         
            byte[] nameBytes = mp.readBinFixed(nameLen);
            byte[] pwd = mp.readBinFixed(pwdLen);
            byte[] modHash = mp.readBinFixed(32);           

            gi.name = new String(nameBytes, StandardCharsets.UTF_8);

            if (!mp.readArraySizeFixed(6)) return null;
            long topicVersion = mp.readUint();
            int topicLen = (int) mp.readUint();
            long topicChecksum = mp.readUint();
            byte[] topicBytes = mp.readBinFixed(topicLen);
            byte[] topicSigPk = mp.readBinFixed(32);        
            byte[] topicSig = mp.readBinFixed(64);          

            String topicStr = new String(topicBytes, StandardCharsets.UTF_8);

            if (!mp.readArraySizeFixed(2)) return null;
            int numMods = (int) mp.readUint();
            byte[] modListBlob = null;
            if (numMods == 0) {
                mp.readNil();
            } else {
                modListBlob = mp.readBinFixed(numMods * 32);
            }

            if (!mp.readArraySizeFixed(4)) return null;
            byte[] chatPub = mp.readBinFixed(64);           
            byte[] chatSec = mp.readBinFixed(96);           
            byte[] selfPub = mp.readBinFixed(64);           
            byte[] selfSec = mp.readBinFixed(96);           

            if (!mp.readArraySizeFixed(4)) return null;
            int nickLen = (int) mp.readUint();
            int selfRole = (int) mp.readUint();
            int selfStatus = (int) mp.readUint();
            byte[] nickBytes = mp.readBinFixed(nickLen);
            String selfNick = new String(nickBytes, StandardCharsets.UTF_8);

            if (!mp.readArraySizeFixed(2)) return null;
            int savedPeerBytes = (int) mp.readUint();
            byte[] savedPeersBlob = null;
            if (savedPeerBytes == 0) {
                mp.readNil();
            } else {
                savedPeersBlob = mp.readBinFixed(savedPeerBytes);
            }

            det.append("Group: \"").append(gi.name).append("\"\n");
            det.append("State:           ").append(disconnected ? "DISCONNECTED" : "CONNECTING/CONNECTED").append("\n");
            det.append("Privacy:         ").append(privacy == 0 ? "PUBLIC" : "PRIVATE").append("\n");
            det.append("Voice:           ").append(voiceName(voice)).append("\n");
            det.append("Topic lock:      ").append(topicLock == 0 ? "ENABLED" : "DISABLED").append("\n");
            det.append("Max peers:       ").append(maxPeers).append("\n");
            det.append("State version:   ").append(version).append("\n");
            det.append("Password:        ").append(pwdLen > 0 ? "set (" + pwdLen + " bytes)" : "none").append("\n");
            det.append("Topic:           ").append(topicStr.isEmpty() ? "(empty)" : "\"" + topicStr + "\"").append("\n");
            det.append("Topic version:   ").append(topicVersion).append("\n");
            det.append("Chat ID:         ").append(hex(Arrays.copyOfRange(chatPub, 0, 32))).append("\n");
            det.append("Founder enc pk:  ").append(hex(Arrays.copyOfRange(founderPk, 0, 32))).append("\n");
            det.append("Mod list hash:   ").append(hex(modHash)).append("\n");
            
            det.append("\n--- Self Info ---\n");
            det.append("Self nick:       ").append(selfNick.isEmpty() ? "(empty)" : "\"" + selfNick + "\"").append("\n");
            det.append("Self role:       ").append(roleName(selfRole)).append("\n");
            det.append("Self status:     ").append(userStatusName(selfStatus)).append("\n");
            det.append("Self enc pk:     ").append(hex(Arrays.copyOfRange(selfPub, 0, 32))).append("\n");
            det.append("Self sig pk:     ").append(hex(Arrays.copyOfRange(selfPub, 32, 64))).append("\n");
            
            det.append("\n--- Keys ---\n");
            det.append("Chat pub:        ").append(hex(chatPub)).append("\n");
            det.append("Chat sec:        ").append(hex(chatSec)).append("\n");
            det.append("Self pub:        ").append(hex(selfPub)).append("\n");
            det.append("Self sec:        ").append(hex(selfSec)).append("\n");
            det.append("State sig:       ").append(hex(sig)).append("\n");
            det.append("Topic sig pk:    ").append(hex(topicSigPk)).append("\n");
            det.append("Topic sig:       ").append(hex(topicSig)).append("\n");
            
            det.append("\n--- Moderators (").append(numMods).append(") ---");
            det.append(parseMods(modListBlob, numMods)).append("\n");
            
            det.append("\n--- Saved Peers (").append(savedPeerBytes).append(" bytes) ---");
            det.append(parseSavedPeers(savedPeersBlob)).append("\n");

            gi.details = det.toString();
            return gi;
        } catch (Exception e) {
            throw new RuntimeException("MsgPack parse error at pos " + mp.getPosition() + ": " + e.getMessage(), e);
        }
    }

    private String formatIPv6(byte[] b, int off) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x%02x", b[off+i]&0xFF, b[off+i+1]&0xFF));
        }
        return sb.toString();
    }

    private String parseMods(byte[] blob, int numMods) {
        if (numMods == 0 || blob == null) return "(none)";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < numMods; i++) {
            int start = i * 32;
            if (start + 32 <= blob.length) {
                sb.append("\n  [Mod ").append(i).append("] Sig PK: ").append(hex(Arrays.copyOfRange(blob, start, start + 32)));
            }
        }
        return sb.toString();
    }

    private String parseSavedPeers(byte[] blob) {
        if (blob == null || blob.length == 0) return "(none)";
        StringBuilder sb = new StringBuilder();
        int pos = 0;
        int peerIdx = 0;
        while (pos < blob.length) {
            sb.append("\n  [Saved Peer ").append(peerIdx).append("]");
            boolean hasIp = false;
            boolean hasTcp = false;
            
            if (pos < blob.length) {
                int fam = blob[pos] & 0xFF;
                if (fam == 2) {
                    if (pos + 7 <= blob.length) {
                        sb.append("\n    UDP: ").append(blob[pos+1]&0xFF).append(".").append(blob[pos+2]&0xFF).append(".").append(blob[pos+3]&0xFF).append(".").append(blob[pos+4]&0xFF);
                        int port = ((blob[pos+5]&0xFF) << 8) | (blob[pos+6]&0xFF);
                        sb.append(":").append(port);
                        pos += 7;
                        hasIp = true;
                    }
                } else if (fam == 10) {
                    if (pos + 19 <= blob.length) {
                        sb.append("\n    UDP: [").append(formatIPv6(blob, pos+1)).append("]");
                        int port = ((blob[pos+17]&0xFF) << 8) | (blob[pos+18]&0xFF);
                        sb.append(":").append(port);
                        pos += 19;
                        hasIp = true;
                    }
                }
            }
            
            if (pos < blob.length) {
                int fam = blob[pos] & 0xFF;
                if (fam == 2 || fam == 130) {
                    if (pos + 39 <= blob.length) {
                        sb.append("\n    TCP: ").append(blob[pos+1]&0xFF).append(".").append(blob[pos+2]&0xFF).append(".").append(blob[pos+3]&0xFF).append(".").append(blob[pos+4]&0xFF);
                        int port = ((blob[pos+5]&0xFF) << 8) | (blob[pos+6]&0xFF);
                        sb.append(":").append(port);
                        sb.append("\n      Relay PK: ").append(hex(Arrays.copyOfRange(blob, pos + 7, pos + 39)));
                        pos += 39;
                        hasTcp = true;
                    }
                } else if (fam == 10 || fam == 138) {
                    if (pos + 51 <= blob.length) {
                        sb.append("\n    TCP: [").append(formatIPv6(blob, pos+1)).append("]");
                        int port = ((blob[pos+17]&0xFF) << 8) | (blob[pos+18]&0xFF);
                        sb.append(":").append(port);
                        sb.append("\n      Relay PK: ").append(hex(Arrays.copyOfRange(blob, pos + 19, pos + 51)));
                        pos += 51;
                        hasTcp = true;
                    }
                }
            }
            
            if (!hasIp && !hasTcp) {
                sb.append("\n    (Invalid/Truncated peer data)");
                break;
            }
            
            if (pos + 32 <= blob.length) {
                sb.append("\n    Peer PK: ").append(hex(Arrays.copyOfRange(blob, pos, pos + 32)));
                pos += 32;
            } else {
                sb.append("\n    (Truncated PK)");
                break;
            }
            peerIdx++;
        }
        return sb.toString();
    }

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
        byte[] d = s.data;
        StringBuilder sb = new StringBuilder();
        int pos = 0;
        if (d.length >= 4 && readLE32(d, 0) == DHT_STATE_COOKIE_GLOBAL) {
            sb.append("DHT_STATE_COOKIE_GLOBAL: 0x159000d  OK\n\n");
            pos = 4;
        } else {
            return "DHT state (" + d.length + " bytes) - unexpected format (missing cookie).\nSee hex dump.";
        }
        while (pos + 8 <= d.length) {
            long lenLong = readLE32(d, pos);
            int type = readLE16(d, pos + 4);
            int cookie = readLE16(d, pos + 6);
            if (cookie != DHT_STATE_COOKIE_TYPE || lenLong < 0 || pos + 8 + lenLong > d.length) {
                sb.append("(malformed DHT sub-section at offset ").append(pos).append(")\n");
                break;
            }
            int len = (int) lenLong;
            if (type == DHT_STATE_TYPE_NODES) {
                sb.append("NODES sub-section: ").append(len).append(" bytes\n");
                sb.append(describeNodesIn(d, pos + 8, len, "saved DHT node"));
            } else {
                sb.append("Unknown DHT sub-section type ").append(type).append(" (").append(len).append(" bytes)\n");
            }
            pos += 8 + len;
        }
        return sb.toString();
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
            
            sb.append("========== Friend #").append(i).append(" (Total: 2216 bytes) ==========\n");
            sb.append(String.format("  [%4d bytes] Status: %s\n", 1, getFriendStatusName(status)));
            sb.append(String.format("  [%4d bytes] Public Key: %s\n", 32, hex(pk)));
            
            if (status == 1 || status == 2) {
                int infoSize = readBE16(d, off + OFF_INFO_SIZE);
                if (infoSize > 1024) infoSize = 1024;
                String info = trimNulls(new String(d, off + OFF_INFO, infoSize, StandardCharsets.UTF_8));
                long nospam = readLE32(d, off + OFF_NOSPAM);
                byte[] nospamBytes = Arrays.copyOfRange(d, off + OFF_NOSPAM, off + OFF_NOSPAM + 4);
                
                sb.append(String.format("  [%4d bytes] Request Message: \"%s\"\n", 1024, info.isEmpty() ? "(empty)" : info));
                sb.append(String.format("  [%4d bytes] Padding (after info)\n", 1));
                sb.append(String.format("  [%4d bytes] Info Size: %d\n", 2, infoSize));
                sb.append(String.format("  [%4d bytes] Nospam: 0x%08X (%d)\n", 4, nospam, nospam));
                sb.append(String.format("  [%4d bytes] Derived Tox ID (38 bytes): %s\n", 38, computeToxId(pk, nospamBytes)));
                sb.append("\n(Note: Name, Status Message, User Status, and Last Seen are zeroed/empty for pending requests)\n");
            } else if (status == 3) {
                int nameLen = readBE16(d, off + OFF_NAME_LEN);
                if (nameLen > 128) nameLen = 128;
                String name = trimNulls(new String(d, off + OFF_NAME, nameLen, StandardCharsets.UTF_8));
                
                int msgLen = readBE16(d, off + OFF_STATUSMSG_LEN);
                if (msgLen > 1007) msgLen = 1007;
                String msg = trimNulls(new String(d, off + OFF_STATUSMSG, msgLen, StandardCharsets.UTF_8));
                
                int userStatus = d[off + OFF_USERSTATUS] & 0xFF;
                long lastSeen = readBE64(d, off + OFF_LASTSEEN);
                
                sb.append(String.format("  [%4d bytes] Padding (after info)\n", 1));
                sb.append(String.format("  [%4d bytes] Info Size: 0 (ignored)\n", 2));
                sb.append(String.format("  [%4d bytes] Name: \"%s\"\n", 128, name.isEmpty() ? "(empty)" : name));
                sb.append(String.format("  [%4d bytes] Name Length: %d\n", 2, nameLen));
                sb.append(String.format("  [%4d bytes] Status Message: \"%s\"\n", 1007, msg.isEmpty() ? "(empty)" : msg));
                sb.append(String.format("  [%4d bytes] Padding (after status message)\n", 1));
                sb.append(String.format("  [%4d bytes] Status Message Length: %d\n", 2, msgLen));
                sb.append(String.format("  [%4d bytes] User Status: %s\n", 1, userStatusName(userStatus)));
                sb.append(String.format("  [%4d bytes] Padding (after user status)\n", 3));
                sb.append(String.format("  [%4d bytes] Nospam: (ignored for confirmed)\n", 4));
                sb.append(String.format("  [%4d bytes] Last Seen: %s\n", 8, formatTime(lastSeen)));
            } else {
                sb.append("\n--- Empty Slot ---\n");
                sb.append("  (All remaining 2215 bytes are zeroed)\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    private String describeGroups(Section s) {
        byte[] d = s.data;
        StringBuilder sb = new StringBuilder();
        try {
            MsgPack mp = new MsgPack(d);
            long countLong = mp.readArraySize();
            int count = (int) countLong;
            sb.append(count).append(" saved group chat(s)  (msgpack encoded)\n\n");
            for (int g = 0; g < count; g++) {
                GroupInfo gi = parseOneGroup(mp);
                if (gi == null) {
                    sb.append("[group ").append(g).append("]: failed to parse (msgpack error)\n");
                    break;
                }
                sb.append("########## Group ").append(g).append(" ##########\n");
                sb.append(gi.details).append("\n");
            }
        } catch (Exception e) {
            sb.append("Groups data (").append(d.length).append(" bytes): could not read msgpack array header.\n");
            sb.append("Error: ").append(e.getMessage()).append("\nSee hex dump.");
        }
        return sb.toString();
    }

    private void buildConferenceSubItems(Section s) {
        byte[] d = s.data;
        int base = s.offset + 8;
        int pos = 0;
        int confIdx = 0;

        while (pos < d.length) {
            int confStart = pos;
            if (pos + 46 > d.length) break;

            int type = d[pos] & 0xFF; pos += 1;
            byte[] id = Arrays.copyOfRange(d, pos, pos + 32); pos += 32;
            long msgNum = readLE32(d, pos); pos += 4;
            int lossyMsgNum = readLE16(d, pos); pos += 2;
            int peerNum = readLE16(d, pos); pos += 2;
            long numPeersLong = readLE32(d, pos); pos += 4;
            int numPeers = (int) numPeersLong;
            
            int titleLen = d[pos] & 0xFF; pos += 1;
            if (pos + titleLen > d.length) break;
            String title = trimNulls(new String(d, pos, titleLen, StandardCharsets.UTF_8));
            pos += titleLen;

            StringBuilder det = new StringBuilder();
            det.append("Conference #").append(confIdx).append("\n");
            det.append("Type: ").append(type == 0 ? "TEXT" : "AV (Audio/Video)").append(" (").append(type).append(")\n");
            det.append("ID: ").append(hex(id)).append("\n");
            det.append("Title: \"").append(title.isEmpty() ? "(empty)" : title).append("\"\n");
            det.append("Self peer #: ").append(peerNum).append("\n");
            det.append("Msg #: ").append(msgNum).append("\n");
            det.append("Peers saved: ").append(numPeers).append("\n");

            boolean parseError = false;
            for (int p = 0; p < numPeers; p++) {
                if (pos + 75 > d.length) { parseError = true; break; }
                byte[] realPk = Arrays.copyOfRange(d, pos, pos + 32); pos += 32;
                pos += 32; // skip tempPk
                int pNum = readLE16(d, pos); pos += 2;
                long lastActive = readLE64(d, pos); pos += 8;
                int nickLen = d[pos] & 0xFF; pos += 1;
                if (pos + nickLen > d.length) { parseError = true; break; }
                String nick = trimNulls(new String(d, pos, nickLen, StandardCharsets.UTF_8));
                pos += nickLen;

                det.append("  [Peer ").append(p).append("] #").append(pNum).append(" \"").append(nick.isEmpty() ? "(empty)" : nick).append("\"\n");
                det.append("    pubkey: ").append(hex(realPk)).append("\n");
                det.append("    last_active: ").append(lastActive).append(" (mono_time)\n");
            }

            if (parseError) {
                det.append("\n[Parse error: truncated peer data]\n");
            }

            int size = pos - confStart;
            String label = title.isEmpty() ? ("conf#" + confIdx) : title;
            s.subItems.add(makeItem(base + confStart, size, label, PALETTE[confIdx % PALETTE.length], det.toString()));
            confIdx++;
        }
        
        if (confIdx == 0 && s.subItems.isEmpty()) {
            s.subItems.add(makeItem(base, d.length, "empty", s.color, "No connected conferences saved (or empty section)."));
        } else if (pos < d.length) {
            s.subItems.add(makeItem(base + pos, d.length - pos, "tail", Color.GRAY,
                "Trailing " + (d.length - pos) + " bytes not parsed"));
        }
    }

    private String describeConferences(Section s) {
        byte[] d = s.data;
        StringBuilder sb = new StringBuilder();
        int pos = 0;
        int confIdx = 0;

        while (pos < d.length) {
            if (pos + 46 > d.length) break;

            int type = d[pos] & 0xFF; pos += 1;
            byte[] id = Arrays.copyOfRange(d, pos, pos + 32); pos += 32;
            long msgNum = readLE32(d, pos); pos += 4;
            int lossyMsgNum = readLE16(d, pos); pos += 2;
            int peerNum = readLE16(d, pos); pos += 2;
            long numPeersLong = readLE32(d, pos); pos += 4;
            int numPeers = (int) numPeersLong;
            
            int titleLen = d[pos] & 0xFF; pos += 1;
            if (pos + titleLen > d.length) break;
            String title = trimNulls(new String(d, pos, titleLen, StandardCharsets.UTF_8));
            pos += titleLen;

            sb.append("########## Conference ").append(confIdx).append(" ##########\n");
            sb.append("Type: ").append(type == 0 ? "TEXT" : "AV (Audio/Video)").append(" (").append(type).append(")\n");
            sb.append("ID: ").append(hex(id)).append("\n");
            sb.append("Title: \"").append(title).append("\"\n");
            sb.append("Self peer #: ").append(peerNum).append("\n");
            sb.append("Msg #: ").append(msgNum).append("\n");
            sb.append("Peers saved: ").append(numPeers).append("\n");

            boolean parseError = false;
            for (int p = 0; p < numPeers; p++) {
                if (pos + 75 > d.length) { parseError = true; break; }
                byte[] realPk = Arrays.copyOfRange(d, pos, pos + 32); pos += 32;
                pos += 32; // skip tempPk
                int pNum = readLE16(d, pos); pos += 2;
                long lastActive = readLE64(d, pos); pos += 8;
                int nickLen = d[pos] & 0xFF; pos += 1;
                if (pos + nickLen > d.length) { parseError = true; break; }
                String nick = trimNulls(new String(d, pos, nickLen, StandardCharsets.UTF_8));
                pos += nickLen;

                sb.append("  [Peer ").append(p).append("] #").append(pNum).append(" \"").append(nick).append("\"\n");
                sb.append("    pubkey: ").append(hex(realPk)).append("\n");
                sb.append("    last_active: ").append(lastActive).append(" (mono_time)\n");
            }

            if (parseError) {
                sb.append("\n[Parse error: truncated peer data]\n");
                break;
            }
            sb.append("\n");
            confIdx++;
        }
        
        if (confIdx == 0) {
            sb.append("No connected conferences saved (or empty section).\n");
        } else {
            sb.append("Total conferences saved: ").append(confIdx).append("\n");
        }
        return sb.toString();
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
        return describeNodesIn(d, 0, d.length, label);
    }

    private String describeNodesIn(byte[] d, int start, int len, String label) {
        int pos = start;
        int end = Math.min(start + len, d.length);
        int count = 0;
        StringBuilder sb = new StringBuilder();
        while (pos < end) {
            int family = d[pos] & 0xFF;
            int nodeSize;
            String famName;
            if (family == FAM_IPV4) { nodeSize = 39; famName = "UDP IPv4"; }
            else if (family == FAM_IPV6) { nodeSize = 51; famName = "UDP IPv6"; }
            else if (family == FAM_TCP_IPV4) { nodeSize = 39; famName = "TCP IPv4"; }
            else if (family == FAM_TCP_IPV6) { nodeSize = 51; famName = "TCP IPv6"; }
            else {
                sb.append("  (unknown family byte 0x").append(String.format("%02X", family))
                  .append(" at offset ").append(pos).append(", stopping)\n");
                break;
            }
            if (pos + nodeSize > end) {
                sb.append("  (truncated node at offset ").append(pos).append(")\n");
                break;
            }
            boolean v6 = (family == FAM_IPV6 || family == FAM_TCP_IPV6);
            String ip;
            int port;
            byte[] key;
            if (v6) {
                ip = formatIpv6(Arrays.copyOfRange(d, pos + 1, pos + 17));
                port = readBE16(d, pos + 17);
                key = Arrays.copyOfRange(d, pos + 19, pos + 51);
            } else {
                ip = formatIpv4(Arrays.copyOfRange(d, pos + 1, pos + 5));
                port = readBE16(d, pos + 5);
                key = Arrays.copyOfRange(d, pos + 7, pos + 39);
            }
            sb.append("  [").append(count).append("] ").append(ip).append(":").append(port)
              .append("   (").append(famName).append(")\n");
            sb.append("       key=").append(hex(key)).append("\n");
            pos += nodeSize;
            count++;
        }
        return count + " " + label + "(s)\n" + sb.toString();
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

    private String roleName(int role) {
        switch (role) {
            case 0: return "FOUNDER";
            case 1: return "MODERATOR";
            case 2: return "USER";
            case 3: return "OBSERVER";
            default: return "Unknown(" + role + ")";
        }
    }

    private String voiceName(int v) {
        switch (v) {
            case 0: return "ALL can speak";
            case 1: return "MODS+FOUNDER can speak";
            case 2: return "FOUNDER only can speak";
            default: return "Unknown(" + v + ")";
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

    private long readLE64(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= ((long)(b[off + i] & 0xFF)) << (8 * i);
        }
        return v;
    }

    private int readBE16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private long readBE64(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[off + i] & 0xFF);
        return v;
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

    class ChartPanel extends JPanel {
        List<Section> sections;
        byte[] fileData;
        private final int pad = scale(6);
        private int highlightType = -1;
        private Section lastHovered;

        public ChartPanel() {
            setBackground(Color.LIGHT_GRAY);
            int h = scale(MAIN_CHART_HEIGHT);
            setPreferredSize(new Dimension(scale(700), h));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, h));

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
            FontMetrics fm = g2d.getFontMetrics();

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

                if (!dim && availableHeight > fm.getHeight() && w > fm.stringWidth(s.typeName) + 10) {
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

    class ZoomPanel extends JPanel {
        Section section;
        List<SubItem> items;
        int hoveredIndex = -1;

        public ZoomPanel() {
            setBackground(new Color(245, 245, 245));
            int h = scale(ZOOM_CHART_HEIGHT);
            setPreferredSize(new Dimension(scale(700), h));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, h));

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

        private int zoomPad() { return scale(6); }
        private int zoomTopY() { return zoomPad() + scale(20); }
        private int zoomBarH() { return Math.max(getHeight() - zoomTopY() - zoomPad(), scale(16)); }

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
            FontMetrics fm = g2d.getFontMetrics();
            g2d.setColor(Color.DARK_GRAY);

            if (section == null) {
                g2d.drawString("Zoom: hover a section bar above to inspect its contents", pad, pad + fm.getAscent());
                return;
            }

            g2d.drawString("Zoom: " + section.typeName + "  (" + section.length + " bytes, " +
                    (items == null ? 0 : items.size()) + " parts)", pad, pad + fm.getAscent());

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

                if (barH > fm.getHeight() && w > fm.stringWidth(it.label) + 8) {
                    g2d.setColor(Color.BLACK);
                    int ty = topY + (barH + fm.getAscent() - fm.getDescent()) / 2;
                    g2d.drawString(it.label, x + 4, ty);
                }
                x += w;
            }
        }
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
