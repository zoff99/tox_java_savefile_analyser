import java.util.Arrays;

/**
 * Minimal, robust MessagePack reader adapted from cmp.c (Tox's msgpack library).
 * Supports the subset of msgpack used by c-toxcore's bin_unpack for group saves.
 */
public class MsgPack {
    private final byte[] data;
    private int pos;

    public MsgPack(byte[] data) {
        this.data = data;
        this.pos = 0;
    }

    public MsgPack(byte[] data, int offset) {
        this.data = data;
        this.pos = offset;
    }

    public int getPosition() {
        return pos;
    }

    public boolean hasMore() {
        return pos < data.length;
    }

    private int readByte() throws Exception {
        if (pos >= data.length) throw new Exception("EOF");
        return data[pos++] & 0xFF;
    }

    private int readU16() throws Exception {
        if (pos + 2 > data.length) throw new Exception("EOF");
        int v = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    private long readU32() throws Exception {
        if (pos + 4 > data.length) throw new Exception("EOF");
        long v = ((data[pos] & 0xFFL) << 24) | ((data[pos + 1] & 0xFFL) << 16) |
                 ((data[pos + 2] & 0xFFL) << 8) | (data[pos + 3] & 0xFFL);
        pos += 4;
        return v;
    }

    private long readU64() throws Exception {
        if (pos + 8 > data.length) throw new Exception("EOF");
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (data[pos + i] & 0xFFL);
        }
        pos += 8;
        return v;
    }

    public long readArraySize() throws Exception {
        int b = readByte();
        if (b >= 0x90 && b <= 0x9f) {
            return b & 0x0f;
        } else if (b == 0xdc) {
            return readU16();
        } else if (b == 0xdd) {
            return readU32();
        }
        throw new Exception("Expected array, got 0x" + Integer.toHexString(b));
    }

    public boolean readArraySizeFixed(int expected) throws Exception {
        long size = readArraySize();
        return size == expected;
    }

    public long readUint() throws Exception {
        int b = readByte();
        if (b <= 0x7f) return b;           // positive fixint
        if (b == 0xcc) return readByte();  // uint 8
        if (b == 0xcd) return readU16();   // uint 16
        if (b == 0xce) return readU32();   // uint 32
        if (b == 0xcf) return readU64();   // uint 64
        if (b >= 0xe0) return b - 256;     // negative fixint
        throw new Exception("Expected uint, got 0x" + Integer.toHexString(b));
    }

    public boolean readBoolean() throws Exception {
        int b = readByte();
        if (b == 0xc2) return false;
        if (b == 0xc3) return true;
        throw new Exception("Expected boolean, got 0x" + Integer.toHexString(b));
    }

    public boolean readNil() throws Exception {
        int b = readByte();
        if (b == 0xc0) return true;
        throw new Exception("Expected nil, got 0x" + Integer.toHexString(b));
    }

    public byte[] readBin() throws Exception {
        int b = readByte();
        int len;
        if (b == 0xc4) {
            len = readByte();
        } else if (b == 0xc5) {
            len = readU16();
        } else if (b == 0xc6) {
            len = (int) readU32();
        } else {
            throw new Exception("Expected bin, got 0x" + Integer.toHexString(b));
        }
        if (pos + len > data.length) throw new Exception("EOF in bin");
        byte[] res = Arrays.copyOfRange(data, pos, pos + len);
        pos += len;
        return res;
    }

    /** Reads a bin payload and verifies its length exactly matches expectedLen (like bin_unpack_bin_fixed). */
    public byte[] readBinFixed(int expectedLen) throws Exception {
        byte[] b = readBin();
        if (b.length != expectedLen) {
            throw new Exception("Bin length mismatch: expected " + expectedLen + " got " + b.length);
        }
        return b;
    }

    /** Skips exactly one msgpack value of any type. */
    public void skipValue() throws Exception {
        int b = readByte();
        if (b <= 0x7f) return; // positive fixint
        if (b >= 0x80 && b <= 0x8f) { skipMap(b & 0x0f); return; }
        if (b >= 0x90 && b <= 0x9f) { skipArray(b & 0x0f); return; }
        if (b >= 0xa0 && b <= 0xbf) { skipBytes(b & 0x1f); return; } // fixstr
        if (b >= 0xe0) return; // negative fixint

        switch (b) {
            case 0xc0: case 0xc2: case 0xc3: return; // nil, false, true
            case 0xc4: skipBytes(readByte()); return;
            case 0xc5: skipBytes(readU16()); return;
            case 0xc6: skipBytes((int)readU32()); return;
            case 0xc7: { int l = readByte(); skipBytes(1 + l); return; } // ext 8
            case 0xc8: { int l = readU16(); skipBytes(1 + l); return; }  // ext 16
            case 0xc9: { int l = (int)readU32(); skipBytes(1 + l); return; } // ext 32
            case 0xca: skipBytes(4); return; // float 32
            case 0xcb: skipBytes(8); return; // float 64
            case 0xcc: skipBytes(1); return;
            case 0xcd: skipBytes(2); return;
            case 0xce: skipBytes(4); return;
            case 0xcf: skipBytes(8); return;
            case 0xd0: skipBytes(1); return;
            case 0xd1: skipBytes(2); return;
            case 0xd2: skipBytes(4); return;
            case 0xd3: skipBytes(8); return;
            case 0xd4: skipBytes(2); return;  // fixext 1
            case 0xd5: skipBytes(3); return;  // fixext 2
            case 0xd6: skipBytes(5); return;  // fixext 4
            case 0xd7: skipBytes(9); return;  // fixext 8
            case 0xd8: skipBytes(17); return; // fixext 16
            case 0xd9: skipBytes(readByte()); return; // str 8
            case 0xda: skipBytes(readU16()); return;
            case 0xdb: skipBytes((int)readU32()); return;
            case 0xdc: skipArray(readU16()); return;
            case 0xdd: skipArray((int)readU32()); return;
            case 0xde: skipMap(readU16()); return;
            case 0xdf: skipMap((int)readU32()); return;
        }
        throw new Exception("Unknown msgpack type 0x" + Integer.toHexString(b));
    }

    private void skipBytes(int count) throws Exception {
        if (pos + count > data.length) throw new Exception("EOF");
        pos += count;
    }

    private void skipArray(int count) throws Exception {
        for (int i = 0; i < count; i++) skipValue();
    }

    private void skipMap(int count) throws Exception {
        for (int i = 0; i < count * 2; i++) skipValue();
    }
}
