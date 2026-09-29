import java.util.Arrays;

/**
 * Robust MessagePack reader fully compatible with cmp.c (used by c-toxcore).
 * Supports both bin and str markers for byte arrays, and all int/uint/bool variants.
 */
public class MsgPack {
    private final byte[] data;
    private int pos;

    public MsgPack(byte[] data) {
        this.data = data;
        this.pos = 0;
    }

    public int getPosition() {
        return pos;
    }

    public boolean hasMore() {
        return pos < data.length;
    }

    private int readByte() throws Exception {
        if (pos >= data.length) throw new Exception("EOF at pos " + pos);
        return data[pos++] & 0xFF;
    }

    private int readU16() throws Exception {
        if (pos + 2 > data.length) throw new Exception("EOF at pos " + pos);
        int v = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    private long readU32() throws Exception {
        if (pos + 4 > data.length) throw new Exception("EOF at pos " + pos);
        long v = ((data[pos] & 0xFFL) << 24) | ((data[pos + 1] & 0xFFL) << 16) |
                 ((data[pos + 2] & 0xFFL) << 8) | (data[pos + 3] & 0xFFL);
        pos += 4;
        return v;
    }

    private long readU64() throws Exception {
        if (pos + 8 > data.length) throw new Exception("EOF at pos " + pos);
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
        throw new Exception("Expected array, got 0x" + Integer.toHexString(b) + " at pos " + (pos-1));
    }

    public boolean readArraySizeFixed(int expected) throws Exception {
        long size = readArraySize();
        if (size != expected) {
            throw new Exception("Array size mismatch: expected " + expected + " got " + size + " at pos " + (pos-1));
        }
        return true;
    }

    public long readUint() throws Exception {
        int b = readByte();
        if (b <= 0x7f) return b;           // positive fixint
        if (b == 0xcc) return readByte();  // uint 8
        if (b == 0xcd) return readU16();   // uint 16
        if (b == 0xce) return readU32();   // uint 32
        if (b == 0xcf) return readU64();   // uint 64
        if (b >= 0xe0) return b - 256;     // negative fixint
        if (b == 0xd0) return (byte)readByte(); // int 8
        if (b == 0xd1) return (short)readU16(); // int 16
        if (b == 0xd2) return (int)readU32();   // int 32
        if (b == 0xd3) return readU64();        // int 64
        throw new Exception("Expected uint/int, got 0x" + Integer.toHexString(b) + " at pos " + (pos-1));
    }

    public boolean readBoolean() throws Exception {
        int b = readByte();
        if (b == 0xc2) return false;
        if (b == 0xc3) return true;
        // Fallback: sometimes booleans are packed as 0/1 integers
        if (b == 0xcc) { // uint 8
            int val = readByte();
            return val != 0;
        }
        if (b <= 0x7f) {
            return b != 0;
        }
        throw new Exception("Expected boolean, got 0x" + Integer.toHexString(b) + " at pos " + (pos-1));
    }

    public boolean readNil() throws Exception {
        int b = readByte();
        if (b == 0xc0) return true;
        throw new Exception("Expected nil, got 0x" + Integer.toHexString(b) + " at pos " + (pos-1));
    }

    public byte[] readBin() throws Exception {
        int b = readByte();
        int len;
        // Bin markers
        if (b == 0xc4) { // bin 8
            len = readByte();
        } else if (b == 0xc5) { // bin 16
            len = readU16();
        } else if (b == 0xc6) { // bin 32
            len = (int) readU32();
        } 
        // String markers (cmp often uses str for byte arrays like names/topics)
        else if (b >= 0xa0 && b <= 0xbf) { // fixstr
            len = b & 0x1f;
        } else if (b == 0xd9) { // str 8
            len = readByte();
        } else if (b == 0xda) { // str 16
            len = readU16();
        } else if (b == 0xdb) { // str 32
            len = (int) readU32();
        } else {
            throw new Exception("Expected bin/str, got 0x" + Integer.toHexString(b) + " at pos " + (pos-1));
        }
        if (pos + len > data.length) throw new Exception("EOF in bin/str at pos " + pos);
        byte[] res = Arrays.copyOfRange(data, pos, pos + len);
        pos += len;
        return res;
    }

    public byte[] readBinFixed(int expectedLen) throws Exception {
        byte[] b = readBin();
        if (b.length != expectedLen) {
            throw new Exception("Bin length mismatch: expected " + expectedLen + " got " + b.length + " at pos " + (pos - b.length));
        }
        return b;
    }

    public void skipValue() throws Exception {
        int b = readByte();
        if (b <= 0x7f) return; 
        if (b >= 0x80 && b <= 0x8f) { skipMap(b & 0x0f); return; }
        if (b >= 0x90 && b <= 0x9f) { skipArray(b & 0x0f); return; }
        if (b >= 0xa0 && b <= 0xbf) { skipBytes(b & 0x1f); return; } 
        if (b >= 0xe0) return; 

        switch (b) {
            case 0xc0: case 0xc2: case 0xc3: return; 
            case 0xc4: skipBytes(readByte()); return;
            case 0xc5: skipBytes(readU16()); return;
            case 0xc6: skipBytes((int)readU32()); return;
            case 0xc7: { int l = readByte(); skipBytes(1 + l); return; } 
            case 0xc8: { int l = readU16(); skipBytes(1 + l); return; }  
            case 0xc9: { int l = (int)readU32(); skipBytes(1 + l); return; } 
            case 0xca: skipBytes(4); return; 
            case 0xcb: skipBytes(8); return; 
            case 0xcc: skipBytes(1); return;
            case 0xcd: skipBytes(2); return;
            case 0xce: skipBytes(4); return;
            case 0xcf: skipBytes(8); return;
            case 0xd0: skipBytes(1); return;
            case 0xd1: skipBytes(2); return;
            case 0xd2: skipBytes(4); return;
            case 0xd3: skipBytes(8); return;
            case 0xd4: skipBytes(2); return;  
            case 0xd5: skipBytes(3); return;  
            case 0xd6: skipBytes(5); return;  
            case 0xd7: skipBytes(9); return;  
            case 0xd8: skipBytes(17); return; 
            case 0xd9: skipBytes(readByte()); return; 
            case 0xda: skipBytes(readU16()); return;
            case 0xdb: skipBytes((int)readU32()); return;
            case 0xdc: skipArray(readU16()); return;
            case 0xdd: skipArray((int)readU32()); return;
            case 0xde: skipMap(readU16()); return;
            case 0xdf: skipMap((int)readU32()); return;
        }
        throw new Exception("Unknown msgpack type 0x" + Integer.toHexString(b) + " at pos " + (pos-1));
    }

    private void skipBytes(int count) throws Exception {
        if (pos + count > data.length) throw new Exception("EOF at pos " + pos);
        pos += count;
    }

    private void skipArray(int count) throws Exception {
        for (int i = 0; i < count; i++) skipValue();
    }

    private void skipMap(int count) throws Exception {
        for (int i = 0; i < count * 2; i++) skipValue();
    }
}
