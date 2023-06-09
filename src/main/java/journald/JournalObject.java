package journald;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import com.google.common.hash.HashFunction;

public class JournalObject {
	protected JournalFileBuffer bb;

	static class DataObject extends JournalObject implements HashedObject {
		private byte[] data;
		private long hash;
		private long nextHashOff;
		private long entryOff;
		private long nEntries;

		public DataObject(JournalFileBuffer bb) {
			super(bb);
			hash = bb.getLong();
			nextHashOff = bb.getLong();
			long nextFieldOff = bb.getLong();
			entryOff = bb.getLong();
			long entryArrayOff = bb.getLong();
			nEntries = bb.getLong();
			data = new byte[bb.remaining()];
			bb.get(data);
		}

		@Override
		public String toString() {
			return new String(data, StandardCharsets.UTF_8);
		}

		@Override
		public long getHash() {
			return hash;
		}

		public long getNextHashOff() {
			return nextHashOff;
		}

		public byte[] getData() {
			return data;
		}

		public void rehash(HashFunction hasher) {
			this.hash = hasher.hashBytes(data).asLong();
		}

		public void writeBack() {
			bb.putLong(0, hash);
			bb.put(8 * 6, data);

		}

		public long getEntryOff() {
			return entryOff;
		}

		public long getNEntries() {
			return nEntries;
		}

	}

	static class FieldObject extends JournalObject implements HashedObject {

		private long hash;
		private long nextHashOff;
		private long firstData;
		private byte[] datas;

		public FieldObject(JournalFileBuffer sub) {
			super(sub);
			hash = sub.getLong();
			nextHashOff = sub.getLong();
			firstData = sub.getLong();
			datas = new byte[sub.remaining()];
			sub.get(datas);
		}

		public long getHash() {
			return hash;
		}

		public long getNextHashOff() {
			return nextHashOff;
		}
	}

	static class EntryObject extends JournalObject implements Iterable<DataObject> {

		public long monotonic;
		public long real;

		public EntryObject(JournalFileBuffer sub) {
			super(sub);
			long seq = sub.getLong();
			real = sub.getLong();
			monotonic = sub.getLong();
			Journal.readU128(sub);
			long xorhash = sub.getLong();
			// System.out.println("Entry@" + ": " + sdf.format(new Date(real / 1000)));
			for (int i = 0; sub.hasRemaining(); i++) {
				long object = sub.getLong();
				if (false && Journal.dataMap.get(object).toString().startsWith("MESSAGE="))
					System.out.println(Journal.dataMap.get(object) + ";");
				long hash = sub.getLong();
			}
		}

		public Iterator<DataObject> iterator() {
			JournalFileBuffer myView = getBodyBytebuffer();
			return new Iterator<JournalObject.DataObject>() {

				@Override
				public boolean hasNext() {
					return myView.hasRemaining();
				}

				@Override
				public DataObject next() {
					long obj = myView.getLong();
					long hash = myView.getLong();
					return Journal.dataMap.get(obj);
				}

			};
		}

		public JournalFileBuffer getBodyBytebuffer() {
			bb.position(16 * 3);
			JournalFileBuffer myView = bb.slice();
			return myView;
		}

	}

	static class EntryArrayObject extends JournalObject {

		public EntryArrayObject(JournalFileBuffer sub) {
			super(sub);
			long nextEntryOff = sub.getLong();
			// System.out.println("EntryArray@" + start + ": " + (size - 16 - 8) / 8 + "
			// next: " + nextEntryOff);
			while (sub.hasRemaining()) {
				long object = sub.getLong();
				// System.out.println(object);
			}
		}

	}

	static class TagObject extends JournalObject {

		private long seqnum;
		public long epoch;
		private byte[] mac;

		private long localStart;

		public TagObject(JournalFileBuffer sub) {
			super(sub);
			if (sub.remaining() != 8 + 8 + 32) {
				throw new Error(sub.remaining() + "");
			}
			seqnum = sub.getLong();
			epoch = sub.getLong();
			System.out.println("Tag: " + seqnum + "/" + epoch);
			mac = new byte[32];
			sub.get(mac);
			localStart = sub.position();

		}

		public TagObject check(JournalMacChecker jmc) {
			if (jmc == null) {
				return this;
			}
			jmc.advanceSeqnum(seqnum);
			jmc.check(bb.getOffsetFrom(jmc.data) + localStart, epoch, mac);
			// System.out.println(new BigInteger(1, mac).toString(16));
			return this;
		}

		public byte[] getMac() {
			return mac;
		}

		public long getEpoch() {
			return epoch;
		}

		public void setEpoch(long epoch) {
			this.epoch = epoch;
		}

		public void setMac(byte[] mac) {
			this.mac = mac;
		}

		public void writeBack() {
			bb.putLong(8, epoch);
			bb.put(16, mac);
		}

		public long getMacRangeEnd(JournalFileBuffer mapped) {
			return bb.getOffsetFrom(mapped) + localStart;
		}

	}

	public JournalObject(JournalFileBuffer bb) {
		this.bb = bb;
	}

	public static JournalObject read(JournalFileBuffer bb, JournalMacChecker jmc) {
		long start = bb.position();
		byte type = bb.get();
		byte flags = bb.get();
		bb.position(bb.position() + 6); // reserved
		long size = bb.getLong();
		int newPosition = (int) (bb.position() + size - 16);
		newPosition = (newPosition + 7) & (~7);
		if (size == 0) {
			return null;
		}
		JournalFileBuffer sub = bb.slice(bb.position(), (int) size - 16);
		bb.position(newPosition);
		if (type == 1) {
			JournalObject.DataObject result = new DataObject(sub);
			Journal.dataMap.put(start, result);
			return result;
		} else if (type == 2) {
			JournalObject.FieldObject result = new FieldObject(sub);
			Journal.fieldMap.put(start, result);
			return result;
		} else if (type == 3) {
			return new EntryObject(sub);
		} else if (type == 6) { // EntryArray
			return new EntryArrayObject(sub);
		} else if (type == 7) { // Tag
			return new TagObject(sub).check(jmc);
		} else {
			System.out.println("Object of type " + type + " flags " + flags + " size " + size);
		}
		return null;
	}
}