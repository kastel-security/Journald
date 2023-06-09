package journald;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.HashMap;

import javax.crypto.Mac;

import journald.JournalObject.EntryObject;
import journald.JournalObject.TagObject;

public class Journal {

	public static void main(String[] args) throws IOException, GeneralSecurityException {
		FSPRNGKey key = new FSPRNGKey("5ff23e-2eb86e-40aaf1-c19528/1c7dff-35a4e900");
		Path target = Paths.get(
				"testdata/logs/journal/df960f53188843b8ac3c88fef7075463/system.journal");
		JournalFileBuffer mapped = JournalFileBuffer.open(target, false);

		Header h = Header.readHeader(mapped);
		JournalMacChecker jmc = new JournalMacChecker(mapped, key, h);
		long lastReal = 0;
		long firstReal = 0;
		for (int i = 0; i < h.nObjects; i++) {
			JournalObject obj = JournalObject.read(mapped, jmc);
			if (obj instanceof EntryObject) {
				long real = ((EntryObject) obj).real;
				System.out.println("Entry@" + real);
				if (real < lastReal) {
					throw new Error();
				}
				lastReal = real;
				if (firstReal == 0) {
					firstReal = real;
				}
			}
			if (obj instanceof TagObject) {
				if (firstReal != 0) {
					key.validateEpoch(firstReal, lastReal, ((TagObject) obj).epoch);
				}
				firstReal = 0;
			}
		}
		System.out.println(Long.toHexString(h.nObjects));
		if (false) {
			// append new mac
			mapped.put((byte) 7);
			mapped.put((byte) 0);
			mapped.put(new byte[6]);
			mapped.putLong(64);
			mapped.putLong(4);
			mapped.putLong(7000);
			mapped.put(jmc.getNextMac(mapped.position() + 32, 7000));
		}
		System.out.println("Done@" + Integer.toHexString(mapped.position()));
		System.out.println(mapped.remaining());
		JournalObject.read(mapped, jmc);

		if (fieldMap.size() != h.nFields) {
			throw new Error();
		}
		if (dataMap.size() != h.nData) {
			throw new Error();
		}

		checkHashMapContents(h.sliceFieldMap(mapped), fieldMap);
		checkHashMapContents(h.sliceDataMap(mapped), dataMap);
	}

	private static <T extends HashedObject> void checkHashMapContents(JournalFileBuffer fieldHash,
			HashMap<Long, T> objMap) throws Error {
		int hashSize = fieldHash.remaining() / 16;
		int nObjs = 0;
		while (fieldHash.hasRemaining()) {
			long head = fieldHash.getLong();
			long tail = fieldHash.getLong();
			if (head != 0) {
				HashedObject fo = objMap.get(head);
				long hash = fo.reduceHash(hashSize);
				nObjs++;
				while (fo.getNextHashOff() != 0) {
					head = fo.getNextHashOff();
					nObjs++;
					fo = objMap.get(head);
					if (fo.reduceHash(hashSize) != hash) {
						throw new Error();
					}
				}
			}
			if (head != tail) {
				throw new Error();
			}
		}
		if (objMap.size() != nObjs) {
			throw new Error();
		}
	}

	public static void hash(JournalFileBuffer mapped, Mac m, int off, int len) {
		m.update(mapped.slice(off, len).getDelegate());
	}

	static HashMap<Long, JournalObject.DataObject> dataMap = new HashMap<>();
	static HashMap<Long, JournalObject.FieldObject> fieldMap = new HashMap<>();

	private static DateFormat sdf = SimpleDateFormat.getTimeInstance();

	public static class Header {
		int compatibleFlags;
		int incompatibleFlags;

		long arenaSize, dataHashOffset, dataHashSize, fieldHashOffset, fieldHashSize;
		long tailObjectOffset;

		long nObjects, nEntries, nData, nFields, nTags;
		public final long headerSize;
		public UUID fileid;

		private Header(JournalFileBuffer bb) {
			// https://github.com/systemd/systemd/blob/31b5f920168c5366b28040592fc72f4226575112/src/libsystemd/sd-journal/journal-def.h

			long signature = bb.getLong();
			if (signature != 0x48524848534b504cL) {
				throw new Error();
			}
			compatibleFlags = bb.getInt();
			incompatibleFlags = bb.getInt();
			System.out.println(bb.get()); // State
			bb.position(bb.position() + 7); // reserved
			fileid = readU128(bb); // fileid
			readU128(bb); // machineid
			readU128(bb); // bootid
			readU128(bb); // seqnumid
			headerSize = bb.getLong();
			if (headerSize < 0xf0) {
				throw new Error(Long.toHexString(headerSize));
			}
			arenaSize = bb.getLong();
			dataHashOffset = bb.getLong();
			dataHashSize = bb.getLong();
			fieldHashOffset = bb.getLong();
			fieldHashSize = bb.getLong();
			tailObjectOffset = bb.getLong();

			nObjects = bb.getLong();
			nEntries = bb.getLong();

			long headSeq = bb.getLong();
			long tailSeq = bb.getLong();
			long entryArrayOffset = bb.getLong();

			long hRealtime = bb.getLong();
			long tRealtime = bb.getLong();
			long tMonotonic = bb.getLong();

			// from 187
			nData = bb.getLong();
			nFields = bb.getLong();

			// from 189
			nTags = bb.getLong();
			long nEntryArrays = bb.getLong();

			if (headerSize > 0xf0) {
				// from 246
				long dataHashDepth = bb.getLong();
				long fieldHashDepth = bb.getLong();
			}
			if (headerSize > 0x100) {
				bb.getLong();
				bb.getLong();
			}
			if (headerSize > 0x110) {
				throw new Error(Long.toHexString(headerSize));
			}

			System.out.println("Objects: " + nObjects);
			System.out.println("Entries: " + nEntries);
			System.out.println("Tags: " + nTags);
		}

		public JournalFileBuffer sliceFieldMap(JournalFileBuffer mapped) {
			return mapped.slice((int) fieldHashOffset, (int) fieldHashSize);
		}

		public JournalFileBuffer sliceDataMap(JournalFileBuffer mapped) {
			return mapped.slice((int) dataHashOffset, (int) dataHashSize);
		}

		public static Journal.Header readHeader(JournalFileBuffer bb) {
			Header h = new Header(bb);
			return h;
		}
	}

	static class UUID {
		long l1;
		long l2;

		public UUID(long l1, long l2) {
			super();
			this.l1 = l1;
			this.l2 = l2;
		}

	}

	public static UUID readU128(JournalFileBuffer bb) {
		return new UUID(bb.getLong(), bb.getLong());

	}

}
