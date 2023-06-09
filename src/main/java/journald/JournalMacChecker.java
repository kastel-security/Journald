package journald;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;

import journald.Journal.Header;

public class JournalMacChecker {
	long macedUntil = 0;
	JournalFileBuffer data;
	private FSPRNGKey key;
	long headerSize;

	public JournalMacChecker(JournalFileBuffer data, FSPRNGKey key, Header h) {
		this.data = data.slice(0, data.capacity());
		this.key = key;
		headerSize = h.headerSize;
	}

	public byte[] getNextMac(long targetPos, long epoch) {
		return getNextMac(targetPos, epoch, key.getState(epoch));
	}

	// see
	// https://github.com/systemd/systemd/blob/71eaa9291d407b49c66c99adb0cb8d6a6eca6c89/src/libsystemd/sd-journal/journal-verify.c#L1163
	public byte[] getNextMac(long targetPos, long epoch, BigInteger epochKey) {
		System.out.println("Macing from " + macedUntil + " to " + targetPos);
		Mac m;
		try {
			m = key.deriveHmac(epochKey, 256 / 8, 0, epoch);
		} catch (GeneralSecurityException e) {
			throw new Error(e);
		}
		if (macedUntil == 0) {
			Journal.hash(data, m, 0, 8 + 4 + 4);
			Journal.hash(data, m, 24, 16 * 2);
			Journal.hash(data, m, 72, 16 + 8);
			Journal.hash(data, m, 104, 4 * 8);
			long offsetFHT = data.getInt(104 + 16);
			long offsetDHT = data.getInt(104);
			long sizeFHT = data.getInt(104 + 16 + 8);
			long sizeDHT = data.getInt(104 + 8);
			data.position((int) headerSize);
		} else {
			data.position((int) macedUntil);
		}
		while (data.position() < targetPos) {
			hashObject(m);
		}
		macedUntil = targetPos;
		byte[] recalced = m.doFinal();
		return recalced;
	}

	public void check(long targetPos, long epoch, byte[] hash) {
		key.printEpoc(epoch);
		if (!Arrays.equals(getNextMac(targetPos, epoch), hash)) {
			throw new Error("Mac mismatch");
		}
	}

	public long getMacedUntil() {
		return macedUntil;
	}

	public void setMacedUntil(long macedUntil) {
		this.macedUntil = macedUntil;
	}

	private void hashObject(Mac m) {
		Journal.hash(data, m, data.position(), 16);
		byte type = data.get();
		byte flags = data.get();
		data.position(data.position() + 6); // reserved
		long size = data.getLong();
		int newPosition = (int) (data.position() + size - 16);
		newPosition = (newPosition + 7) & (~7);

		switch (type) {
		case 1:// OBJECT_DATA
			Journal.hash(data, m, data.position(), 8);
			Journal.hash(data, m, data.position() + 6 * 8, (int) (size - 16 - 6 * 8));
			break;
		case 2:// OBJECT_FIELD
			Journal.hash(data, m, data.position(), 8);
			Journal.hash(data, m, data.position() + 3 * 8, (int) (size - 16 - 3 * 8));
			break;
		case 3:// OBJECT_FENTRY
			Journal.hash(data, m, data.position(), (int) (size - 16));
			break;
		case 4:
		case 5:
		case 6:
			/* Nothing: everything is mutable */
			break;

		case 7:
			Journal.hash(data, m, data.position(), 16);
			break;
		default:
			throw new Error("UnknownType: " + type);

		}

		data.position(newPosition);
	}

	long seqnum = 1;

	public void advanceSeqnum(long seqnum) {
		if (this.seqnum != seqnum) {
			throw new Error();
		}
		this.seqnum++;
	}
}