package journald;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class FSPRNGKey {
	byte[] seed = new byte[12];

	private BigInteger n;
	BigInteger x;

	private BigInteger phi;

	private long epoch = 0;

	public BigInteger getN() {
		return n;
	}

	private long start_usec;
	private long interval_usec;

	public FSPRNGKey(JournalFileBuffer fssFile) {
		byte[] magic = "KSHHRHLP".getBytes(StandardCharsets.US_ASCII);
		byte[] readMagic = new byte[magic.length];
		fssFile.get(readMagic);
		if (!Arrays.equals(magic, readMagic)) {
			throw new Error("Magic mismatch");
		}
		int compatibleFlags = fssFile.getInt();
		int incompatibleFlags = fssFile.getInt();
		if (incompatibleFlags != 0)
			throw new Error();
		Journal.readU128(fssFile);// machine
		Journal.readU128(fssFile);// boot
		long headerSize = fssFile.getLong();
		if (headerSize < 0x58) {
			throw new Error();
		}
		start_usec = fssFile.getLong();// start_usec
		interval_usec = fssFile.getLong();// interval_usec
		fssFile.getLong();// 2byte secpar + reserved
		long stateSize = fssFile.getLong();// stateSize;
		if (stateSize + headerSize != fssFile.capacity()) {
			throw new Error(stateSize + headerSize + " != " + fssFile.capacity());
		}
		fssFile.position((int) headerSize);

		fssFile.getDelegate().order(ByteOrder.BIG_ENDIAN);
		int secpar = 16 * ((fssFile.getShort() & 0xFFFF) + 1);
		byte[] numdata = new byte[secpar / 8];
		fssFile.get(numdata);
		n = new BigInteger(1, numdata);
		fssFile.get(numdata);
		x = new BigInteger(1, numdata);
		epoch = fssFile.getLong();
	}

	public FSPRNGKey(String seed) {
		int j = 0;
		for (int i = 0; i < seed.length(); i++) {
			char c = seed.charAt(i);
			if (c == '-') {
				continue;
			}
			if (c == '/') {
				break;
			}
			int b = unhex(c) * 16 + unhex(seed.charAt(++i));
			this.seed[j++] = (byte) b;
		}
		String[] parts = seed.split("/", 2)[1].split("-", 2);
		interval_usec = Long.parseLong(parts[1], 16);
		start_usec = interval_usec * Long.parseLong(parts[0], 16);
		if (j != this.seed.length)
			throw new Error();

		BigInteger p = genprime3mod4(FSPRNGKey.SECPAR / 2, FSPRNGKey.RND_GEN_P);
		BigInteger q = genprime3mod4(FSPRNGKey.SECPAR / 2, FSPRNGKey.RND_GEN_Q);
		n = p.multiply(q);
		phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		x = gensquare(n, FSPRNGKey.RND_GEN_X, FSPRNGKey.SECPAR);

	}

	// x^(2^e) = x^(2^e (mod phi) )
	BigInteger getFast(long epoch) {
		return x.modPow(BigInteger.TWO.modPow(BigInteger.valueOf(epoch), phi), n);
	}

	public BigInteger getState(long epoch) {
		if (this.epoch == 0 && this.phi != null) {
			return getFast(epoch);
		}
		return getLin(epoch);
	}

	public long getMinEpoch() {
		return epoch;
	}

	// x -> x^2 -> x^4, x^8,... x^(2^e)
	BigInteger getLin(long epoch) {
		if (epoch < this.epoch) {
			throw new Error(epoch + " < " + this.epoch);
		}
		epoch -= this.epoch;
		BigInteger r = x;
		for (int i = 0; i < epoch; i++) {
			r = r.multiply(r).mod(n);
		}
		return r;
	}

	/*
	 * deterministically generate from seed/idx a string of buflen pseudorandom
	 * bytes
	 */
	private byte[] det_randomize(int buflen, int idx) {
		return det_randomize(buflen, seed, idx);
	}

	private byte[] det_randomize(int buflen, byte[] seed, int idx) {
		try {
			MessageDigest dgst = MessageDigest.getInstance("SHA256");

			dgst.update(seed);
			dgst.update((byte) (idx >> 24));
			dgst.update((byte) (idx >> 16));
			dgst.update((byte) (idx >> 8));
			dgst.update((byte) (idx >> 0));

			byte[] out = new byte[buflen];
			int outpos = 0;

			for (int ctr = 0; buflen > 0; ctr++) {
				MessageDigest dgs = (MessageDigest) dgst.clone();
				dgs.update((byte) (ctr >> 24));
				dgs.update((byte) (ctr >> 16));
				dgs.update((byte) (ctr >> 8));
				dgs.update((byte) (ctr >> 0));
				byte[] buf = dgs.digest();
				int cpylen = (buflen < buf.length) ? buflen : buf.length;
				System.arraycopy(buf, 0, out, outpos, cpylen);
				outpos += cpylen;
				buflen -= cpylen;
			}
			return out;
		} catch (NoSuchAlgorithmException e) {
			throw new Error(e);
		} catch (CloneNotSupportedException e) {
			throw new Error(e);
		}
	}

	private static int SECPAR = 1536;

	/*
	 * deterministically generate from seed/idx a prime of length `bits' that is 3
	 * (mod 4)
	 */
	private BigInteger genprime3mod4(int bits, int idx) {
		int buflen = bits / 8;

		assert (bits % 8 == 0);
		assert (buflen > 0);

		byte[] buf = det_randomize(buflen, idx);
		buf[0] |= 0xc0; /* set upper two bits, so that n=pq has maximum size */
		buf[buflen - 1] |= 0x03; /* set lower two bits, to have result 3 (mod 4) */

		BigInteger p = new BigInteger(1, buf);

		while (!p.isProbablePrime(40))
			p = p.add(BigInteger.valueOf(4));
		return p;
	}

	private BigInteger gensquare(BigInteger n, int idx, int secpar) {
		int buflen = secpar / 8;
		byte[] buf = det_randomize(buflen, idx);
		buf[0] &= 0x7f; /* clear upper bit, so that we have x < n */
		BigInteger x = new BigInteger(1, buf);
		assert (x.compareTo(n) < 0);
		return x.multiply(x).mod(n);
	}

	private int unhex(char c) {
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		}
		throw new Error();
	}

	Mac deriveHmac(BigInteger state, int keylen, int idx, long epoch) throws GeneralSecurityException {
		byte[] allseed = new byte[(SECPAR / 8) * 2 + 8];
		getBytes(n, allseed, 0);
		getBytes(state, allseed, SECPAR / 8);
		ByteBuffer.wrap(allseed).order(ByteOrder.BIG_ENDIAN).putLong((SECPAR / 8) * 2, epoch);

		String macalg = "HmacSHA256";
		Mac mac = Mac.getInstance(macalg);
		byte[] mackey = det_randomize(keylen, allseed, idx);
		mac.init(new SecretKeySpec(mackey, macalg));
		return mac;
	}

	private void getBytes(BigInteger n, byte[] buf, int off) {
		byte[] contents = n.toByteArray();
		if (contents.length > SECPAR / 8) {
			System.arraycopy(contents, contents.length - SECPAR / 8, buf, off, SECPAR / 8);
		} else {
			System.arraycopy(contents, 0, buf, off + SECPAR / 8 - contents.length, contents.length);
		}
	}

	private static int RND_GEN_P = 1;
	private static int RND_GEN_Q = 2;
	private static int RND_GEN_X = 3;

	public void validateEpoch(long start, long end, long epoch) {
		if (start < epoch * interval_usec + start_usec) {
			throw new Error();
		}
		if (end >= (epoch + 1) * interval_usec + start_usec) {
			printEpoc(epoch);
			throw new Error(sdf.format(new Date(end / 1000)) + " after end of epoch at "
					+ sdf.format(new Date(((epoch + 1) * interval_usec + start_usec) / 1000)));
		}
	}

	private static DateFormat sdf = SimpleDateFormat.getDateTimeInstance();

	public void printEpoc(long epoch) {
		System.out.println(sdf.format(new Date((epoch * interval_usec + start_usec) / 1000)) + "--"
				+ sdf.format(new Date(((epoch + 1) * interval_usec + start_usec) / 1000)));
	}
}