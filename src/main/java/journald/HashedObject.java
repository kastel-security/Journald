package journald;

public interface HashedObject {
	long getHash();

	long getNextHashOff();

	public default long reduceHash(int mod) {
		long hashed = getHash();
		if (hashed < 0) {
			hashed = hashed & 0x7fffffffffffffffL;
			hashed %= mod;
			hashed += 0x4000000000000000L % mod;
			hashed += 0x4000000000000000L % mod;
			hashed %= mod;
		} else {
			hashed %= mod;
		}
		return hashed;
	}

}