package journald;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

import journald.FSPRNGKey;
import journald.JournalFileBuffer;


class TestFSPRNG {
	FSPRNGKey key = new FSPRNGKey("bf10b7-475683-760414-8cbe5e/1c3fa1-35a4e900");

	@Test
	void testBasic() {
		assertEquals("bf10b74756837604148cbe5e", new BigInteger(1, key.seed).toString(16));
		assertEquals(key.getLin(0x19f2), key.getFast(0x19f2));
		assertEquals(key.getLin(0), key.x);
	}

	@Test
	void testFile() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		TestFSPRNG.class.getResourceAsStream("fss").transferTo(baos);
		FSPRNGKey fromFile = new FSPRNGKey(new JournalFileBuffer(ByteBuffer.wrap(baos.toByteArray())));
		assertEquals(fromFile.getLin(fromFile.getMinEpoch()), fromFile.x);
		assertEquals(key.getLin(fromFile.getMinEpoch()), fromFile.getLin(fromFile.getMinEpoch()));
		assertEquals(key.getFast(fromFile.getMinEpoch()), fromFile.getLin(fromFile.getMinEpoch()));
		
	}
	

}
