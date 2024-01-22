package journald;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import journald.JournalFileBuffer;
import journald.JournalObject;
import journald.JournalSystem;
import journald.Journal.Header;
import journald.JournalObject.TagObject;

class TestEpochSkipping {
	@Test
	void test() throws IOException, InterruptedException {
		JournalSystem js = JournalSystem.createInstance();

		js.setupKeys();
		js.startJournald();
		JournalFileBuffer mapped = js.getJournal();
		try {
			js.log("hello");
			js.verifyJournal();
			js.epoch();
			js.log("hello2");

			js.verifyJournal();
			js.epoch();
			js.epoch();
			js.epoch();
			js.log("hello3");
			js.verifyJournal();
			js.rotateJournal();
		} finally {
			Thread.sleep(200);
			js.stopJournald();
		}
		js.verifyJournal();
		String[] archived = js.getArchivedJournals();
		assertEquals(1, archived.length);
		js.verifyJournal(archived[0]);
		JournalFileBuffer rotated = js.reopen();
		{
			Header h1 = Header.readHeader(rotated);
			for (int i = 0; i < h1.nObjects; i++) {
				JournalObject obj = JournalObject.read(rotated, null);
				if (obj instanceof TagObject) {
					System.out.println(obj);
				}
			}
		}
		
		Header h = Header.readHeader(mapped);
		System.out.println("IncompatibleFlags: " + Integer.toHexString(h.incompatibleFlags));
		System.out.println("CompatibleFlags: " + Integer.toHexString(h.compatibleFlags));
		long prev = 0;
		boolean foundJump = false;
		for (int i = 0; i < h.nObjects; i++) {
			JournalObject obj = JournalObject.read(mapped, null);
			if (obj instanceof TagObject) {
				long epoch = ((TagObject) obj).getEpoch();
				if (epoch != prev && epoch != prev + 1) {
					foundJump = true;
				}
				prev = epoch;
			}
		}
		assertTrue(foundJump);
	}
}
