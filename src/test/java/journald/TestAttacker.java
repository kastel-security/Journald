package journald;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Paths;
import java.text.ParseException;

import org.junit.jupiter.api.Test;

import journald.Attacker;
import journald.Challenger;
import journald.FSPRNGKey;
import journald.JournalFileBuffer;
import journald.Challenger.LogAdapter;

class TestAttacker {

	@Test
	void testEmpty() throws IOException, ParseException, InterruptedException {
		Challenger.Attacker attacker = new Challenger.Attacker() {

			@Override
			public void tamperWithLogfile(JournalFileBuffer mapped, FSPRNGKey key) {
				// No-op
			}

			@Override
			public void interactWithLog(LogAdapter l) {
				l.log("hello");
				l.advanceEpoch();
				l.log("hello");
			}
			
		};
		Challenger c = new Challenger(attacker);
		assertThrows(Challenger.AttackFailedException.class, c::experiment);
	}
	
	@Test
	void testModifying() throws IOException, ParseException, InterruptedException {
		Challenger.Attacker attacker = new Attacker();
		Challenger c = new Challenger(attacker);
		c.experiment();
	}
}
