package journald;

import java.io.ByteArrayOutputStream;
import java.io.IOError;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Challenger {
	public String JOURNALCTL = "journalctl";
	private Attacker a;

	public interface LogAdapter {
		public void log(String message);

		public void advanceEpoch();

		public JournalFileBuffer obtainJournal();

	}

	public interface Attacker {
		public void interactWithLog(LogAdapter l);

		public void tamperWithLogfile(JournalFileBuffer mapped, FSPRNGKey key);
	}

	public static class AttackFailedException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		public AttackFailedException(String cause) {
			super(cause);
		}
	}

	Path journal;
	Path journalPatched;
	Path keyFile;
	private String sealingKey;
	private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	private JournalSystem js;

	public Challenger(Attacker a) throws IOException, InterruptedException {
		this.a = a;
		js = JournalSystem.createInstance();
		js.setupKeys();

		Path base = Paths.get(js.getJournalBasePath());

		this.journal = base.resolve("system.journal");
		this.keyFile = base.resolve("fss");
		this.sealingKey = js.getVerificationKey();
		this.journalPatched = journal.resolveSibling(journal.getFileName() + ".patched");
	}

	public void experiment() throws IOException, ParseException, InterruptedException {
		try {
			js.startJournald();
			experimentWithJournal();
		} finally {
			js.stopJournald();
		}
	}

	public void experimentWithJournal() throws IOException, ParseException {
		AtomicBoolean inPhase1 = new AtomicBoolean(true);
		a.interactWithLog(getLogAdapter(inPhase1));
		inPhase1.set(false);

		// Break-in Phase
		Files.copy(journal, journalPatched, StandardCopyOption.REPLACE_EXISTING);
		JournalFileBuffer fileToModify = JournalFileBuffer.open(journalPatched, true);
		FSPRNGKey key = new FSPRNGKey(JournalFileBuffer.open(keyFile, false));

		a.tamperWithLogfile(fileToModify, key);

		Date untilAttacker = verifyJournal(journalPatched);
		Date untilOriginal = verifyJournal(journal);
		if(untilAttacker.getTime() < untilOriginal.getTime()) {
			throw new AttackFailedException("Attacker patched journal is sealed less");
		}
		String untilOffByOne = dateFormat
				.format(new Date(untilOriginal.getTime() + 1000));

		byte[] reply = runProcess(JOURNALCTL, "--file=" + journal, "-U", untilOffByOne);
		byte[] replyPatched = runProcess(JOURNALCTL, "--file=" + journalPatched, "-U", untilOffByOne);
		if (Arrays.equals(reply, replyPatched)) {
			throw new AttackFailedException("Output does not differ");
		} else {
			System.out.println("Attack Succeeded");
		}
	}

	private Date verifyJournal(Path filename) throws IOException, ParseException {
		return dateFormat.parse(verify(JOURNALCTL, "--verify", "--verify-key=" + sealingKey, "--file=" + filename));
	}

	private LogAdapter getLogAdapter(AtomicBoolean inPhase1) {
		return new LogAdapter() {

			@Override
			public JournalFileBuffer obtainJournal() {
				if (!inPhase1.get()) {
					throw new AttackFailedException("Wrong phase");
				}
				try {
					return new JournalFileBuffer(ByteBuffer.wrap(Files.readAllBytes(journal)));
				} catch (IOException e) {
					throw new IOError(e);
				}
			}

			@Override
			public void log(String message) {
				if (!inPhase1.get()) {
					throw new AttackFailedException("Wrong phase");
				}
				try {
					js.log(message);
				} catch (IOException e) {
					throw new IOError(e);
				} catch (InterruptedException e) {
					throw new Error(e);
				}
			}

			@Override
			public void advanceEpoch() {
				if (!inPhase1.get()) {
					throw new AttackFailedException("Wrong phase");
				}
				try {
					js.epoch();
				} catch (IOException e) {
					throw new IOError(e);
				}
			}
		};
	}

	private static byte[] runProcess(String... command) throws IOException {
		Process p = Runtime.getRuntime().exec(command);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		p.getInputStream().transferTo(baos);
		ByteArrayOutputStream beos = new ByteArrayOutputStream();
		p.getErrorStream().transferTo(beos);
		try {
			if (p.waitFor() != 0) {
				throw new Error();
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return baos.toByteArray();
	}

	private static String verify(String... command) throws IOException {
		Pattern pat = Pattern.compile(
				"=> Validated from [a-zA-Z0-9 :-]* to ([a-zA-Z0-9 :-]*), final [0-9a-z. ]* entries not sealed.");
		Process p = Runtime.getRuntime().exec(command);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		p.getInputStream().transferTo(baos);
		ByteArrayOutputStream beos = new ByteArrayOutputStream();
		p.getErrorStream().transferTo(beos);
		try {
			if (p.waitFor() != 0) {
				throw new Error(new String(beos.toByteArray(), StandardCharsets.UTF_8));
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		if (baos.toByteArray().length != 0) {
			throw new Error();
		}
		String output = new String(beos.toByteArray(), StandardCharsets.UTF_8);
		Matcher m = pat.matcher(output);
		if (!m.find()) {
			throw new Error(output);
		}
		return m.group(1).substring(4, 4 + 19);
	}
}
