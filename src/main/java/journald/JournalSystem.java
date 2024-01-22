package journald;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedList;

public class JournalSystem {

	private final String machineid;
	public final String journald;
	public final String journalctl;
	private Path testdata;
	private String vk;
	private Process journaldProcess;

	private JournalFileBuffer journalFile;

	public JournalSystem(String buildRoot) throws IOException {
		machineid = Files.readString(Paths.get("/etc/machine-id")).trim();
		if (buildRoot == null) {
			journalctl = "journalctl";
			journald = "/lib/systemd/systemd-journald";
		} else {
			journalctl = buildRoot + "/build/journalctl";
			journald = buildRoot + "/build/systemd-journald";
		}
		testdata = Paths.get("testdata");
		wipe();
	}

	public void stopJournald() {
		journaldProcess.descendants().forEach(p -> {
			p.destroy();
			System.out.println(p.pid());
		});
	}

	public void startJournald() throws IOException, InterruptedException {
		journaldProcess = Runtime.getRuntime().exec(new String[] { "bwrap", "--unshare-user", "--uid", "0", //
				"--bind", "/", "/", //
				"--dev-bind", "/dev", "/dev", //
				"--bind", "testdata/runtime", "/run/systemd/journal", //
				"--bind", "testdata/logs", "/var/log", //
				"env", "LANG=C.UTF-8", "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1", //
				"FAKETIME_TIMESTAMP_FILE=faketimefile", "FAKETIME_NO_CACHE=1", "SYSTEMD_JOURNAL_COMPACT=0", //
				this.journald });
		System.out.println("Waiting for journald");
		while (!journalReady()) {
			Thread.sleep(50);
		}

	}

	private boolean journalReady() throws IOException {
		Path path = Paths.get(getJournalBasePath() + "/system.journal");
		if (!Files.exists(path)) {
			return false;
		}
		journalFile = JournalFileBuffer.open(path, false);
		return getNEntries() >= 2;
	}

	public void setupKeys() throws IOException, InterruptedException, Error {
		Process setupkeys = Runtime.getRuntime().exec(new String[] { "bwrap", "--unshare-user", "--uid", "0", //
				"--bind", "/", "/", //
				"--dev-bind", "/dev", "/dev", //
				"--bind", "testdata/runtime", "/run/systemd/journal", //
				"--bind", "testdata/logs", "/var/log", //
				journalctl, "--setup-keys" });
		vk = new String(setupkeys.getInputStream().readAllBytes(), StandardCharsets.US_ASCII);
		System.out.println(vk);
		if (setupkeys.waitFor() != 0) {
			throw new Error("Key setup failed");
		}
		setupkeys.getErrorStream().transferTo(System.out);
	}

	public void wipe() throws IOException {
		Files.walk(testdata).sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
		Files.createDirectories(testdata.resolve("logs").resolve("journal").resolve(machineid));
		Path runtime = testdata.resolve("runtime");
		Files.createDirectories(runtime);
		Files.createFile(runtime.resolve("flushed"));
		faketime("+0min x1");
	}

	int minsSinceStart = 0;

	private void faketime(String faketime) throws IOException {
		Files.write(Paths.get("faketimefile"), faketime.getBytes(StandardCharsets.US_ASCII));
	}

	public void epoch() throws IOException {
		minsSinceStart += 15;
		faketime("+" + minsSinceStart + "min x1");
	}

	public void verifyJournal() throws IOException, InterruptedException {
		verifyJournal(getVirtualJournalPath());
	}

	public void verifyJournal(String path) throws IOException, InterruptedException {
		String[] command = new String[] { "bwrap", "--unshare-user", "--uid", "0", //
				"--bind", "/", "/", //
				"--dev-bind", "/dev", "/dev", //
				"--bind", "testdata/runtime", "/run/systemd/journal", //
				"--bind", "testdata/logs", "/var/log", //
				"env", "LANG=C.UTF-8", "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1", //
				"FAKETIME_TIMESTAMP_FILE=faketimefile", "FAKETIME_NO_CACHE=1", //
				journalctl, "--verify", "--verify-key=" + vk, "--file=" + path };
		Process verify = Runtime.getRuntime().exec(command);
		verify.getInputStream().transferTo(System.out);
		verify.getErrorStream().transferTo(System.out);
		if (verify.waitFor() != 0) {
			throw new Error("Verification failed");
		}
	}

	public void rotateJournal() throws IOException, InterruptedException {
		Process rotate = Runtime.getRuntime().exec(new String[] { "bwrap", "--unshare-user", "--uid", "0", //
				"--bind", "/", "/", //
				"--dev-bind", "/dev", "/dev", //
				"--bind", "testdata/runtime", "/run/systemd/journal", //
				"--bind", "testdata/logs", "/var/log", //
				"env", "LANG=C.UTF-8", "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1", //
				"FAKETIME_TIMESTAMP_FILE=faketimefile", "FAKETIME_NO_CACHE=1", //
				journalctl, "--rotate" });
		rotate.getInputStream().transferTo(System.out);
		rotate.getErrorStream().transferTo(System.out);
		if (rotate.waitFor() != 0) {
			throw new Error("Rotating failed");
		}
	}

	private String getVirtualJournalPath() {
		return getVirtualJournalBasePath() + "/system.journal";
	}

	public String[] getArchivedJournals() {
		File[] files = new File(getJournalBasePath()).listFiles();
		LinkedList<String> archived = new LinkedList<>();
		for (File file : files) {
			if (file.getName().startsWith("system@") && file.getName().endsWith(".journal")) {
				archived.add(getVirtualJournalBasePath() + "/" + file.getName());
			}
		}
		return archived.toArray(String[]::new);
	}

	private String getVirtualJournalBasePath() {
		return "/var/log/journal/" + machineid;
	}

	public String getJournalBasePath() {
		return "testdata/logs/journal/" + machineid;
	}

	public void log(String message) throws IOException, InterruptedException {
		long start = getNEntries();
		Process verify = Runtime.getRuntime()
				.exec(new String[] { "env", "LANG=C.UTF-8",
						"LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1", //
						"FAKETIME_TIMESTAMP_FILE=faketimefile", "FAKETIME_NO_CACHE=1", "logger", "-u",
						"testdata/runtime/dev-log", "hello-message" });
		verify.getInputStream().transferTo(System.out);
		verify.getErrorStream().transferTo(System.out);
		verify.waitFor();
		while (getNEntries() == start) {
			Thread.sleep(50);
		}
	}

	private long getNEntries() {
		return journalFile.getLong(19 * 8);
	}

	public long getNTags() {
		return journalFile.getLong(28 * 8);
	}

	public void dumpJournal() throws IOException {
		Process verify = Runtime.getRuntime().exec(new String[] { "bwrap", "--unshare-user", "--uid", "0", //
				"--bind", "/", "/", //
				"--dev-bind", "/dev", "/dev", //
				"--bind", "testdata/runtime", "/run/systemd/journal", //
				"--bind", "testdata/logs", "/var/log", //
				"env", "LANG=C.UTF-8", "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1", //
				"FAKETIME_TIMESTAMP_FILE=faketimefile", "FAKETIME_NO_CACHE=1", //
				journalctl, "--file=/var/log/journal/" + machineid + "/system.journal" });
		verify.getInputStream().transferTo(System.out);
		verify.getErrorStream().transferTo(System.out);

	}

	public static JournalSystem createInstance() throws IOException {
		return new JournalSystem(null);
	}
	private static final int EPOCH_MILLIS = 15 * 60 * 1000;

	public static void main(String[] args) throws IOException, InterruptedException, ParseException {
		JournalSystem js = JournalSystem.createInstance();
		js.setupKeys();

		js.startJournald();

		js.verifyJournal();
		js.dumpJournal();

		System.out.println("--");
		js.log("hello");
		js.dumpJournal();
		js.verifyJournal();

		Date nextEpoch = new Date(System.currentTimeMillis());
		nextEpoch.setTime(nextEpoch.getTime() - (nextEpoch.getTime() % EPOCH_MILLIS) + EPOCH_MILLIS);

		js.faketime("+" + ((nextEpoch.getTime() - System.currentTimeMillis() - 3 * 1000) / 1000) + "s x1");
		System.out.println("--");
		js.log("hello");
		js.dumpJournal();
		js.verifyJournal();
		Thread.sleep(5000);
		js.verifyJournal();
		js.stopJournald();

		js.verifyJournal();
		js.dumpJournal();
	}

	public String getVerificationKey() {
		return vk;
	}

	public JournalFileBuffer getJournal() {
		return journalFile.slice();
	}

	public JournalFileBuffer reopen() throws IOException {
		return JournalFileBuffer.open(Paths.get(getJournalBasePath() + "/system.journal"), false);
	}

}
