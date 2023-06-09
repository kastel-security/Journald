package journald;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class JournalFileBuffer {
	public final int remaining() {
		return delegate.remaining();
	}

	ByteBuffer file;
	long offset;
	ByteBuffer delegate;

	public JournalFileBuffer(ByteBuffer file) {
		this.file = file.order(ByteOrder.LITTLE_ENDIAN);
		delegate = file;
	}

	private JournalFileBuffer(ByteBuffer file, ByteBuffer delegate, long offset) {
		this.file = file;
		this.delegate = delegate;
		this.offset = offset;
	}

	public long getOffsetFrom(JournalFileBuffer other) {
		if (other.file != file)
			throw new Error();
		return offset - other.offset;
	}

	public JournalFileBuffer slice() {
		ByteBuffer newDelegate = delegate.slice().order(ByteOrder.LITTLE_ENDIAN);
		return new JournalFileBuffer(file, newDelegate, offset + delegate.position());
	}

	public JournalFileBuffer slice(int index, int length) {
		ByteBuffer newDelegate = delegate.slice(index, length).order(ByteOrder.LITTLE_ENDIAN);
		return new JournalFileBuffer(file, newDelegate, offset + index);
	}

	public ByteBuffer getDelegate() {
		return delegate;
	}

	public final ByteBuffer put(byte[] src) {
		return delegate.put(src);
	}

	public int getInt(int index) {
		return delegate.getInt(index);
	}

	public final boolean hasRemaining() {
		return delegate.hasRemaining();
	}

	public final int capacity() {
		return delegate.capacity();
	}

	public static JournalFileBuffer open(Path p, boolean rw) throws IOException {
		FileChannel fc = FileChannel.open(p, StandardOpenOption.READ, rw ? StandardOpenOption.WRITE : StandardOpenOption.READ);
		MappedByteBuffer mapped = fc.map(rw ? MapMode.READ_WRITE : MapMode.READ_ONLY, 0, fc.size());
		return new JournalFileBuffer(mapped);
	}

	public final int position() {
		return delegate.position();
	}

	public byte get() {
		return delegate.get();
	}

	public ByteBuffer put(int index, byte b) {
		return delegate.put(index, b);
	}

	public ByteBuffer put(byte b) {
		return delegate.put(b);
	}

	public int getInt() {
		return delegate.getInt();
	}

	public ByteBuffer putInt(int index, int value) {
		return delegate.putInt(index, value);
	}

	public ByteBuffer put(int index, byte[] src) {
		return delegate.put(index, src);
	}

	public ByteBuffer get(byte[] dst) {
		return delegate.get(dst);
	}

	public ByteBuffer position(int newPosition) {
		return delegate.position(newPosition);
	}

	public long getLong() {
		return delegate.getLong();
	}

	public long getLong(int index) {
		return delegate.getLong(index);
	}

	public ByteBuffer putLong(long value) {
		return delegate.putLong(value);
	}

	public ByteBuffer putLong(int index, long value) {
		return delegate.putLong(index, value);
	}

	public short getShort() {
		return delegate.getShort();
	}

}
