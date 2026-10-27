package org.hyperledger.besu.crypto.pqc.metrics;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Appends metric samples to a CSV file from a single background thread.
 *
 * <p>Samples come from every thread that signs, verifies or recovers a key, the parallel block
 * processor included, so {@link #write} only hands the line over: it never touches the file or
 * any state shared with other callers. The file is flushed when the queue runs dry rather than
 * after every sample, and the queue is bounded, so a burst of samples costs memory up to a fixed
 * limit and is then dropped instead of growing until the node stalls.
 */
public class CSVWriter {

    private static final Logger LOG = LoggerFactory.getLogger(CSVWriter.class);

    private static final String HOME_PATH = "/usr/app/";
    static final int QUEUE_CAPACITY = 100_000;
    private static final long CLEAN_TIMEOUT_SECONDS = 5;

    private final String FILE_PATH;

    private BufferedWriter bufferedWriter;
    private final ThreadPoolExecutor executor;
    private final AtomicBoolean droppedSamples = new AtomicBoolean(false);

    public CSVWriter(final String header, final String filePath) {
        this(header, new File(HOME_PATH + filePath + "-metrics.csv"));
    }

    CSVWriter(final String header, final File file) {
        FILE_PATH = file.getPath();
        // A daemon thread, so a run that never calls clean() can still exit.
        this.executor =
                new ThreadPoolExecutor(
                        1,
                        1,
                        0L,
                        TimeUnit.MILLISECONDS,
                        new LinkedBlockingQueue<>(QUEUE_CAPACITY),
                        runnable -> {
                            final Thread thread = new Thread(runnable, "csv-metrics-" + file.getName());
                            thread.setDaemon(true);
                            return thread;
                        },
                        (runnable, pool) -> reportDroppedSample());
        try {
            if (file.exists() && file.length() == 0) {
                // Nothing to keep: it only needs its header.
                Files.delete(file.toPath());
            } else if (file.exists() && !hasHeader(file, header)) {
                setAside(file);
            }
            if (!file.exists()) {
                file.createNewFile();
                initializeTable(header);
            } else {
                initializeWriters();
            }
        } catch (IOException e) {
            LOG.info(e.getMessage());
        }
    }

    private static boolean hasHeader(final File file, final String header) throws IOException {
        try (BufferedReader reader =
                Files.newBufferedReader(file.toPath(), StandardCharsets.ISO_8859_1)) {
            final String firstLine = reader.readLine();
            return header.strip().equals(firstLine == null ? null : firstLine.strip());
        }
    }

    /**
     * Moves a file written with other columns out of the way, so samples are never appended under
     * a header that does not describe them. Its samples are kept, next to the new file.
     */
    private static void setAside(final File file) throws IOException {
        final String name = file.getName();
        final int dot = name.lastIndexOf('.');
        final String stamp =
                LocalDateTime.now(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        final String asideName =
                dot < 0
                        ? name + "-" + stamp
                        : name.substring(0, dot) + "-" + stamp + name.substring(dot);
        final Path aside = file.toPath().resolveSibling(asideName);
        Files.move(file.toPath(), aside);
        LOG.info("{} has the columns of an earlier version; moved it to {}", file, aside);
    }

    private void initializeWriters() throws IOException {
        this.bufferedWriter =
                new BufferedWriter(new FileWriter(FILE_PATH, StandardCharsets.ISO_8859_1, true));
    }

    private void initializeTable(final String header) throws IOException {
        initializeWriters();
        this.bufferedWriter.write(header);
        this.bufferedWriter.flush();
    }

    public void write(final String data) {
        // The metrics file may not have opened, and clean() may already have shut the executor
        // down. Metrics are best effort, so drop the sample instead of failing the caller.
        if (bufferedWriter == null || executor.isShutdown()) {
            return;
        }
        executor.execute(new Register(data));
    }

    private void reportDroppedSample() {
        if (!executor.isShutdown() && droppedSamples.compareAndSet(false, true)) {
            LOG.warn(
                    "Metrics queue for {} is full ({} samples); dropping samples until it drains",
                    FILE_PATH,
                    QUEUE_CAPACITY);
        }
    }

    public void clean() {
        executor.shutdown();
        // Let the samples already queued reach the file before it is closed.
        try {
            if (!executor.awaitTermination(CLEAN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                LOG.info("Metrics for {} were still being written when closing", FILE_PATH);
                executor.shutdownNow();
                executor.awaitTermination(CLEAN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // Closing the buffered writer flushes and closes the underlying file writer.
        try {
            if (bufferedWriter != null) {
                bufferedWriter.close();
            }
        } catch (IOException e) {
            LOG.info(e.getMessage());
        }
    }

    private class Register implements Runnable {
        private final String data;

        public Register(final String data) {
            this.data = data;
        }

        @Override
        public void run() {
            try {
                bufferedWriter.write(data);
                // Flushing after every sample was a write call per signature verified; flushing
                // once the queue is empty keeps the file current without that cost under load.
                if (executor.getQueue().isEmpty()) {
                    bufferedWriter.flush();
                    droppedSamples.set(false);
                }
            } catch (IOException e) {
                LOG.info(e.getMessage());
            }
        }
    }
}
