/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.pqc.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Samples are recorded from every thread that signs or verifies, the parallel block processor's
 * included, so the writer has to take them from many threads at once without losing or mixing
 * lines.
 */
class CSVWriterTest {

  private static final String HEADER = "time,object\n";

  @TempDir Path dir;

  @Test
  void keepsEverySampleWrittenFromManyThreadsIntact() throws Exception {
    final File file = dir.resolve("verify-metrics.csv").toFile();
    final CSVWriter writer = new CSVWriter(HEADER, file);
    final int threads = 8;
    final int samplesPerThread = 2_000;

    final ExecutorService pool = Executors.newFixedThreadPool(threads);
    final CountDownLatch start = new CountDownLatch(1);
    final List<Future<?>> futures = new ArrayList<>();
    for (int t = 0; t < threads; t++) {
      final int thread = t;
      futures.add(
          pool.submit(
              () -> {
                start.await();
                for (int i = 0; i < samplesPerThread; i++) {
                  writer.write(thread + "-" + i + ",tx\n");
                }
                return null;
              }));
    }
    start.countDown();
    for (final Future<?> future : futures) {
      future.get();
    }
    pool.shutdown();
    writer.clean();

    final List<String> lines = read(file);
    assertThat(lines.get(0)).isEqualTo("time,object");
    final Set<String> expected = new HashSet<>();
    for (int t = 0; t < threads; t++) {
      for (int i = 0; i < samplesPerThread; i++) {
        expected.add(t + "-" + i + ",tx");
      }
    }
    assertThat(lines.subList(1, lines.size())).containsExactlyInAnyOrderElementsOf(expected);
  }

  @Test
  void appendsToAnExistingFileWithoutRepeatingTheHeader() throws IOException {
    final File file = dir.resolve("sign-metrics.csv").toFile();
    final CSVWriter first = new CSVWriter(HEADER, file);
    first.write("1,a\n");
    first.clean();

    final CSVWriter second = new CSVWriter(HEADER, file);
    second.write("2,b\n");
    second.clean();

    assertThat(read(file)).containsExactly("time,object", "1,a", "2,b");
  }

  @Test
  void setsAsideAFileWrittenWithOtherColumnsAndStartsANewOne() throws IOException {
    final File file = dir.resolve("sign-metrics.csv").toFile();
    Files.write(
        file.toPath(),
        List.of("time,size,object,algorithm,finality", "1,2,block,SECP256K1,seal"),
        StandardCharsets.ISO_8859_1);

    final CSVWriter writer = new CSVWriter(HEADER, file);
    writer.write("3,a\n");
    writer.clean();

    assertThat(read(file)).containsExactly("time,object", "3,a");
    try (Stream<Path> files = Files.list(dir)) {
      final List<Path> setAside =
          files.filter(p -> !p.equals(file.toPath())).collect(Collectors.toList());
      assertThat(setAside).singleElement().satisfies(
          p -> {
            assertThat(p.getFileName().toString()).startsWith("sign-metrics-").endsWith(".csv");
            assertThat(read(p.toFile()))
                .containsExactly("time,size,object,algorithm,finality", "1,2,block,SECP256K1,seal");
          });
    }
  }

  @Test
  void writesTheHeaderIntoAnEmptyExistingFile() throws IOException {
    final File file = dir.resolve("verify-metrics.csv").toFile();
    Files.createFile(file.toPath());

    final CSVWriter writer = new CSVWriter(HEADER, file);
    writer.write("1,a\n");
    writer.clean();

    assertThat(read(file)).containsExactly("time,object", "1,a");
    try (Stream<Path> files = Files.list(dir)) {
      assertThat(files).containsExactly(file.toPath());
    }
  }

  @Test
  void dropsSamplesWrittenAfterItWasCleaned() throws IOException {
    final File file = dir.resolve("pkr-metrics.csv").toFile();
    final CSVWriter writer = new CSVWriter(HEADER, file);
    writer.clean();

    assertThatCode(() -> writer.write("1,a\n")).doesNotThrowAnyException();
    assertThat(read(file)).containsExactly("time,object");
  }

  @Test
  void dropsSamplesWhenTheFileCannotBeOpened() {
    final File file = dir.resolve("missing").resolve("verify-metrics.csv").toFile();
    final CSVWriter writer = new CSVWriter(HEADER, file);

    assertThatCode(() -> writer.write("1,a\n")).doesNotThrowAnyException();
    writer.clean();
    assertThat(file).doesNotExist();
  }

  private static List<String> read(final File file) throws IOException {
    return Files.readAllLines(file.toPath(), StandardCharsets.ISO_8859_1);
  }
}
