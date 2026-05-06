package org.hyperledger.besu.ethereum.core.encoding;

import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

public class PublicKeyDecoder {

  public static Optional<PublicKey> decodeByDsaId(
      final Short dsaType,
      final RLPInput in) {

    final DigitalSignatureAlgorithm dsa =
        SignatureAlgorithmFactory.getSupportedDsaById(dsaType);

    // 🔹 CASO 1: algoritmo único
    if (!(dsa instanceof HybridDigitalSignatureAlgorithm)) {

      if (isRecoverable(dsa)) {
        // não serializou nada
        return Optional.empty();
      }

      // [pk]
      final Bytes pkBytes = in.readBytes();
      return KeyFactory.createPublicKey(pkBytes, dsa.getDsaParametersSet());
    }

    // 🔹 CASO 2: híbrido
    final HybridDigitalSignatureAlgorithm hybrid =
        (HybridDigitalSignatureAlgorithm) dsa;

    final DigitalSignatureAlgorithm firstAlgo = hybrid.getFirstAlgorithm();
    final DigitalSignatureAlgorithm secondAlgo = hybrid.getSecondAlgorithm();

    final boolean firstRec = isRecoverable(firstAlgo);
    final boolean secondRec = isRecoverable(secondAlgo);

    // 🔸 caso 4: nenhum serializado
    if (firstRec && secondRec) {
      return Optional.empty();
    }

    // 🔸 caso 1: [pk1 || pk2]
    if (!firstRec && !secondRec) {
      final Bytes compositePkBytes = in.readBytes();

      return KeyFactory.createPublicKey(compositePkBytes, dsa.getDsaParametersSet());
    }

    // 🔸 caso 2 e 3: [pk1] ou [pk2]
    if (!firstRec || !secondRec) {
      Bytes partialPkBytes = in.readBytes();

      return KeyFactory.createPublicKey(partialPkBytes, dsa.getDsaParametersSet());
    }

    throw new IllegalStateException("Unreachable state");
  }

  private static boolean isRecoverable(final DigitalSignatureAlgorithm dsa) {
    return dsa instanceof PublicKeyRecoverable;
  }
}