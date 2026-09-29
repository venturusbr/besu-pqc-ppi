package org.hyperledger.besu.crypto.algorithms.hybrid;

import java.security.PrivateKey;
import java.security.PublicKey;
import org.hyperledger.besu.crypto.PublicKeyRecoverable;
import java.util.concurrent.CompletableFuture;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.HybridDigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.types.CompositeSignature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;

public class HybridStrongNestingConcatenation implements HybridDigitalSignatureAlgorithm{

    DigitalSignatureAlgorithm delegateFirstAlgorithm;
    DigitalSignatureAlgorithm delegateSecondAlgorithm;
    DSAParametersSet parametersSet;

    public HybridStrongNestingConcatenation(final DigitalSignatureAlgorithm firstAlgorithm, final DigitalSignatureAlgorithm secondAlgorithm, final DSAParametersSet parametersSet){
        this.delegateFirstAlgorithm = firstAlgorithm;
        this.delegateSecondAlgorithm = secondAlgorithm;
        this.parametersSet = parametersSet;
    }

    @Override
    public Signature sign(final Bytes data, final PrivateKey sk) {
        CompositePrivateKey hybridPrivateKey = (CompositePrivateKey) sk;

        Signature firstSignature = delegateFirstAlgorithm.sign(data, hybridPrivateKey.getFirstKey());
        Signature secondSignature = delegateSecondAlgorithm.sign(Bytes.concatenate(data, firstSignature.encodedBytes()), hybridPrivateKey.getSecondKey());

        return SignatureFactory.createCompositeConcSignature(firstSignature, secondSignature);
    }

    @Override
    public Boolean verify(final Bytes data, final Signature signature, final PublicKey pk) {
        CompositePublicKey hybridPublicKey = (CompositePublicKey) pk;

        CompositeSignature compositeSignature = (CompositeSignature) signature;

        Signature firstSignature = compositeSignature.getFirstSignature();
        Signature secondSignature = compositeSignature.getSecondSignature();

        Bytes dataWithFirstSignature = Bytes.concatenate(data, firstSignature.encodedBytes()); 

        CompletableFuture<Boolean> firstVerify = CompletableFuture.supplyAsync(() ->
            verifyHalf(delegateFirstAlgorithm, data, firstSignature, hybridPublicKey.getFirstKey())
        );

        CompletableFuture<Boolean> secondVerify = CompletableFuture.supplyAsync(() ->
            verifyHalf(delegateSecondAlgorithm, dataWithFirstSignature, secondSignature, hybridPublicKey.getSecondKey())
        );

        return firstVerify.join() && secondVerify.join();
    }

    /**
     * Checks one half of the composite signature against the matching half of the composite key.
     *
     * <p>An algorithm that supports public key recovery is authenticated by recovering the key
     * from the signature, which the caller does, so this does not verify that half. Anything
     * else is verified directly.
     *
     * @param algorithm the algorithm that produced this half
     * @param data what that half was signed over
     * @param signature the half to check
     * @param claimedKey the half of the composite key it is claimed to belong to
     * @return whether the half holds up
     */
    private Boolean verifyHalf(
            final DigitalSignatureAlgorithm algorithm,
            final Bytes data,
            final Signature signature,
            final PublicKey claimedKey) {

        if (algorithm instanceof PublicKeyRecoverable) {
            //uses PKR to authentication, verify is not necessary
            return true;
        }

        return algorithm.verify(data, signature, claimedKey);
    }

    @Override
    public KeyPair generateNodeKeyPair() {
        CompletableFuture<KeyPair> firstFuture = CompletableFuture.supplyAsync(
            () -> delegateFirstAlgorithm.generateNodeKeyPair()
        );

        CompletableFuture<KeyPair> secondFuture = CompletableFuture.supplyAsync(
            () -> delegateSecondAlgorithm.generateNodeKeyPair()
        );

        KeyPair firstKeyPair = firstFuture.join();
        KeyPair secondKeyPair = secondFuture.join();

        return KeyFactory.createHybridKeyPair(firstKeyPair, secondKeyPair);
    }

    @Override
    public DSAParametersSet getDsaParametersSet() {
        return parametersSet;
    }

    @Override
    public DigitalSignatureAlgorithm getFirstAlgorithm(){
        return delegateFirstAlgorithm;
    }

    @Override 
    public DigitalSignatureAlgorithm getSecondAlgorithm(){
        return delegateSecondAlgorithm;
    }
}
