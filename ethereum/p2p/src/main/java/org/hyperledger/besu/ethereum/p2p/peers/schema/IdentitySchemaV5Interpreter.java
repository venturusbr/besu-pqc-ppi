package org.hyperledger.besu.ethereum.p2p.peers.schema;

import java.net.InetSocketAddress;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.IdentitySchemaInterpreter;
import org.ethereum.beacon.discovery.schema.NodeRecord;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;

public class IdentitySchemaV5Interpreter implements IdentitySchemaInterpreter{
    private static final Logger logger = LogManager.getLogger();
    private final LoadingCache<Bytes, Bytes> nodeIdCache = CacheBuilder.newBuilder().maximumSize(4000L).build(CacheLoader.from(IdentitySchemaV5Interpreter::calculateNodeId));
    private static final ImmutableSet<String> ADDRESS_FIELD_NAMES = ImmutableSet.of("ip", "ip6", "udp", "udp6");

    public boolean isValid(NodeRecord nodeRecord) {
        if (!super.isValid(nodeRecord)) {
           return false;
        } else if (nodeRecord.get("secp256k1") == null || nodeRecord.get("mldsa") == null || nodeRecord.get("mlkem") == null || nodeRecord.get("mldsasig") == null) {
           logger.trace("Fields are required {}, {}, {} and {} are required for scheme {}", "secp256k1", "mldsa", "mlkem", "mldsasig", this.getScheme());
           return false;
        } else {
           Bytes pubKey = (Bytes)nodeRecord.get("secp256k1");
           Bytes mldsaPubKey = (Bytes)nodeRecord.get("mldsa");
           Bytes mlkem = (Bytes)nodeRecord.get("mlkem");
           Bytes mldsasig = (Bytes)nodeRecord.get("mldsasig");
           return Functions.verifyECDSASignature(nodeRecord.getSignature(), Functions.hashKeccak(nodeRecord.serializeNoSignature()), pubKey);
        }
     }

    private static Bytes calculateNodeId(Bytes pkey){

    }

    @Override
    public NodeRecord createWithNewAddress(NodeRecord arg0, InetSocketAddress arg1, Optional<Integer> arg2,
            Bytes arg3) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'createWithNewAddress'");
    }

    @Override
    public NodeRecord createWithUpdatedCustomField(NodeRecord arg0, String arg1, Bytes arg2, Bytes arg3) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'createWithUpdatedCustomField'");
    }

    @Override
    public Bytes getNodeId(NodeRecord nodeRecord) {
        
    }

    @Override
    public IdentitySchema getScheme() {
        return IdentitySchema.
    }

    @Override
    public Optional<InetSocketAddress> getTcpAddress(NodeRecord arg0) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getTcpAddress'");
    }

    @Override
    public Optional<InetSocketAddress> getUdpAddress(NodeRecord arg0) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getUdpAddress'");
    }

    @Override
    public void sign(NodeRecord arg0, Bytes arg1) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'sign'");
    }
    
}
