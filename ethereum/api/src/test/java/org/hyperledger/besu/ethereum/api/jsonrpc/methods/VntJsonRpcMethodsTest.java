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
package org.hyperledger.besu.ethereum.api.jsonrpc.methods;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.ethereum.api.jsonrpc.RpcMethod.VNT_GET_SUPPORTED_DSAS;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.ethereum.api.jsonrpc.RpcApis;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods.JsonRpcMethod;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods.VntGetSupportedDSAs;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

public class VntJsonRpcMethodsTest {

  @Test
  public void shouldExposeGetSupportedDSAsMethod() {
    final VntJsonRpcMethods group =
        new VntJsonRpcMethods(List.of(DSAParametersSet.SECP256K1));

    final Map<String, JsonRpcMethod> methods = group.create();

    assertThat(methods.get(VNT_GET_SUPPORTED_DSAS.getMethodName()))
        .isInstanceOf(VntGetSupportedDSAs.class);
  }

  @Test
  public void shouldReportVntApiGroup() {
    final VntJsonRpcMethods group =
        new VntJsonRpcMethods(List.of(DSAParametersSet.SECP256K1));

    assertThat(group.getApiGroup()).isEqualTo(RpcApis.VNT.name());
  }

  @Test
  public void shouldReturnEmptyMapWhenVntNotEnabled() {
    final VntJsonRpcMethods group =
        new VntJsonRpcMethods(List.of(DSAParametersSet.SECP256K1));

    final Map<String, JsonRpcMethod> methods = group.create(List.of("ETH", "NET"));

    assertThat(methods).isEmpty();
  }

  @Test
  public void shouldReturnMethodsWhenVntEnabled() {
    final VntJsonRpcMethods group =
        new VntJsonRpcMethods(List.of(DSAParametersSet.SECP256K1, DSAParametersSet.SECP256K1MLDSA44));

    final Map<String, JsonRpcMethod> methods = group.create(List.of("VNT"));

    assertThat(methods).containsKey(VNT_GET_SUPPORTED_DSAS.getMethodName());
  }
}
