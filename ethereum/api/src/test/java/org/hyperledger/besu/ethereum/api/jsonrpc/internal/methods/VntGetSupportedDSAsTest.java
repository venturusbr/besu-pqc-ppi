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
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequest;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequestContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcSuccessResponse;

import java.util.List;

import org.junit.jupiter.api.Test;

public class VntGetSupportedDSAsTest {

  @Test
  public void shouldReturnCorrectMethodName() {
    final VntGetSupportedDSAs method = new VntGetSupportedDSAs(List.of(DSAParametersSet.SECP256K1));
    assertThat(method.getName()).isEqualTo("vnt_getSupportedDSAs");
  }

  @Test
  public void shouldReturnSingleDefaultDSA() {
    final VntGetSupportedDSAs method = new VntGetSupportedDSAs(List.of(DSAParametersSet.SECP256K1));
    final JsonRpcResponse expectedResponse =
        new JsonRpcSuccessResponse(null, List.of(DSAParametersSet.SECP256K1.getName()));

    final JsonRpcResponse response = method.response(request());

    assertThat(response).usingRecursiveComparison().isEqualTo(expectedResponse);
  }

  @Test
  public void shouldReturnMultipleDSAs() {
    final VntGetSupportedDSAs method =
        new VntGetSupportedDSAs(
            List.of(DSAParametersSet.SECP256K1, DSAParametersSet.SECP256K1MLDSA44));
    final JsonRpcResponse expectedResponse =
        new JsonRpcSuccessResponse(
            null,
            List.of(DSAParametersSet.SECP256K1.getName(), DSAParametersSet.SECP256K1MLDSA44.getName()));

    final JsonRpcResponse response = method.response(request());

    assertThat(response).usingRecursiveComparison().isEqualTo(expectedResponse);
  }

  @Test
  public void shouldReturnAllDSAs() {
    final List<DSAParametersSet> all =
        List.of(
            DSAParametersSet.SECP256K1,
            DSAParametersSet.SECP256R1,
            DSAParametersSet.MLDSA44,
            DSAParametersSet.MLDSA65,
            DSAParametersSet.MLDSA87,
            DSAParametersSet.SECP256K1MLDSA44);
    final VntGetSupportedDSAs method = new VntGetSupportedDSAs(all);

    final JsonRpcResponse response = method.response(request());

    assertThat(response).isInstanceOf(JsonRpcSuccessResponse.class);
    @SuppressWarnings("unchecked")
    final List<String> result = (List<String>) ((JsonRpcSuccessResponse) response).getResult();
    assertThat(result).hasSize(6);
    assertThat(result)
        .containsExactly(
            DSAParametersSet.SECP256K1.getName(),
            DSAParametersSet.SECP256R1.getName(),
            DSAParametersSet.MLDSA44.getName(),
            DSAParametersSet.MLDSA65.getName(),
            DSAParametersSet.MLDSA87.getName(),
            DSAParametersSet.SECP256K1MLDSA44.getName());
  }

  private JsonRpcRequestContext request() {
    return new JsonRpcRequestContext(new JsonRpcRequest("2.0", "vnt_getSupportedDSAs", null));
  }
}
