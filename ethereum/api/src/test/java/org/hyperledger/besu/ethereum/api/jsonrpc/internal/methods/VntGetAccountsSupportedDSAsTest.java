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
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.providers.DigitalSignatureAlgorithmProvider;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequest;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequestContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcSuccessResponse;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class VntGetAccountsSupportedDSAsTest {

  @Mock private DigitalSignatureAlgorithmProvider dsaProvider;

  @Test
  public void shouldReturnCorrectMethodName() {
    final VntGetAccountsSupportedDSAs method = new VntGetAccountsSupportedDSAs(dsaProvider);
    assertThat(method.getName()).isEqualTo("vnt_getAccountsSupportedDSAs");
  }

  @Test
  public void shouldReturnSingleDefaultDSA() {
    when(dsaProvider.getAccountsSupportedDSANames()).thenReturn(List.of("SECP256K1"));
    final VntGetAccountsSupportedDSAs method = new VntGetAccountsSupportedDSAs(dsaProvider);
    final JsonRpcResponse expectedResponse =
        new JsonRpcSuccessResponse(null, List.of("SECP256K1"));

    final JsonRpcResponse response = method.response(request());

    assertThat(response).usingRecursiveComparison().isEqualTo(expectedResponse);
  }

  @Test
  public void shouldReturnMultipleDSAs() {
    when(dsaProvider.getAccountsSupportedDSANames()).thenReturn(List.of("SECP256K1", "MLDSA44"));
    final VntGetAccountsSupportedDSAs method = new VntGetAccountsSupportedDSAs(dsaProvider);
    final JsonRpcResponse expectedResponse =
        new JsonRpcSuccessResponse(null, List.of("SECP256K1", "MLDSA44"));

    final JsonRpcResponse response = method.response(request());

    assertThat(response).usingRecursiveComparison().isEqualTo(expectedResponse);
  }

  @Test
  public void shouldReturnAllDSAs() {
    final List<String> all =
        List.of("SECP256K1", "SECP256R1", "MLDSA44", "MLDSA65", "MLDSA87", "SECP256K1MLDSA44");
    when(dsaProvider.getAccountsSupportedDSANames()).thenReturn(all);
    final VntGetAccountsSupportedDSAs method = new VntGetAccountsSupportedDSAs(dsaProvider);

    final JsonRpcResponse response = method.response(request());

    assertThat(response).isInstanceOf(JsonRpcSuccessResponse.class);
    @SuppressWarnings("unchecked")
    final List<String> result = (List<String>) ((JsonRpcSuccessResponse) response).getResult();
    assertThat(result).containsExactlyElementsOf(all);
  }

  private JsonRpcRequestContext request() {
    return new JsonRpcRequestContext(
        new JsonRpcRequest("2.0", "vnt_getAccountsSupportedDSAs", null));
  }
}
