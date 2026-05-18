// Licensed under the Dartastic Pro Software License Agreement.
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:dartastic_opentelemetry/testing.dart';
import 'package:otel_azure_key_vault/otel_azure_key_vault.dart';
import 'package:test/test.dart';

void main() {
  late TestHarness harness;
  late InMemorySpanExporter spans;

  setUpAll(() async {
    harness = await maybeInitializeOtelForTest(
      serviceName: 'otel_azure_key_vault-test',
    );
    spans = harness.spans;
  });

  setUp(() => harness.clear());

  Map<String, Object> attrsOf(Span s) =>
      {for (final a in s.attributes.toList()) a.key: a.value};

  test('keys.encrypt records algorithm + bytes', () async {
    await tracedAzureKeyVault<String>(
      operation: 'keys.encrypt',
      invoke: () async => const AzureKeyVaultCallResult(
        value: 'ok',
        result: AzureKeyVaultResult(
          vaultName: 'myvault.vault.azure.net',
          vaultKind: 'Premium',
          entityKind: 'key',
          entityName: 'app-master',
          entityVersion: 'v1',
          keyType: 'RSA-HSM',
          keySizeBits: 4096,
          cryptoAlgorithm: 'RSA-OAEP-256',
          encryptedBytes: 256,
          hsmBackend: true,
        ),
      ),
    );
    final a = attrsOf(spans.findSpanByName('azure_key_vault keys.encrypt')!);
    expect(a['azure_key_vault.crypto.algorithm'], 'RSA-OAEP-256');
    expect(a['azure_key_vault.hsm_backend'], true);
  });

  test('SecretNotFound sets span error', () async {
    await tracedAzureKeyVault<String>(
      operation: 'secrets.get',
      invoke: () async => const AzureKeyVaultCallResult(
        value: 'ok',
        result: AzureKeyVaultResult(
          errorCode: 'SecretNotFound',
          statusCode: 404,
        ),
      ),
    );
    expect(
      spans.findSpanByName('azure_key_vault secrets.get')!.status,
      SpanStatusCode.Error,
    );
  });

  test('suppression skips spans', () async {
    await runWithoutAzureKeyVaultInstrumentationAsync(() async {
      await tracedAzureKeyVault<String>(
        operation: 'keys.list',
        invoke: () async => const AzureKeyVaultCallResult(value: 'v'),
      );
    });
    expect(spans.findSpansStartingWith('azure_key_vault '), isEmpty);
  });
}
