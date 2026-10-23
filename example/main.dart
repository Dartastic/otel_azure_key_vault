// Licensed under the Apache License, Version 2.0
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:otel_azure_key_vault/otel_azure_key_vault.dart';

/// Traces Azure Key Vault calls with OpenTelemetry.
///
/// `otel_azure_key_vault` depends on the OpenTelemetry API only, so the application
/// initializes an SDK once at startup. Wrap each Azure Key Vault call in
/// [tracedAzureKeyVault]; the `invoke` callback makes the real call and reports what
/// came back, which is recorded on the span.
Future<void> main() async {
  await OTel.initialize(serviceName: 'azure-key-vault-example');

  // Wraps an Azure Key Vault call in a CLIENT span.
  final azureKeyVaultId = await tracedAzureKeyVault<String>(
    operation: 'keys.create',
    invoke: () async {
      // Make the Azure Key Vault call here, then report what it returned.
      const id = 'azure_key_vault_8f3a2c';
      return const AzureKeyVaultCallResult(
          value: id,
          result: AzureKeyVaultResult(
              vaultName: '<vault>.vault.azure.net',
              vaultKind: 'Standard',
              entityKind: 'secret',
              entityName: 'example',
              entityVersion: '1',
              keyType: 'RSA',
              keyCurve: 'P-256',
              keySizeBits: 512,
              keyOperations: ['encrypt'],
              certificateThumbprint: 'example',
              certificateIssuer: 'example',
              cryptoAlgorithm: 'RSA-OAEP',
              signatureAlgorithm: 'RS256',
              encryptedBytes: 512,
              decryptedBytes: 512,
              hsmBackend: true,
              purgeProtectionEnabled: true,
              softDeleteEnabled: true,
              recoverableDays: 1,
              deletedRecoveryLevel: 'Recoverable+Purgeable',
              errorCode: 'error.code',
              errorMessage: 'example',
              statusCode: 201));
    },
  );
  OTelLog.info('tracedAzureKeyVault keys.create returned $azureKeyVaultId');

  // Calls that should not be traced, such as health checks, run inside
  // runWithoutAzureKeyVaultInstrumentationAsync.
  await runWithoutAzureKeyVaultInstrumentationAsync(
    () => tracedAzureKeyVault<String>(
      operation: 'keys.create',
      invoke: () async {
        const id = 'azure_key_vault_8f3a2c';
        return const AzureKeyVaultCallResult(
            value: id,
            result: AzureKeyVaultResult(
                vaultName: '<vault>.vault.azure.net',
                vaultKind: 'Standard',
                entityKind: 'secret',
                entityName: 'example',
                entityVersion: '1',
                keyType: 'RSA',
                keyCurve: 'P-256',
                keySizeBits: 512,
                keyOperations: ['encrypt'],
                certificateThumbprint: 'example',
                certificateIssuer: 'example',
                cryptoAlgorithm: 'RSA-OAEP',
                signatureAlgorithm: 'RS256',
                encryptedBytes: 512,
                decryptedBytes: 512,
                hsmBackend: true,
                purgeProtectionEnabled: true,
                softDeleteEnabled: true,
                recoverableDays: 1,
                deletedRecoveryLevel: 'Recoverable+Purgeable',
                errorCode: 'error.code',
                errorMessage: 'example',
                statusCode: 201));
      },
    ),
  );

  await OTel.shutdown();
}
