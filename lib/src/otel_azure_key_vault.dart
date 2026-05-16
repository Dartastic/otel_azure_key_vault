// Licensed under the Apache License, Version 2.0
// Copyright 2025, Mindful Software LLC, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';

import 'otel_azure_key_vault_suppression.dart';

const _tracerName = 'dartastic_otel_libs_azure_key_vault';

Tracer _tracer() => OTel.tracerProvider().getTracer(_tracerName);

class AzureKeyVaultResult {
  const AzureKeyVaultResult({
    this.vaultName,
    this.vaultKind,
    this.entityKind,
    this.entityName,
    this.entityVersion,
    this.keyType,
    this.keyCurve,
    this.keySizeBits,
    this.keyOperations,
    this.certificateThumbprint,
    this.certificateIssuer,
    this.cryptoAlgorithm,
    this.signatureAlgorithm,
    this.encryptedBytes,
    this.decryptedBytes,
    this.hsmBackend,
    this.purgeProtectionEnabled,
    this.softDeleteEnabled,
    this.recoverableDays,
    this.deletedRecoveryLevel,
    this.errorCode,
    this.errorMessage,
    this.statusCode,
  });

  /// `<vault>.vault.azure.net` (Standard/Premium) or
  /// `<vault>.managedhsm.azure.net` (Managed HSM).
  final String? vaultName;

  /// `Standard`, `Premium`, `ManagedHsm`.
  final String? vaultKind;

  /// `secret`, `key`, `certificate`, `storage`.
  final String? entityKind;
  final String? entityName;
  final String? entityVersion;

  /// `RSA`, `RSA-HSM`, `EC`, `EC-HSM`, `oct-HSM`.
  final String? keyType;

  /// `P-256`, `P-256K`, `P-384`, `P-521`.
  final String? keyCurve;
  final int? keySizeBits;

  /// `encrypt`, `decrypt`, `sign`, `verify`, `wrapKey`, `unwrapKey`,
  /// `import`, `export`.
  final List<String>? keyOperations;

  final String? certificateThumbprint;
  final String? certificateIssuer;

  /// `RSA-OAEP`, `RSA-OAEP-256`, `RSA1_5`, `A128GCM`, `A192GCM`,
  /// `A256GCM`, `A128CBC`, `A192CBC`, `A256CBC`.
  final String? cryptoAlgorithm;

  /// `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`,
  /// `ES384`, `ES512`, `ES256K`.
  final String? signatureAlgorithm;

  final int? encryptedBytes;
  final int? decryptedBytes;

  /// Managed HSM backend used.
  final bool? hsmBackend;

  final bool? purgeProtectionEnabled;
  final bool? softDeleteEnabled;
  final int? recoverableDays;

  /// `Recoverable+Purgeable`, `Recoverable+ProtectedSubscription`,
  /// `CustomizedRecoverable`, `Purgeable`.
  final String? deletedRecoveryLevel;

  /// Key Vault `error.code` (e.g. `KeyNotFound`, `SecretNotFound`,
  /// `CertificateNotFound`, `Forbidden`, `Unauthorized`,
  /// `Conflict`, `BadParameter`, `Throttled`, `ServiceUnavailable`).
  final String? errorCode;
  final String? errorMessage;
  final int? statusCode;
}

class AzureKeyVaultCallResult<T> {
  const AzureKeyVaultCallResult({required this.value, this.result});
  final T value;
  final AzureKeyVaultResult? result;
}

/// Wraps an Azure Key Vault call in a CLIENT span. [operation] is one of
/// `secrets.set`, `secrets.get`, `secrets.list`, `secrets.delete`,
/// `secrets.purge`, `secrets.recover`, `secrets.backup`, `secrets.restore`,
/// `keys.create`, `keys.import`, `keys.update`, `keys.get`, `keys.list`,
/// `keys.delete`, `keys.purge`, `keys.recover`, `keys.encrypt`,
/// `keys.decrypt`, `keys.sign`, `keys.verify`, `keys.wrapKey`,
/// `keys.unwrapKey`, `keys.rotate`, `keys.release`, `certificates.create`,
/// `certificates.import`, `certificates.get`, `certificates.list`,
/// `certificates.delete`, `certificates.purge`, `certificates.recover`,
/// `certificates.mergeCertificate`, `certificates.getIssuer`,
/// `certificates.setIssuer`, `roleAssignments.assign`,
/// `roleAssignments.list`.
Future<T> tracedAzureKeyVault<T>({
  required String operation,
  required Future<AzureKeyVaultCallResult<T>> Function() invoke,
}) async {
  if (azureKeyVaultInstrumentationSuppressed()) {
    final r = await invoke();
    return r.value;
  }
  final m = <String, Object>{
    'rpc.system': 'azure_key_vault',
    'rpc.method': operation,
    'azure_key_vault.operation': operation,
  };

  final span = _tracer().startSpan(
    'azure_key_vault $operation',
    kind: SpanKind.client,
    attributes: OTel.attributesFromMap(m),
  );
  try {
    final r = await invoke();
    if (r.result != null) {
      final res = r.result!;
      final extras = <Attribute<Object>>[];
      if (res.vaultName != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.vault.name',
          res.vaultName!,
        ));
      }
      if (res.vaultKind != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.vault.kind',
          res.vaultKind!,
        ));
      }
      if (res.entityKind != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.entity.kind',
          res.entityKind!,
        ));
      }
      if (res.entityName != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.entity.name',
          res.entityName!,
        ));
      }
      if (res.entityVersion != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.entity.version',
          res.entityVersion!,
        ));
      }
      if (res.keyType != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.key.type',
          res.keyType!,
        ));
      }
      if (res.keyCurve != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.key.curve',
          res.keyCurve!,
        ));
      }
      if (res.keySizeBits != null) {
        extras.add(OTel.attributeInt(
          'azure_key_vault.key.size_bits',
          res.keySizeBits!,
        ));
      }
      if (res.keyOperations != null) {
        extras.add(OTel.attributeStringList(
          'azure_key_vault.key.operations',
          res.keyOperations!,
        ));
      }
      if (res.certificateThumbprint != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.certificate.thumbprint',
          res.certificateThumbprint!,
        ));
      }
      if (res.certificateIssuer != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.certificate.issuer',
          res.certificateIssuer!,
        ));
      }
      if (res.cryptoAlgorithm != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.crypto.algorithm',
          res.cryptoAlgorithm!,
        ));
      }
      if (res.signatureAlgorithm != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.signature.algorithm',
          res.signatureAlgorithm!,
        ));
      }
      if (res.encryptedBytes != null) {
        extras.add(OTel.attributeInt(
          'azure_key_vault.encrypted_bytes',
          res.encryptedBytes!,
        ));
      }
      if (res.decryptedBytes != null) {
        extras.add(OTel.attributeInt(
          'azure_key_vault.decrypted_bytes',
          res.decryptedBytes!,
        ));
      }
      if (res.hsmBackend != null) {
        extras.add(OTel.attributeBool(
          'azure_key_vault.hsm_backend',
          res.hsmBackend!,
        ));
      }
      if (res.purgeProtectionEnabled != null) {
        extras.add(OTel.attributeBool(
          'azure_key_vault.purge_protection.enabled',
          res.purgeProtectionEnabled!,
        ));
      }
      if (res.softDeleteEnabled != null) {
        extras.add(OTel.attributeBool(
          'azure_key_vault.soft_delete.enabled',
          res.softDeleteEnabled!,
        ));
      }
      if (res.recoverableDays != null) {
        extras.add(OTel.attributeInt(
          'azure_key_vault.recoverable_days',
          res.recoverableDays!,
        ));
      }
      if (res.deletedRecoveryLevel != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.deleted.recovery_level',
          res.deletedRecoveryLevel!,
        ));
      }
      if (res.errorCode != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.error.code',
          res.errorCode!,
        ));
        span.setStatus(SpanStatusCode.Error, 'Key Vault ${res.errorCode}');
      }
      if (res.errorMessage != null) {
        extras.add(OTel.attributeString(
          'azure_key_vault.error.message',
          res.errorMessage!,
        ));
      }
      if (res.statusCode != null) {
        extras.add(OTel.attributeInt(
          'http.response.status_code',
          res.statusCode!,
        ));
        if (res.statusCode! >= 400) {
          span.setStatus(
            SpanStatusCode.Error,
            'Key Vault HTTP ${res.statusCode}',
          );
        }
      }
      if (extras.isNotEmpty) span.addAttributes(OTel.attributes(extras));
    }
    return r.value;
  } catch (e, st) {
    span.addAttributes(OTel.attributes([
      OTel.attributeString(
        ErrorResource.errorType.key,
        e.runtimeType.toString(),
      ),
    ]));
    span.recordException(e, stackTrace: st);
    span.setStatus(SpanStatusCode.Error, e.toString());
    rethrow;
  } finally {
    span.end();
  }
}
