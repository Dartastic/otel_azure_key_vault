// Licensed under the Apache License, Version 2.0
// Copyright 2025, Mindful Software LLC, All rights reserved.

import 'dart:async';

const _key = #dartastic_otel_libs_azure_key_vault_suppress;

bool azureKeyVaultInstrumentationSuppressed() => Zone.current[_key] == true;

T runWithoutAzureKeyVaultInstrumentation<T>(T Function() body) =>
    runZoned(body, zoneValues: {_key: true});

Future<T> runWithoutAzureKeyVaultInstrumentationAsync<T>(
  Future<T> Function() body,
) =>
    runZoned(body, zoneValues: {_key: true});
