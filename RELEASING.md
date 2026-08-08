<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2026 Diridium Technologies Inc. -->

# Releasing

The plugin version is single-sourced in the parent `pom.xml` as `<revision>`. The engine version it targets is `<mc.version>`; CI derives the release tag and OIE tarball name from it.

## Build and verify locally

```bash
ENGINE_DIR=/path/to/engine ./scripts/install-engine-jars.sh
mvn clean package
```

Confirm the zip contains only the three plugin jars plus `plugin.xml`, and nothing else:

```bash
unzip -l package/target/oie-ssh-tunnel-manager-*.zip
```

JSch, XStream, and the test-only libraries must **not** appear — they are `provided` or `test` scope and the engine supplies them at runtime.

## Signing (optional)

Signing is off by default. To produce a signed build, activate the `signing` profile with the YubiKey present:

```bash
YUBIKEY_PIN=…… mvn clean package -Psigning
```

Copy the signed zip out of `package/target/` immediately — a later `mvn clean` deletes it, and the signature cannot be regenerated without the hardware key.

## Publishing a release

1. Bump `<revision>` in the parent `pom.xml`.
2. Tag the release and push the tag.
3. Let CI build, or build locally, then attach the zip to a **draft** GitHub release.
4. Review the draft's assets, then publish by hand. Do not auto-publish, and never overwrite a published release's assets — cut a new version instead.

## Engine version bumps

When targeting a new engine version, update `<mc.version>`, re-run the pre-flight checks (no direct xerces use, Java 17, XML through the JDK parser), and follow the compat-release policy: a minor plugin bump, a clean break to the new engine only unless both have actually been tested, and keep the previous release available for users on the older engine.
