---
title: Failures and recovery
summary: What the app does when something fails: signature, network, altered file, rollback or a crash during install.
---
In every case the result is the same: nothing new is installed, the already installed rules keep working and the reason is explained to the person with the technical detail.

## Signature failure

{{diagram:client-signature-failure}}

## Network failure

{{diagram:client-network-failure}}

## Altered file

{{diagram:client-altered-file}}

## Rollback or fork

{{diagram:client-rollback}}

The trust state (the newest verified checkpoint) is stored in a file with 0600 permissions and is saved before the rules are activated, so a crash cannot leave it behind.

## Crash during install

See the diagram in [Atomic install](page:client-update). A journal lets the next start finish or undo the swap, and a file lock prevents two updates at once.
