# Service Protos

This repository contains Protocol Buffer definitions shared between `wendylabsinc/wendy-agent` and cloud services.

## Purpose

These protobuf files define the common interfaces and data structures used for communication between:
- Wendy Agent components
- Cloud service implementations
- Inter-service communication protocols

## Usage

Import these protobuf definitions into your projects to ensure consistent data structures and API contracts across the Wendy ecosystem.

## Structure

The protobuf files are organized to support various service interactions and maintain backwards compatibility across different service versions.

## Compatibility views and checks

See [frozen compatibility views](contracts/README.md) for build/generation
commands, independent compatibility baselines and the maintenance path for
additive canonical edits. Use Python 3.15.2 and Buf 1.75.0:

```sh
python3 scripts/contracts.py check --base <PR-base-commit>
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```
