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

## Versioned contracts

See the [compatibility policy](docs/compatibility.md),
[frozen compatibility views and validation](contracts/README.md), and
[release/protection procedure](docs/releases.md). The planned first catalogue
tag is `v1.0.0`. It is not published by this change. Existing root import paths
remain available. Consumers migrate separately after the tag is approved.
