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
Hosted MCP implementers must also follow the
[scoped tunnel descriptor contract](conformance/tunnel/README.md#hosted-mcp-delegation-binding)
for FleetScope v2 credentials (WDY-3526).
