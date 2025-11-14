# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- High-contrast architecture diagram (SVG + PNG) with color-coded domains.
- Repository banner, screenshots, and animated demo for README.
- Automated setup script (`install.sh`) for local provisioning.
- Minimal OpenAPI specification for REST endpoints (`docs/api/openapi.yaml`).
- Initial unit test suite covering parsing, correlation, and analytics workflows.
- CHANGELOG in Keep a Changelog format.

### Security
- Prepared CodeQL workflow for static analysis (pending first run).

## [1.0.0] - 2025-11-14
### Added
- Initial CyberSentinel release with Dockerized Flask backend and Chart.js dashboard.
- Threat intelligence ingestion from AbuseIPDB and AlienVault OTX.
- SSH and Apache log parsing with IOC correlation and analytics summaries.
- GitHub Pages walkthrough and recruiter-focused documentation.

### Infrastructure
- GitHub Actions CI smoke tests for backend import and syntax validation.

[Unreleased]: https://github.com/sr-857/CyberSentinel/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/sr-857/CyberSentinel/releases/tag/v1.0.0
