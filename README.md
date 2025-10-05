# OpenGov-Grants

**Comprehensive grant management and fiscal administration system for city governments managing federal, state, and foundation funding opportunities**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org/downloads/)
[![CI](https://github.com/llamasearchai/OpenGrants/actions/workflows/ci.yml/badge.svg)](https://github.com/llamasearchai/OpenGrants/actions/workflows/ci.yml)

OpenGov-Grants is a production-grade Python system designed to support comprehensive grant management and fiscal administration system for city governments managing federal, state, and foundation funding opportunities. The system integrates AI/ML capabilities with regulatory compliance workflows to support government agencies and organizations.

## Key Features

- **AI-Powered Analysis**: Integrated OpenAI and Ollama support for intelligent analysis
- **Regulatory Compliance**: Built-in compliance checking and reporting
- **Multi-Provider LLM Support**: Graceful fallback between OpenAI, Ollama, and local models
- **Production-Ready**: Complete with testing, documentation, and deployment tools

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- Python 3.11 or higher
- uv (recommended) or pip
- SQLite 3.8 or higher
- Optional: Ollama for local LLM support

### Install with uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/llamasearchai/OpenGov-Grants.git
cd OpenGov-Grants

# Create virtual environment and install dependencies
uv venv
uv sync

# Activate virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

## Quick Start

1. **Initialize the database**:
   ```bash
   opengrants db init
   opengrants db seed
   ```

2. **Start the web interface**:
   ```bash
   opengrants serve-datasette
   ```

3. **Run your first analysis**:
   ```bash
   opengrants agent run "Analyze sample data"
   ```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone
git clone https://github.com/your-username/OpenGrants.git
cd OpenGrants

# Install development dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Run linters
uv run ruff check .
uv run mypy src/

# Format code
uv run black src/
uv run isort src/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/llamasearchai/OpenGov-Grants/issues)
- **Discussions**: [GitHub Discussions](https://github.com/llamasearchai/OpenGov-Grants/discussions)
- **Email**: nikjois@llamasearch.ai

---

Built by Nik Jois <nikjois@llamasearch.ai>