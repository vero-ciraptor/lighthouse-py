# lighthouse-py

Python bindings for [Lighthouse](https://github.com/sigp/lighthouse) Ethereum consensus types.

## Overview

This package provides Python bindings for SSZ serialization/deserialization of Ethereum consensus layer types using the Sigma Prime Lighthouse client library. It uses [PyO3](https://github.com/PyO3/pyo3) to expose Rust SSZ functionality to Python.

## Supported Types

### Electra Fork Types

**Mainnet:**
- `ElectraSignedBeaconBlockMainnet`
- `ElectraBeaconBlockContentsMainnet`
- `ElectraSignedBeaconBlockContentsMainnet`
- `ElectraBlindedBeaconBlockMainnet`
- `ElectraSignedBlindedBeaconBlockMainnet`

**Minimal:**
- `ElectraSignedBeaconBlockMinimal`
- `ElectraBeaconBlockContentsMinimal`
- `ElectraSignedBeaconBlockContentsMinimal`
- `ElectraBlindedBeaconBlockMinimal`
- `ElectraSignedBlindedBeaconBlockMinimal`

**Gnosis:**
- `ElectraSignedBeaconBlockGnosis`
- `ElectraBeaconBlockContentsGnosis`
- `ElectraSignedBeaconBlockContentsGnosis`
- `ElectraBlindedBeaconBlockGnosis`
- `ElectraSignedBlindedBeaconBlockGnosis`

## Installation

Requires Python 3.8+ and Rust toolchain.

```bash
pip install lighthouse-py
```

Or install from source:

```bash
pip install maturin
maturin develop  # for development
maturin build --release  # for distribution
```

## Usage

```python
from lighthouse_py import (
    ElectraSignedBeaconBlockMainnet,
    ElectraBeaconBlockContentsMainnet,
)

# Decode from SSZ bytes
block = ElectraSignedBeaconBlockMainnet.from_ssz(ssz_bytes)

# Encode to SSZ bytes
ssz_bytes = block.to_ssz()

# Decode from JSON
block = ElectraBeaconBlockContentsMainnet.from_json(json_bytes)

# Encode to JSON
json_bytes = block.to_json()

# Sign a block
signed_block = block.sign(signature_hex)

# Get block hash tree root
root = block.block_hash_tree_root()

# Get header dict
header = block.header_dict()
```

## Development

### Requirements

- Python 3.8+
- Rust toolchain
- [maturin](https://github.com/PyO3/maturin)

### Setup

```bash
# Build the Rust extension
maturin develop --release

# Run tests
python -c "from lighthouse_py import ElectraSignedBeaconBlockMainnet; print('OK')"
```

## License

Apache-2.0
