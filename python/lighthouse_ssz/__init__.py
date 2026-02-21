"""
Lighthouse SSZ - Python bindings for Lighthouse consensus types

This module provides Python bindings for Ethereum consensus types from
Sigma Prime's Lighthouse client.

Usage:
    from lighthouse_ssz import ElectraSignedBeaconBlockMainnet
    
    # Load from SSZ bytes
    with open('block.ssz', 'rb') as f:
        block = ElectraSignedBeaconBlockMainnet.from_ssz(f.read())
    
    print(block.slot())
    print(block.block_hash_tree_root())
"""

import sys
import os

# Get the directory of this file
_dir = os.path.dirname(os.path.abspath(__file__))

# Try to import the native module
try:
    from lighthouse_ssz_py import (
        # Mainnet classes
        ElectraSignedBeaconBlockMainnet,
        ElectraBeaconBlockContentsMainnet,
        ElectraSignedBeaconBlockContentsMainnet,
        ElectraBlindedBeaconBlockMainnet,
        ElectraSignedBlindedBeaconBlockMainnet,
        # Minimal classes
        ElectraSignedBeaconBlockMinimal,
        ElectraBeaconBlockContentsMinimal,
        ElectraSignedBeaconBlockContentsMinimal,
        ElectraBlindedBeaconBlockMinimal,
        ElectraSignedBlindedBeaconBlockMinimal,
        # Gnosis classes
        ElectraSignedBeaconBlockGnosis,
        ElectraBeaconBlockContentsGnosis,
        ElectraSignedBeaconBlockContentsGnosis,
        ElectraBlindedBeaconBlockGnosis,
        ElectraSignedBlindedBeaconBlockGnosis,
    )
except ImportError:
    # Try loading from the same directory
    import importlib.util
    spec = importlib.util.find_spec("lighthouse_ssz_py", [_dir])
    if spec is None:
        # Try with .so extension
        so_path = os.path.join(_dir, "lighthouse_ssz_py.so")
        if os.path.exists(so_path):
            spec = importlib.util.spec_from_file_location("lighthouse_ssz_py", so_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules["lighthouse_ssz_py"] = module
            spec.loader.exec_module(module)
            
            # Mainnet classes
            ElectraSignedBeaconBlockMainnet = module.ElectraSignedBeaconBlockMainnet
            ElectraBeaconBlockContentsMainnet = module.ElectraBeaconBlockContentsMainnet
            ElectraSignedBeaconBlockContentsMainnet = module.ElectraSignedBeaconBlockContentsMainnet
            ElectraBlindedBeaconBlockMainnet = module.ElectraBlindedBeaconBlockMainnet
            ElectraSignedBlindedBeaconBlockMainnet = module.ElectraSignedBlindedBeaconBlockMainnet
            # Minimal classes
            ElectraSignedBeaconBlockMinimal = module.ElectraSignedBeaconBlockMinimal
            ElectraBeaconBlockContentsMinimal = module.ElectraBeaconBlockContentsMinimal
            ElectraSignedBeaconBlockContentsMinimal = module.ElectraSignedBeaconBlockContentsMinimal
            ElectraBlindedBeaconBlockMinimal = module.ElectraBlindedBeaconBlockMinimal
            ElectraSignedBlindedBeaconBlockMinimal = module.ElectraSignedBlindedBeaconBlockMinimal
            # Gnosis classes
            ElectraSignedBeaconBlockGnosis = module.ElectraSignedBeaconBlockGnosis
            ElectraBeaconBlockContentsGnosis = module.ElectraBeaconBlockContentsGnosis
            ElectraSignedBeaconBlockContentsGnosis = module.ElectraSignedBeaconBlockContentsGnosis
            ElectraBlindedBeaconBlockGnosis = module.ElectraBlindedBeaconBlockGnosis
            ElectraSignedBlindedBeaconBlockGnosis = module.ElectraSignedBlindedBeaconBlockGnosis
        else:
            raise

__version__ = "0.1.0"

__all__ = [
    # Mainnet classes
    "ElectraSignedBeaconBlockMainnet",
    "ElectraBeaconBlockContentsMainnet",
    "ElectraSignedBeaconBlockContentsMainnet",
    "ElectraBlindedBeaconBlockMainnet",
    "ElectraSignedBlindedBeaconBlockMainnet",
    # Minimal classes
    "ElectraSignedBeaconBlockMinimal",
    "ElectraBeaconBlockContentsMinimal",
    "ElectraSignedBeaconBlockContentsMinimal",
    "ElectraBlindedBeaconBlockMinimal",
    "ElectraSignedBlindedBeaconBlockMinimal",
    # Gnosis classes
    "ElectraSignedBeaconBlockGnosis",
    "ElectraBeaconBlockContentsGnosis",
    "ElectraSignedBeaconBlockContentsGnosis",
    "ElectraBlindedBeaconBlockGnosis",
    "ElectraSignedBlindedBeaconBlockGnosis",
]
