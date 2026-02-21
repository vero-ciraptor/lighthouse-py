use pyo3::prelude::*;
use pyo3::types::PyBytes;
use types::{MainnetEthSpec, MinimalEthSpec, GnosisEthSpec};
use types::{SignedBeaconBlock, BeaconBlockElectra, BeaconBlock};
use types::execution::{FullPayload, BlindedPayload};
use types::ChainSpec;
use ssz::{Encode, Decode};
use tree_hash::TreeHash;
use bls::Signature;

// ============================================================================
// Error conversion helpers
// ============================================================================

fn ssz_decode_error_to_pyerr(e: ssz::DecodeError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("SSZ decode error: {:?}", e))
}

fn serde_error_to_pyerr(e: serde_json::Error) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("JSON error: {:?}", e))
}

fn hex_decode_error_to_pyerr(e: hex::FromHexError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("Hex decode error: {:?}", e))
}

fn bls_error_to_pyerr(e: bls::Error) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("BLS error: {:?}", e))
}

// ============================================================================
// Spec helpers
// ============================================================================

fn get_mainnet_spec() -> ChainSpec { ChainSpec::mainnet() }
fn get_minimal_spec() -> ChainSpec { ChainSpec::minimal() }
fn get_gnosis_spec() -> ChainSpec { ChainSpec::gnosis() }

fn parse_hex(hex_str: &str) -> PyResult<Vec<u8>> {
    let hex_clean = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        &hex_str[2..]
    } else {
        hex_str
    };
    hex::decode(hex_clean).map_err(hex_decode_error_to_pyerr)
}

fn parse_signature(sig_hex: &str) -> PyResult<Signature> {
    let bytes = parse_hex(sig_hex)?;
    if bytes.len() != 96 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("Invalid signature length: expected 96 bytes, got {}", bytes.len())
        ));
    }
    Signature::deserialize(&bytes).map_err(bls_error_to_pyerr)
}

// ============================================================================
// Macros to generate the repetitive class implementations
// ============================================================================

/// Macro to generate a SignedBeaconBlock wrapper class
macro_rules! define_signed_beacon_block {
    ($class_name:ident, $inner_type:ty, $get_spec:expr) => {
        #[pyclass]
        #[derive(Clone)]
        struct $class_name {
            inner: $inner_type,
        }

        #[pymethods]
        impl $class_name {
            #[staticmethod]
            fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
                let spec = $get_spec;
                let inner = <$inner_type>::from_ssz_bytes(bytes, &spec)
                    .map_err(ssz_decode_error_to_pyerr)?;
                Ok(Self { inner })
            }

            #[staticmethod]
            fn from_json(bytes: &[u8]) -> PyResult<Self> {
                let inner: $inner_type = serde_json::from_slice(bytes)
                    .map_err(serde_error_to_pyerr)?;
                Ok(Self { inner })
            }

            fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
                Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
            }

            fn to_json(&self) -> PyResult<String> {
                serde_json::to_string(&self.inner).map_err(serde_error_to_pyerr)
            }

            fn __repr__(&self) -> String {
                format!("{}(slot={})", stringify!($class_name), self.slot())
            }

            fn slot(&self) -> u64 {
                self.inner.message().slot().into()
            }

            fn proposer_index(&self) -> u64 {
                self.inner.message().proposer_index()
            }

            fn parent_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().parent_root().as_slice()))
            }

            fn state_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().state_root().as_slice()))
            }

            fn signature(&self) -> String {
                format!("0x{}", hex::encode(self.inner.signature().serialize().as_slice()))
            }

            fn block_hash_tree_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().tree_hash_root().as_slice()))
            }

            fn signed_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
            }
        }
    };
}

/// Macro to generate a BeaconBlockElectra (contents) wrapper class
macro_rules! define_beacon_block_contents {
    ($class_name:ident, $inner_type:ty, $signed_class:ident) => {
        #[pyclass]
        #[derive(Clone)]
        struct $class_name {
            inner: $inner_type,
        }

        #[pymethods]
        impl $class_name {
            #[staticmethod]
            fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
                let inner = <$inner_type>::from_ssz_bytes(bytes)
                    .map_err(ssz_decode_error_to_pyerr)?;
                Ok(Self { inner })
            }

            #[staticmethod]
            fn from_json(bytes: &[u8]) -> PyResult<Self> {
                let inner: $inner_type = serde_json::from_slice(bytes)
                    .map_err(serde_error_to_pyerr)?;
                Ok(Self { inner })
            }

            fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
                Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
            }

            fn to_json(&self) -> PyResult<String> {
                serde_json::to_string(&self.inner).map_err(serde_error_to_pyerr)
            }

            fn __repr__(&self) -> String {
                format!("{}(slot={})", stringify!($class_name), self.slot())
            }

            fn slot(&self) -> u64 {
                self.inner.slot.into()
            }

            fn proposer_index(&self) -> u64 {
                self.inner.proposer_index
            }

            fn parent_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.parent_root.as_slice()))
            }

            fn state_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.state_root.as_slice()))
            }

            fn header_dict(&self) -> PyResult<PyObject> {
                Python::with_gil(|py| {
                    let dict = pyo3::types::PyDict::new_bound(py);
                    dict.set_item("slot", self.slot())?;
                    dict.set_item("proposer_index", self.proposer_index())?;
                    dict.set_item("parent_root", self.parent_root())?;
                    dict.set_item("state_root", self.state_root())?;
                    dict.set_item("block_hash_tree_root", self.block_hash_tree_root())?;
                    Ok(dict.into())
                })
            }

            fn sign(&self, signature: &str) -> PyResult<$signed_class> {
                let sig = parse_signature(signature)?;
                let block = BeaconBlock::Electra(self.inner.clone());
                let signed_block = SignedBeaconBlock::from_block(block, sig);
                Ok($signed_class { inner: signed_block })
            }

            fn block_hash_tree_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
            }
        }
    };
}

/// Macro to generate a SignedBeaconBlock (contents) wrapper class
macro_rules! define_signed_beacon_block_contents {
    ($class_name:ident, $inner_type:ty, $get_spec:expr) => {
        #[pyclass]
        #[derive(Clone)]
        struct $class_name {
            inner: $inner_type,
        }

        #[pymethods]
        impl $class_name {
            #[staticmethod]
            fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
                let spec = $get_spec;
                let inner = <$inner_type>::from_ssz_bytes(bytes, &spec)
                    .map_err(ssz_decode_error_to_pyerr)?;
                Ok(Self { inner })
            }

            #[staticmethod]
            fn from_json(bytes: &[u8]) -> PyResult<Self> {
                let inner: $inner_type = serde_json::from_slice(bytes)
                    .map_err(serde_error_to_pyerr)?;
                Ok(Self { inner })
            }

            fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
                Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
            }

            fn to_json(&self) -> PyResult<String> {
                serde_json::to_string(&self.inner).map_err(serde_error_to_pyerr)
            }

            fn __repr__(&self) -> String {
                format!("{}(slot={})", stringify!($class_name), self.slot())
            }

            fn slot(&self) -> u64 {
                self.inner.message().slot().into()
            }

            fn proposer_index(&self) -> u64 {
                self.inner.message().proposer_index()
            }

            fn parent_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().parent_root().as_slice()))
            }

            fn state_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().state_root().as_slice()))
            }

            fn signature(&self) -> String {
                format!("0x{}", hex::encode(self.inner.signature().serialize().as_slice()))
            }

            fn block_hash_tree_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().tree_hash_root().as_slice()))
            }

            fn signed_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
            }
        }
    };
}

/// Macro to generate a BlindedBeaconBlock (contents) wrapper class
macro_rules! define_blinded_beacon_block {
    ($class_name:ident, $inner_type:ty, $signed_class:ident) => {
        #[pyclass]
        #[derive(Clone)]
        struct $class_name {
            inner: $inner_type,
        }

        #[pymethods]
        impl $class_name {
            #[staticmethod]
            fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
                let inner = <$inner_type>::from_ssz_bytes(bytes)
                    .map_err(ssz_decode_error_to_pyerr)?;
                Ok(Self { inner })
            }

            #[staticmethod]
            fn from_json(bytes: &[u8]) -> PyResult<Self> {
                let inner: $inner_type = serde_json::from_slice(bytes)
                    .map_err(serde_error_to_pyerr)?;
                Ok(Self { inner })
            }

            fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
                Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
            }

            fn to_json(&self) -> PyResult<String> {
                serde_json::to_string(&self.inner).map_err(serde_error_to_pyerr)
            }

            fn __repr__(&self) -> String {
                format!("{}(slot={})", stringify!($class_name), self.slot())
            }

            fn slot(&self) -> u64 {
                self.inner.slot.into()
            }

            fn proposer_index(&self) -> u64 {
                self.inner.proposer_index
            }

            fn parent_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.parent_root.as_slice()))
            }

            fn state_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.state_root.as_slice()))
            }

            fn header_dict(&self) -> PyResult<PyObject> {
                Python::with_gil(|py| {
                    let dict = pyo3::types::PyDict::new_bound(py);
                    dict.set_item("slot", self.slot())?;
                    dict.set_item("proposer_index", self.proposer_index())?;
                    dict.set_item("parent_root", self.parent_root())?;
                    dict.set_item("state_root", self.state_root())?;
                    dict.set_item("block_hash_tree_root", self.block_hash_tree_root())?;
                    Ok(dict.into())
                })
            }

            fn sign(&self, signature: &str) -> PyResult<$signed_class> {
                let sig = parse_signature(signature)?;
                let block = BeaconBlock::Electra(self.inner.clone());
                let signed_block = SignedBeaconBlock::from_block(block, sig);
                Ok($signed_class { inner: signed_block })
            }

            fn block_hash_tree_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
            }
        }
    };
}

/// Macro to generate a SignedBlindedBeaconBlock wrapper class
macro_rules! define_signed_blinded_beacon_block {
    ($class_name:ident, $inner_type:ty, $get_spec:expr) => {
        #[pyclass]
        #[derive(Clone)]
        struct $class_name {
            inner: $inner_type,
        }

        #[pymethods]
        impl $class_name {
            #[staticmethod]
            fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
                let spec = $get_spec;
                let inner = <$inner_type>::from_ssz_bytes(bytes, &spec)
                    .map_err(ssz_decode_error_to_pyerr)?;
                Ok(Self { inner })
            }

            #[staticmethod]
            fn from_json(bytes: &[u8]) -> PyResult<Self> {
                let inner: $inner_type = serde_json::from_slice(bytes)
                    .map_err(serde_error_to_pyerr)?;
                Ok(Self { inner })
            }

            fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
                Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
            }

            fn to_json(&self) -> PyResult<String> {
                serde_json::to_string(&self.inner).map_err(serde_error_to_pyerr)
            }

            fn __repr__(&self) -> String {
                format!("{}(slot={})", stringify!($class_name), self.slot())
            }

            fn slot(&self) -> u64 {
                self.inner.message().slot().into()
            }

            fn proposer_index(&self) -> u64 {
                self.inner.message().proposer_index()
            }

            fn parent_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().parent_root().as_slice()))
            }

            fn state_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().state_root().as_slice()))
            }

            fn signature(&self) -> String {
                format!("0x{}", hex::encode(self.inner.signature().serialize().as_slice()))
            }

            fn block_hash_tree_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.message().tree_hash_root().as_slice()))
            }

            fn signed_root(&self) -> String {
                format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
            }
        }
    };
}

// ============================================================================
// Type aliases
// ============================================================================

// Mainnet
type SignedBeaconBlockMainnet = SignedBeaconBlock<MainnetEthSpec, FullPayload<MainnetEthSpec>>;
type SignedBlindedBeaconBlockMainnet = SignedBeaconBlock<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;
type BeaconBlockElectraMainnet = BeaconBlockElectra<MainnetEthSpec, FullPayload<MainnetEthSpec>>;
type BeaconBlockElectraBlindedMainnet = BeaconBlockElectra<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;

// Minimal
type SignedBeaconBlockMinimal = SignedBeaconBlock<MinimalEthSpec, FullPayload<MinimalEthSpec>>;
type SignedBlindedBeaconBlockMinimal = SignedBeaconBlock<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>;
type BeaconBlockElectraMinimal = BeaconBlockElectra<MinimalEthSpec, FullPayload<MinimalEthSpec>>;
type BeaconBlockElectraBlindedMinimal = BeaconBlockElectra<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>;

// Gnosis
type SignedBeaconBlockGnosis = SignedBeaconBlock<GnosisEthSpec, FullPayload<GnosisEthSpec>>;
type SignedBlindedBeaconBlockGnosis = SignedBeaconBlock<GnosisEthSpec, BlindedPayload<GnosisEthSpec>>;
type BeaconBlockElectraGnosis = BeaconBlockElectra<GnosisEthSpec, FullPayload<GnosisEthSpec>>;
type BeaconBlockElectraBlindedGnosis = BeaconBlockElectra<GnosisEthSpec, BlindedPayload<GnosisEthSpec>>;

// ============================================================================
// Generate Mainnet classes
// ============================================================================

define_signed_beacon_block!(ElectraSignedBeaconBlockMainnet, SignedBeaconBlockMainnet, get_mainnet_spec());
define_beacon_block_contents!(ElectraBeaconBlockContentsMainnet, BeaconBlockElectraMainnet, ElectraSignedBeaconBlockContentsMainnet);
define_signed_beacon_block_contents!(ElectraSignedBeaconBlockContentsMainnet, SignedBeaconBlockMainnet, get_mainnet_spec());
define_blinded_beacon_block!(ElectraBlindedBeaconBlockMainnet, BeaconBlockElectraBlindedMainnet, ElectraSignedBlindedBeaconBlockMainnet);
define_signed_blinded_beacon_block!(ElectraSignedBlindedBeaconBlockMainnet, SignedBlindedBeaconBlockMainnet, get_mainnet_spec());

// ============================================================================
// Generate Minimal classes
// ============================================================================

define_signed_beacon_block!(ElectraSignedBeaconBlockMinimal, SignedBeaconBlockMinimal, get_minimal_spec());
define_beacon_block_contents!(ElectraBeaconBlockContentsMinimal, BeaconBlockElectraMinimal, ElectraSignedBeaconBlockContentsMinimal);
define_signed_beacon_block_contents!(ElectraSignedBeaconBlockContentsMinimal, SignedBeaconBlockMinimal, get_minimal_spec());
define_blinded_beacon_block!(ElectraBlindedBeaconBlockMinimal, BeaconBlockElectraBlindedMinimal, ElectraSignedBlindedBeaconBlockMinimal);
define_signed_blinded_beacon_block!(ElectraSignedBlindedBeaconBlockMinimal, SignedBlindedBeaconBlockMinimal, get_minimal_spec());

// ============================================================================
// Generate Gnosis classes
// ============================================================================

define_signed_beacon_block!(ElectraSignedBeaconBlockGnosis, SignedBeaconBlockGnosis, get_gnosis_spec());
define_beacon_block_contents!(ElectraBeaconBlockContentsGnosis, BeaconBlockElectraGnosis, ElectraSignedBeaconBlockContentsGnosis);
define_signed_beacon_block_contents!(ElectraSignedBeaconBlockContentsGnosis, SignedBeaconBlockGnosis, get_gnosis_spec());
define_blinded_beacon_block!(ElectraBlindedBeaconBlockGnosis, BeaconBlockElectraBlindedGnosis, ElectraSignedBlindedBeaconBlockGnosis);
define_signed_blinded_beacon_block!(ElectraSignedBlindedBeaconBlockGnosis, SignedBlindedBeaconBlockGnosis, get_gnosis_spec());

// ============================================================================
// Module
// ============================================================================

#[pymodule]
fn lighthouse_ssz_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Mainnet classes
    m.add_class::<ElectraSignedBeaconBlockMainnet>()?;
    m.add_class::<ElectraBeaconBlockContentsMainnet>()?;
    m.add_class::<ElectraSignedBeaconBlockContentsMainnet>()?;
    m.add_class::<ElectraBlindedBeaconBlockMainnet>()?;
    m.add_class::<ElectraSignedBlindedBeaconBlockMainnet>()?;

    // Minimal classes
    m.add_class::<ElectraSignedBeaconBlockMinimal>()?;
    m.add_class::<ElectraBeaconBlockContentsMinimal>()?;
    m.add_class::<ElectraSignedBeaconBlockContentsMinimal>()?;
    m.add_class::<ElectraBlindedBeaconBlockMinimal>()?;
    m.add_class::<ElectraSignedBlindedBeaconBlockMinimal>()?;

    // Gnosis classes
    m.add_class::<ElectraSignedBeaconBlockGnosis>()?;
    m.add_class::<ElectraBeaconBlockContentsGnosis>()?;
    m.add_class::<ElectraSignedBeaconBlockContentsGnosis>()?;
    m.add_class::<ElectraBlindedBeaconBlockGnosis>()?;
    m.add_class::<ElectraSignedBlindedBeaconBlockGnosis>()?;

    Ok(())
}
