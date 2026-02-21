use pyo3::prelude::*;
use pyo3::types::PyBytes;
use types::{MainnetEthSpec, MinimalEthSpec, GnosisEthSpec};
use types::{SignedBeaconBlock, BeaconBlockElectra, BeaconBlock};
use types::execution::{FullPayload, BlindedPayload};
use types::ChainSpec;
use ssz::{Encode, Decode};
use tree_hash::TreeHash;
use bls::Signature;

// Type aliases for concrete types - Mainnet
type SignedBeaconBlockMainnet = SignedBeaconBlock<MainnetEthSpec, FullPayload<MainnetEthSpec>>;
type SignedBlindedBeaconBlockMainnet = SignedBeaconBlock<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;
type BeaconBlockElectraMainnet = BeaconBlockElectra<MainnetEthSpec, FullPayload<MainnetEthSpec>>;
type BeaconBlockElectraBlindedMainnet = BeaconBlockElectra<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>;

// Type aliases for concrete types - Minimal
type SignedBeaconBlockMinimal = SignedBeaconBlock<MinimalEthSpec, FullPayload<MinimalEthSpec>>;
type SignedBlindedBeaconBlockMinimal = SignedBeaconBlock<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>;
type BeaconBlockElectraMinimal = BeaconBlockElectra<MinimalEthSpec, FullPayload<MinimalEthSpec>>;
type BeaconBlockElectraBlindedMinimal = BeaconBlockElectra<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>;

// Type aliases for concrete types - Gnosis
type SignedBeaconBlockGnosis = SignedBeaconBlock<GnosisEthSpec, FullPayload<GnosisEthSpec>>;
type SignedBlindedBeaconBlockGnosis = SignedBeaconBlock<GnosisEthSpec, BlindedPayload<GnosisEthSpec>>;
type BeaconBlockElectraGnosis = BeaconBlockElectra<GnosisEthSpec, FullPayload<GnosisEthSpec>>;
type BeaconBlockElectraBlindedGnosis = BeaconBlockElectra<GnosisEthSpec, BlindedPayload<GnosisEthSpec>>;

/// Convert SSZ decode error to PyErr
fn ssz_decode_error_to_pyerr(e: ssz::DecodeError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("SSZ decode error: {:?}", e))
}

/// Convert serde error to PyErr
fn serde_error_to_pyerr(e: serde_json::Error) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("JSON error: {:?}", e))
}

/// Convert hex decode error to PyErr
fn hex_decode_error_to_pyerr(e: hex::FromHexError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("Hex decode error: {:?}", e))
}

/// Convert BLS error to PyErr
fn bls_error_to_pyerr(e: bls::Error) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("BLS error: {:?}", e))
}

// ============================================================================
// Helper functions
// ============================================================================

fn get_mainnet_spec() -> ChainSpec {
    ChainSpec::mainnet()
}

fn get_minimal_spec() -> ChainSpec {
    ChainSpec::minimal()
}

fn get_gnosis_spec() -> ChainSpec {
    ChainSpec::gnosis()
}

/// Parse a hex string (with or without 0x prefix) into bytes
fn parse_hex(hex_str: &str) -> PyResult<Vec<u8>> {
    let hex_clean = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        &hex_str[2..]
    } else {
        hex_str
    };
    hex::decode(hex_clean).map_err(hex_decode_error_to_pyerr)
}

/// Parse a BLS signature from a hex string
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
// ElectraSignedBeaconBlockMainnet
// ============================================================================

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBeaconBlockMainnet {
    inner: SignedBeaconBlockMainnet,
}

#[pymethods]
impl ElectraSignedBeaconBlockMainnet {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_mainnet_spec();
        let inner = SignedBeaconBlockMainnet::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBeaconBlockMainnet = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBeaconBlockMainnet(slot={})", self.slot())
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

// ============================================================================
// ElectraBeaconBlockContentsMainnet
// ============================================================================

#[pyclass]
#[derive(Clone)]
struct ElectraBeaconBlockContentsMainnet {
    inner: BeaconBlockElectraMainnet,
}

#[pymethods]
impl ElectraBeaconBlockContentsMainnet {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let inner = BeaconBlockElectraMainnet::from_ssz_bytes(bytes)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: BeaconBlockElectraMainnet = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraBeaconBlockContentsMainnet(slot={})", self.slot())
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

    fn sign(&self, signature: &str) -> PyResult<ElectraSignedBeaconBlockContentsMainnet> {
        let sig = parse_signature(signature)?;
        let block = BeaconBlock::Electra(self.inner.clone());
        let signed_block = SignedBeaconBlock::from_block(block, sig);
        Ok(ElectraSignedBeaconBlockContentsMainnet { inner: signed_block })
    }

    fn block_hash_tree_root(&self) -> String {
        format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
    }
}

// ============================================================================
// ElectraSignedBeaconBlockContentsMainnet (wrapper)
// ============================================================================

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBeaconBlockContentsMainnet {
    inner: SignedBeaconBlockMainnet,
}

#[pymethods]
impl ElectraSignedBeaconBlockContentsMainnet {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_mainnet_spec();
        let inner = SignedBeaconBlockMainnet::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBeaconBlockMainnet = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBeaconBlockContentsMainnet(slot={})", self.slot())
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

// ============================================================================
// ElectraBlindedBeaconBlockMainnet
// ============================================================================

#[pyclass]
#[derive(Clone)]
struct ElectraBlindedBeaconBlockMainnet {
    inner: BeaconBlockElectraBlindedMainnet,
}

#[pymethods]
impl ElectraBlindedBeaconBlockMainnet {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let inner = BeaconBlockElectraBlindedMainnet::from_ssz_bytes(bytes)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: BeaconBlockElectraBlindedMainnet = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraBlindedBeaconBlockMainnet(slot={})", self.slot())
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

    fn sign(&self, signature: &str) -> PyResult<ElectraSignedBlindedBeaconBlockMainnet> {
        let sig = parse_signature(signature)?;
        let block = BeaconBlock::Electra(self.inner.clone());
        let signed_block = SignedBeaconBlock::from_block(block, sig);
        Ok(ElectraSignedBlindedBeaconBlockMainnet { inner: signed_block })
    }

    fn block_hash_tree_root(&self) -> String {
        format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
    }
}

// ============================================================================
// ElectraSignedBlindedBeaconBlockMainnet
// ============================================================================

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBlindedBeaconBlockMainnet {
    inner: SignedBlindedBeaconBlockMainnet,
}

#[pymethods]
impl ElectraSignedBlindedBeaconBlockMainnet {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_mainnet_spec();
        let inner = SignedBlindedBeaconBlockMainnet::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBlindedBeaconBlockMainnet = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBlindedBeaconBlockMainnet(slot={})", self.slot())
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

// ============================================================================
// Minimal Spec Classes
// ============================================================================

// ----------------------------------------------------------------------------
// ElectraSignedBeaconBlockMinimal
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBeaconBlockMinimal {
    inner: SignedBeaconBlockMinimal,
}

#[pymethods]
impl ElectraSignedBeaconBlockMinimal {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_minimal_spec();
        let inner = SignedBeaconBlockMinimal::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBeaconBlockMinimal = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBeaconBlockMinimal(slot={})", self.slot())
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

// ----------------------------------------------------------------------------
// ElectraBeaconBlockContentsMinimal
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraBeaconBlockContentsMinimal {
    inner: BeaconBlockElectraMinimal,
}

#[pymethods]
impl ElectraBeaconBlockContentsMinimal {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let inner = BeaconBlockElectraMinimal::from_ssz_bytes(bytes)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: BeaconBlockElectraMinimal = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraBeaconBlockContentsMinimal(slot={})", self.slot())
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

    fn sign(&self, signature: &str) -> PyResult<ElectraSignedBeaconBlockContentsMinimal> {
        let sig = parse_signature(signature)?;
        let block = BeaconBlock::Electra(self.inner.clone());
        let signed_block = SignedBeaconBlock::from_block(block, sig);
        Ok(ElectraSignedBeaconBlockContentsMinimal { inner: signed_block })
    }

    fn block_hash_tree_root(&self) -> String {
        format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
    }
}

// ----------------------------------------------------------------------------
// ElectraSignedBeaconBlockContentsMinimal
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBeaconBlockContentsMinimal {
    inner: SignedBeaconBlockMinimal,
}

#[pymethods]
impl ElectraSignedBeaconBlockContentsMinimal {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_minimal_spec();
        let inner = SignedBeaconBlockMinimal::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBeaconBlockMinimal = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBeaconBlockContentsMinimal(slot={})", self.slot())
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

// ----------------------------------------------------------------------------
// ElectraBlindedBeaconBlockMinimal
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraBlindedBeaconBlockMinimal {
    inner: BeaconBlockElectraBlindedMinimal,
}

#[pymethods]
impl ElectraBlindedBeaconBlockMinimal {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let inner = BeaconBlockElectraBlindedMinimal::from_ssz_bytes(bytes)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: BeaconBlockElectraBlindedMinimal = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraBlindedBeaconBlockMinimal(slot={})", self.slot())
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

    fn sign(&self, signature: &str) -> PyResult<ElectraSignedBlindedBeaconBlockMinimal> {
        let sig = parse_signature(signature)?;
        let block = BeaconBlock::Electra(self.inner.clone());
        let signed_block = SignedBeaconBlock::from_block(block, sig);
        Ok(ElectraSignedBlindedBeaconBlockMinimal { inner: signed_block })
    }

    fn block_hash_tree_root(&self) -> String {
        format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
    }
}

// ----------------------------------------------------------------------------
// ElectraSignedBlindedBeaconBlockMinimal
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBlindedBeaconBlockMinimal {
    inner: SignedBlindedBeaconBlockMinimal,
}

#[pymethods]
impl ElectraSignedBlindedBeaconBlockMinimal {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_minimal_spec();
        let inner = SignedBlindedBeaconBlockMinimal::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBlindedBeaconBlockMinimal = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBlindedBeaconBlockMinimal(slot={})", self.slot())
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

// ============================================================================
// Gnosis Spec Classes
// ============================================================================

// ----------------------------------------------------------------------------
// ElectraSignedBeaconBlockGnosis
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBeaconBlockGnosis {
    inner: SignedBeaconBlockGnosis,
}

#[pymethods]
impl ElectraSignedBeaconBlockGnosis {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_gnosis_spec();
        let inner = SignedBeaconBlockGnosis::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBeaconBlockGnosis = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBeaconBlockGnosis(slot={})", self.slot())
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

// ----------------------------------------------------------------------------
// ElectraBeaconBlockContentsGnosis
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraBeaconBlockContentsGnosis {
    inner: BeaconBlockElectraGnosis,
}

#[pymethods]
impl ElectraBeaconBlockContentsGnosis {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let inner = BeaconBlockElectraGnosis::from_ssz_bytes(bytes)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: BeaconBlockElectraGnosis = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraBeaconBlockContentsGnosis(slot={})", self.slot())
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

    fn sign(&self, signature: &str) -> PyResult<ElectraSignedBeaconBlockContentsGnosis> {
        let sig = parse_signature(signature)?;
        let block = BeaconBlock::Electra(self.inner.clone());
        let signed_block = SignedBeaconBlock::from_block(block, sig);
        Ok(ElectraSignedBeaconBlockContentsGnosis { inner: signed_block })
    }

    fn block_hash_tree_root(&self) -> String {
        format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
    }
}

// ----------------------------------------------------------------------------
// ElectraSignedBeaconBlockContentsGnosis
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBeaconBlockContentsGnosis {
    inner: SignedBeaconBlockGnosis,
}

#[pymethods]
impl ElectraSignedBeaconBlockContentsGnosis {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_gnosis_spec();
        let inner = SignedBeaconBlockGnosis::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBeaconBlockGnosis = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBeaconBlockContentsGnosis(slot={})", self.slot())
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

// ----------------------------------------------------------------------------
// ElectraBlindedBeaconBlockGnosis
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraBlindedBeaconBlockGnosis {
    inner: BeaconBlockElectraBlindedGnosis,
}

#[pymethods]
impl ElectraBlindedBeaconBlockGnosis {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let inner = BeaconBlockElectraBlindedGnosis::from_ssz_bytes(bytes)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: BeaconBlockElectraBlindedGnosis = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraBlindedBeaconBlockGnosis(slot={})", self.slot())
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

    fn sign(&self, signature: &str) -> PyResult<ElectraSignedBlindedBeaconBlockGnosis> {
        let sig = parse_signature(signature)?;
        let block = BeaconBlock::Electra(self.inner.clone());
        let signed_block = SignedBeaconBlock::from_block(block, sig);
        Ok(ElectraSignedBlindedBeaconBlockGnosis { inner: signed_block })
    }

    fn block_hash_tree_root(&self) -> String {
        format!("0x{}", hex::encode(self.inner.tree_hash_root().as_slice()))
    }
}

// ----------------------------------------------------------------------------
// ElectraSignedBlindedBeaconBlockGnosis
// ----------------------------------------------------------------------------

#[pyclass]
#[derive(Clone)]
struct ElectraSignedBlindedBeaconBlockGnosis {
    inner: SignedBlindedBeaconBlockGnosis,
}

#[pymethods]
impl ElectraSignedBlindedBeaconBlockGnosis {
    #[staticmethod]
    fn from_ssz(bytes: &[u8]) -> PyResult<Self> {
        let spec = get_gnosis_spec();
        let inner = SignedBlindedBeaconBlockGnosis::from_ssz_bytes(bytes, &spec)
            .map_err(ssz_decode_error_to_pyerr)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_json(bytes: &[u8]) -> PyResult<Self> {
        let inner: SignedBlindedBeaconBlockGnosis = serde_json::from_slice(bytes)
            .map_err(serde_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn to_ssz<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.inner.as_ssz_bytes()))
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(serde_error_to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("ElectraSignedBlindedBeaconBlockGnosis(slot={})", self.slot())
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
