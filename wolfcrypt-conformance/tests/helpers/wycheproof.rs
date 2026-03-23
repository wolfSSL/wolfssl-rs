use serde::Deserialize;

// ---------------------------------------------------------------------------
// Generic Wycheproof file structure
// ---------------------------------------------------------------------------

/// Top-level Wycheproof test file structure.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WycheproofFile<G> {
    pub algorithm: String,
    pub schema: String,
    pub number_of_tests: usize,
    pub test_groups: Vec<G>,
}

pub trait HasTests {
    fn test_count(&self) -> usize;
}

impl<G: HasTests> WycheproofFile<G> {
    /// Verify parsed vector count matches the file's declared count.
    pub fn assert_vector_count(&self) {
        let actual: usize = self.test_groups.iter().map(|g| g.test_count()).sum();
        assert_eq!(
            actual, self.number_of_tests,
            "Wycheproof file {} claims {} tests but contains {}. \
             File may be truncated or parser is skipping vectors.",
            self.schema, self.number_of_tests, actual
        );
        assert!(
            actual > 0,
            "Wycheproof file {} contains zero tests",
            self.schema
        );
    }
}

/// Decode a hex string from Wycheproof JSON. Panics with context on failure.
pub fn hex_decode(hex_str: &str, context: &str) -> Vec<u8> {
    hex::decode(hex_str)
        .unwrap_or_else(|e| panic!("Invalid hex in {}: '{}': {}", context, hex_str, e))
}

/// Wycheproof test result field.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WycheproofResult {
    Valid,
    Invalid,
    Acceptable,
}

// ---------------------------------------------------------------------------
// AEAD (AES-GCM, ChaCha20-Poly1305)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AeadTestGroup {
    pub iv_size: usize,
    pub key_size: usize,
    pub tag_size: usize,
    pub tests: Vec<AeadTestCase>,
}

impl HasTests for AeadTestGroup {
    fn test_count(&self) -> usize {
        self.tests.len()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AeadTestCase {
    pub tc_id: usize,
    pub comment: String,
    pub key: String,
    pub iv: String,
    pub aad: String,
    pub msg: String,
    pub ct: String,
    pub tag: String,
    pub result: WycheproofResult,
    #[serde(default)]
    pub flags: Vec<String>,
}

// ---------------------------------------------------------------------------
// MAC (HMAC, CMAC)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MacTestGroup {
    pub key_size: usize,
    pub tag_size: usize,
    pub tests: Vec<MacTestCase>,
}

impl HasTests for MacTestGroup {
    fn test_count(&self) -> usize {
        self.tests.len()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MacTestCase {
    pub tc_id: usize,
    pub comment: String,
    pub key: String,
    pub msg: String,
    pub tag: String,
    pub result: WycheproofResult,
    #[serde(default)]
    pub flags: Vec<String>,
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HkdfTestGroup {
    pub key_size: usize,
    pub tests: Vec<HkdfTestCase>,
}

impl HasTests for HkdfTestGroup {
    fn test_count(&self) -> usize {
        self.tests.len()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HkdfTestCase {
    pub tc_id: usize,
    pub comment: String,
    pub ikm: String,
    pub salt: String,
    pub info: String,
    pub size: usize,
    pub okm: String,
    pub result: WycheproofResult,
    #[serde(default)]
    pub flags: Vec<String>,
}

// ---------------------------------------------------------------------------
// EdDSA (Ed25519, Ed448)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaTestGroup {
    #[serde(rename = "publicKey")]
    pub public_key: EddsaKeyInfo,
    pub tests: Vec<EddsaTestCase>,
}

impl HasTests for EddsaTestGroup {
    fn test_count(&self) -> usize {
        self.tests.len()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaKeyInfo {
    pub curve: String,
    pub pk: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaTestCase {
    pub tc_id: usize,
    pub comment: String,
    pub msg: String,
    pub sig: String,
    pub result: WycheproofResult,
    #[serde(default)]
    pub flags: Vec<String>,
}

// ---------------------------------------------------------------------------
// Key Wrap (AES-WRAP)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyWrapTestGroup {
    pub key_size: usize,
    pub tests: Vec<KeyWrapTestCase>,
}

impl HasTests for KeyWrapTestGroup {
    fn test_count(&self) -> usize {
        self.tests.len()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyWrapTestCase {
    pub tc_id: usize,
    pub comment: String,
    pub key: String,
    pub msg: String,
    pub ct: String,
    pub result: WycheproofResult,
    #[serde(default)]
    pub flags: Vec<String>,
}

// ---------------------------------------------------------------------------
// RSA signature verification (PKCS#1 v1.5 and PSS)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RsaSigTestGroup {
    pub key_size: usize,
    #[serde(rename = "publicKeyDer")]
    pub public_key_der: String,
    pub sha: String,
    pub tests: Vec<RsaSigTestCase>,
}

impl HasTests for RsaSigTestGroup {
    fn test_count(&self) -> usize {
        self.tests.len()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RsaSigTestCase {
    pub tc_id: usize,
    pub comment: String,
    pub msg: String,
    pub sig: String,
    pub result: WycheproofResult,
    #[serde(default)]
    pub flags: Vec<String>,
}

// ---------------------------------------------------------------------------
// ECDSA P1363 verification
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaP1363TestGroup {
    #[serde(rename = "publicKey")]
    pub public_key: EcdsaP1363KeyInfo,
    pub sha: String,
    pub tests: Vec<EcdsaP1363TestCase>,
}

impl HasTests for EcdsaP1363TestGroup {
    fn test_count(&self) -> usize {
        self.tests.len()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaP1363KeyInfo {
    pub curve: String,
    pub uncompressed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaP1363TestCase {
    pub tc_id: usize,
    pub comment: String,
    pub msg: String,
    pub sig: String,
    pub result: WycheproofResult,
    #[serde(default)]
    pub flags: Vec<String>,
}
