//! DPE engine test harness: wires wolfcrypt-dpe and reference backends into
//! the caliptra-dpe engine type system.

use caliptra_cfi_lib::CfiCounter;
use caliptra_dpe::dpe_instance::{DpeEnv, DpeInstance, DpeTypes};
use caliptra_dpe::support::Support;
use caliptra_dpe::{DpeFlags, DpeProfile, State};
use caliptra_dpe_platform::default::{DefaultPlatform, DefaultPlatformProfile};

use wolfcrypt_dpe::WolfCryptDpe384;

// ---------------------------------------------------------------------------
// DpeTypes wiring
// ---------------------------------------------------------------------------

/// DPE types wired to wolfcrypt-dpe P-384.
pub struct WolfDpeTypes384;

impl DpeTypes for WolfDpeTypes384 {
    type Crypto<'a> = WolfCryptDpe384;
    type Platform<'a> = DefaultPlatform;
}

/// DPE types wired to reference RustCrypto P-384.
pub struct RefDpeTypes384;

impl DpeTypes for RefDpeTypes384 {
    type Crypto<'a> = caliptra_dpe_crypto::Ecdsa384RustCrypto;
    type Platform<'a> = DefaultPlatform;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const LOCALITY: u32 = 0;

/// Standard support flags for most tests.
pub const DEFAULT_SUPPORT: Support = Support::AUTO_INIT
    .union(Support::SIMULATION)
    .union(Support::X509)
    .union(Support::RETAIN_PARENT_CONTEXT)
    .union(Support::ROTATE_CONTEXT);

/// Full support flags including CDI export and recursive.
pub const FULL_SUPPORT: Support = DEFAULT_SUPPORT
    .union(Support::CDI_EXPORT)
    .union(Support::RECURSIVE);

// ---------------------------------------------------------------------------
// Environment constructors
// ---------------------------------------------------------------------------

/// Create a DpeEnv for wolf P-384 backend.
pub fn make_wolf_env(state: &mut State) -> DpeEnv<'_, WolfDpeTypes384> {
    DpeEnv {
        crypto: WolfCryptDpe384::new(),
        platform: DefaultPlatform(DefaultPlatformProfile::P384),
        state,
    }
}

/// Create a DpeEnv for reference RustCrypto P-384 backend.
pub fn make_ref_env(state: &mut State) -> DpeEnv<'_, RefDpeTypes384> {
    DpeEnv {
        crypto: caliptra_dpe_crypto::Ecdsa384RustCrypto::new(),
        platform: DefaultPlatform(DefaultPlatformProfile::P384),
        state,
    }
}

// ---------------------------------------------------------------------------
// DPE instance constructors
// ---------------------------------------------------------------------------

/// Create a DPE instance with wolf backend and default support flags.
pub fn new_dpe_wolf(support: Support) -> (DpeInstance, State) {
    CfiCounter::reset_for_test();
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = make_wolf_env(&mut state);
    let dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).expect("Wolf DPE init failed");
    (dpe, state)
}

/// Create a DPE instance with reference backend and default support flags.
pub fn new_dpe_ref(support: Support) -> (DpeInstance, State) {
    CfiCounter::reset_for_test();
    let mut state = State::new(support, DpeFlags::empty());
    let mut env = make_ref_env(&mut state);
    let dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).expect("Ref DPE init failed");
    (dpe, state)
}
