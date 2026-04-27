use wolfhsm_sys::{
    wh_Client_CounterDestroy, wh_Client_CounterIncrement, wh_Client_CounterInit,
    wh_Client_CounterRead, wh_Client_CounterReset,
};

use crate::client::Client;
use crate::error::WolfHsmError;
use crate::nvm::NvmId;

impl Client {
    /// Create or reinitialize a counter with the given starting value.
    ///
    /// Passes `value` to the server as the desired initial count.  Returns the
    /// server's confirmed value.  Counters saturate at `u32::MAX` — they never
    /// wrap.
    pub fn counter_init(&mut self, id: NvmId, value: u32) -> Result<u32, WolfHsmError> {
        let mut counter: u32 = value;
        // SAFETY: ctx_ptr is valid for the duration of this call; counter is a
        // valid stack location for the IN/OUT parameter.
        let rc = unsafe { wh_Client_CounterInit(self.ctx_ptr(), id.0, &mut counter) };
        WolfHsmError::check(rc, "wh_Client_CounterInit")?;
        Ok(counter)
    }

    /// Reset a counter to zero.
    ///
    /// Returns the server's confirmed value (0).
    pub fn counter_reset(&mut self, id: NvmId) -> Result<u32, WolfHsmError> {
        let mut counter: u32 = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; counter is a
        // valid stack location for the OUT parameter.
        let rc = unsafe { wh_Client_CounterReset(self.ctx_ptr(), id.0, &mut counter) };
        WolfHsmError::check(rc, "wh_Client_CounterReset")?;
        Ok(counter)
    }

    /// Increment a counter by 1.
    ///
    /// Returns the value after increment.  Saturates at `u32::MAX` per server
    /// policy — the value never wraps.
    pub fn counter_increment(&mut self, id: NvmId) -> Result<u32, WolfHsmError> {
        let mut counter: u32 = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; counter is a
        // valid stack location for the OUT parameter.
        let rc = unsafe { wh_Client_CounterIncrement(self.ctx_ptr(), id.0, &mut counter) };
        WolfHsmError::check(rc, "wh_Client_CounterIncrement")?;
        Ok(counter)
    }

    /// Read the current counter value without modifying it.
    pub fn counter_read(&mut self, id: NvmId) -> Result<u32, WolfHsmError> {
        let mut counter: u32 = 0;
        // SAFETY: ctx_ptr is valid for the duration of this call; counter is a
        // valid stack location for the OUT parameter.
        let rc = unsafe { wh_Client_CounterRead(self.ctx_ptr(), id.0, &mut counter) };
        WolfHsmError::check(rc, "wh_Client_CounterRead")?;
        Ok(counter)
    }

    /// Permanently destroy a counter.
    pub fn counter_destroy(&mut self, id: NvmId) -> Result<(), WolfHsmError> {
        // SAFETY: ctx_ptr is valid for the duration of this call.
        let rc = unsafe { wh_Client_CounterDestroy(self.ctx_ptr(), id.0) };
        WolfHsmError::check(rc, "wh_Client_CounterDestroy")
    }
}
