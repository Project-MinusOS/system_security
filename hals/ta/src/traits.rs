// Copyright 2025, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Common TA traits.

use hal_wire::types::MillisecondsSinceEpoch;

/// Abstraction of constant-time comparisons, for use in cryptographic contexts where timing attacks
/// need to be avoided.
pub trait ConstTimeEq: Send {
    /// Indicate whether arguments are the same.
    fn eq(&self, left: &[u8], right: &[u8]) -> bool;
    /// Indicate whether arguments are the different.
    fn ne(&self, left: &[u8], right: &[u8]) -> bool {
        !self.eq(left, right)
    }
}

/// Abstraction of a monotonic clock.
pub trait MonotonicClock: Send {
    /// Return the current time in milliseconds since some arbitrary point in time.  Time must be
    /// monotonically increasing, and "current time" must not repeat until the Android device
    /// reboots, or until at least 50 million years have elapsed.  Time must also continue to
    /// advance while the device is suspended.  (For example, in Linux the equivalent would be to
    /// use `CLOCK_BOOTTIME` rather than `CLOCK_MONOTONIC` in `clock_gettime`.)
    fn now(&self) -> MillisecondsSinceEpoch;
}
