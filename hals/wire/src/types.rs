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

//! Common HAL types.

use crate::{AsCborValue, CborError, Value};

/// Milliseconds since an arbitrary epoch.  This must be monotonically increasing and not repeat
/// before device reboot, and should also count time passing while the device is suspended.
///
/// Encoded as a signed 64-bit integer to match the AIDL type (`long milliSeconds` in
/// `android.hardware.security.secureclock.Timestamp`) that it corresponds to.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MillisecondsSinceEpoch(pub i64);

impl AsCborValue for MillisecondsSinceEpoch {
    fn from_cbor_value(value: Value) -> Result<Self, CborError> {
        Ok(Self(i64::from_cbor_value(value)?))
    }
    fn to_cbor_value(self) -> Result<Value, CborError> {
        self.0.to_cbor_value()
    }
}

impl core::ops::Add<i64> for MillisecondsSinceEpoch {
    type Output = Self;
    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl core::ops::Sub<MillisecondsSinceEpoch> for MillisecondsSinceEpoch {
    type Output = i64;
    fn sub(self, rhs: MillisecondsSinceEpoch) -> Self::Output {
        self.0.saturating_sub(rhs.0)
    }
}
