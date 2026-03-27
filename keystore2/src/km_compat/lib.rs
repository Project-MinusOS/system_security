// Copyright 2020, The Android Open Source Project
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

//! Export into Rust a function to create a KeyMintDevice and add it as a service.

unsafe extern "C" {
    /// Start a KeyMint compatibility wrapper service.
    ///
    /// Returns a binder status value.
    safe fn addKeyMintDeviceService() -> i32;

    /// Start a KeyMint compatibility wrapper service registered with the provided name.
    ///
    /// Returns a binder status value.
    fn addNamedKeyMintDeviceService(instance_name: *const std::ffi::c_char) -> i32;
}

/// Start a KeyMint compatibility wrapper service.
///
/// Returns a binder status value.
pub fn add_keymint_device_service() -> i32 {
    addKeyMintDeviceService()
}

/// Start a KeyMint compatibility wrapper service registered with the provided name.
///
/// Returns a binder status value.
pub fn add_named_keymint_device_service(name: &str) -> i32 {
    let name = std::ffi::CString::new(name).unwrap();
    // SAFETY: The `name` C string is valid for the duration of the call, and
    // the underlying C++ code does not hold on to the pointer.
    unsafe { addNamedKeyMintDeviceService(name.as_ptr()) }
}

#[cfg(test)]
mod tests;
