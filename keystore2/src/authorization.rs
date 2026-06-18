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

//! This module implements IKeystoreAuthorization AIDL interface.

use crate::async_task::AsyncTask;
use crate::error::anyhow_error_to_cstring;
use crate::error::Error as KeystoreError;
use crate::globals::{DB, ENFORCEMENTS, LEGACY_IMPORTER, SUPER_KEY};
use crate::permission::KeystorePerm;
use crate::super_key::WipeKeyOption;
use crate::utils::{
    check_keystore_permission, watchdog as wd, AndroidUserId, Challenge, SecureUserId,
};
use crate::{ks_err, log_client_err};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use android_security_authorization::aidl::android::security::authorization::{
    AuthorizationTokens::AuthorizationTokens, IKeystoreAuthorization::BnKeystoreAuthorization,
    IKeystoreAuthorization::IKeystoreAuthorization, ResponseCode::ResponseCode,
};
use android_security_authorization::binder::{
    BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Status as BinderStatus,
    Strong,
};
use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode as KsResponseCode;
use anyhow::{Context, Result};
use keystore2_crypto::{zvec::ZVec, Password};
use keystore2_selinux as selinux;
use log::{error, info};
use std::sync::Arc;

/// This is the Authorization error type, it wraps binder exceptions and the
/// Authorization ResponseCode
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Wraps an IKeystoreAuthorization response code as defined by
    /// android.security.authorization AIDL interface specification.
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),
    /// Wraps a Binder exception code other than a service specific exception.
    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),
}

/// Translate an error into a service specific exception, logging along the way.
///
/// `Error::Rc(x)` variants get mapped onto a service specific error code of `x`.
/// Certain response codes may be returned from keystore/ResponseCode.aidl by the keystore2 modules,
/// which are then converted to the corresponding response codes of android.security.authorization
/// AIDL interface specification.
///
/// `selinux::Error::perm()` is mapped on `ResponseCode::PERMISSION_DENIED`.
///
/// All non `Error` error conditions get mapped onto ResponseCode::SYSTEM_ERROR`.
pub fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
    log_client_err!(e);
    let root_cause = e.root_cause();
    if let Some(KeystoreError::Rc(ks_rcode)) = root_cause.downcast_ref::<KeystoreError>() {
        let rc = match *ks_rcode {
            // Although currently keystore2/ResponseCode.aidl and
            // authorization/ResponseCode.aidl share the same integer values for the
            // common response codes, this may deviate in the future, hence the
            // conversion here.
            KsResponseCode::SYSTEM_ERROR => ResponseCode::SYSTEM_ERROR.0,
            KsResponseCode::KEY_NOT_FOUND => ResponseCode::KEY_NOT_FOUND.0,
            KsResponseCode::VALUE_CORRUPTED => ResponseCode::VALUE_CORRUPTED.0,
            KsResponseCode::INVALID_ARGUMENT => ResponseCode::INVALID_ARGUMENT.0,
            // If the code paths of IKeystoreAuthorization aidl's methods happen to return
            // other error codes from KsResponseCode in the future, they should be converted
            // as well.
            _ => ResponseCode::SYSTEM_ERROR.0,
        };
        BinderStatus::new_service_specific_error(rc, anyhow_error_to_cstring(&e).as_deref())
    } else {
        let rc = match root_cause.downcast_ref::<Error>() {
            Some(Error::Rc(rcode)) => rcode.0,
            Some(Error::Binder(_, _)) => ResponseCode::SYSTEM_ERROR.0,
            None => match root_cause.downcast_ref::<selinux::Error>() {
                Some(selinux::Error::PermissionDenied) => ResponseCode::PERMISSION_DENIED.0,
                _ => ResponseCode::SYSTEM_ERROR.0,
            },
        };
        BinderStatus::new_service_specific_error(rc, anyhow_error_to_cstring(&e).as_deref())
    }
}

/// This struct is defined to implement the `IKeystoreAuthorization` AIDL interface.
pub enum AuthorizationManager {
    /// Device lock notifications are handled synchronously.
    Synchronous,
    /// Device lock notifications are handled asynchronously by a separate thread, started on
    /// demand.
    Asynchronous(Arc<AsyncTask>),
}

/// Implementation of the parts of `IKeystoreAuthorization` that track device lock status.
pub struct DeviceLockState;

/// Pending notifications about the lock state of the device for a user.
#[derive(Debug)]
pub struct LockStateNotification {
    /// Android user that the notification pertains to.
    pub user: AndroidUserId,
    /// Lock state
    pub state: LockState,
}

/// Lock state for a user.
#[derive(Debug)]
pub enum LockState {
    /// Device has been unlocked.
    DeviceUnlocked {
        /// Secret derived from synthetic password, if available.
        password: Option<ZVec>,
    },
    /// Device has been locked.
    DeviceLocked {
        /// SIDs of class 3 biometrics that can unlock the device for the user.
        unlocking_sids: Vec<SecureUserId>,
        /// Whether a weak unlock method can unlock the device for the user.
        weak_unlock_enabled: bool,
    },
    /// User's CE storage has been locked.
    UserStorageLocked,
    /// Weak unlock methods have expired.
    WeakUnlockMethodsExpired,
    /// Non-LSKF unlock methods have expired.
    NonLskfUnlockMethodsExpired,
}

impl DeviceLockState {
    /// Update the lock state based on the given notification.
    fn update(op: LockStateNotification) {
        match op.state {
            LockState::DeviceUnlocked { password } => {
                Self::on_device_unlocked(op.user, password.map(Password::Owned))
            }
            LockState::DeviceLocked { unlocking_sids, weak_unlock_enabled } => {
                Self::on_device_locked(op.user, &unlocking_sids, weak_unlock_enabled)
            }
            LockState::UserStorageLocked => Self::on_user_storage_locked(op.user),
            LockState::WeakUnlockMethodsExpired => Self::on_weak_unlock_methods_expired(op.user),
            LockState::NonLskfUnlockMethodsExpired => {
                Self::on_non_lskf_unlock_methods_expired(op.user)
            }
        }
    }

    fn on_device_unlocked(user: AndroidUserId, password: Option<Password>) {
        info!("on_device_unlocked({user:?}, password.is_some()={})", password.is_some());
        let _wp = wd::watch("DeviceLockState::on_device_unlocked");
        ENFORCEMENTS.set_device_locked(user, false);

        let mut skm = SUPER_KEY.write().unwrap();
        if let Some(password) = password {
            if let Err(e) = DB
                .with(|db| skm.unlock_user(&mut db.borrow_mut(), &LEGACY_IMPORTER, user, &password))
            {
                error!("Unlock with password failed for {user:?}: {e:?}");
            }
        } else if let Err(e) =
            DB.with(|db| skm.try_unlock_user_with_biometric(&mut db.borrow_mut(), user))
        {
            error!("try_unlock_user_with_biometric failed for {user:?}: {e:?}");
        }
    }

    fn on_device_locked(
        user: AndroidUserId,
        unlocking_sids: &[SecureUserId],
        weak_unlock_enabled: bool,
    ) {
        info!(
            "on_device_locked({user:?}, unlocking_sids={unlocking_sids:?}, weak_unlock_enabled={weak_unlock_enabled})"
        );
        let _wp = wd::watch("DeviceLockState::on_device_locked");
        ENFORCEMENTS.set_device_locked(user, true);
        let mut skm = SUPER_KEY.write().unwrap();
        DB.with(|db| {
            skm.lock_unlocked_device_required_keys(
                &mut db.borrow_mut(),
                user,
                unlocking_sids,
                weak_unlock_enabled,
            );
        });
    }

    fn on_user_storage_locked(user: AndroidUserId) {
        log::info!("on_user_storage_locked({user:?})");
        let _wp = wd::watch("DeviceLockState::on_user_storage_locked");

        // Delete super key in cache, if exists.
        SUPER_KEY.write().unwrap().forget_all_keys_for_user(user);
    }

    fn on_weak_unlock_methods_expired(user: AndroidUserId) {
        info!("on_weak_unlock_methods_expired({user:?})");
        let _wp = wd::watch("DeviceLockState::on_weak_unlock_methods_expired");
        SUPER_KEY
            .write()
            .unwrap()
            .wipe_unlocked_device_required_keys(user, WipeKeyOption::PlaintextOnly);
    }

    fn on_non_lskf_unlock_methods_expired(user: AndroidUserId) {
        info!("on_non_lskf_unlock_methods_expired({user:?})");
        let _wp = wd::watch("DeviceLockState::on_non_lskf_unlock_methods_expired");
        SUPER_KEY
            .write()
            .unwrap()
            .wipe_unlocked_device_required_keys(user, WipeKeyOption::PlaintextAndBiometric);
    }
}

impl AuthorizationManager {
    /// Create a new instance of Keystore Authorization service.
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreAuthorization>> {
        let mgr = if keystore2_flags::async_lock_state() {
            // Use an `AsyncTask` to handle notifications of authorization state, so Binder
            // invocations can complete swiftly.
            let lock_state_task = Arc::new(AsyncTask::new(std::time::Duration::from_secs(5)));
            ENFORCEMENTS.install_lock_state_task(lock_state_task.clone());

            Self::Asynchronous(lock_state_task)
        } else {
            Self::Synchronous
        };
        Ok(BnKeystoreAuthorization::new_binder(
            mgr,
            BinderFeatures { set_requesting_sid: true, ..BinderFeatures::default() },
        ))
    }

    /// Act on a lock state notification.
    fn update_lock_state(&self, op: LockStateNotification) {
        match self {
            Self::Asynchronous(async_task) => {
                // Send the notification to the async task to be acted on there.
                info!("add {op:?} to notification queue");
                async_task.queue_hi(|_shelf| {
                    info!("process {op:?} from notification queue");
                    DeviceLockState::update(op)
                });
            }
            Self::Synchronous => {
                // Act on the notification operation immediately.
                DeviceLockState::update(op)
            }
        }
    }

    fn add_auth_token(&self, auth_token: &HardwareAuthToken) {
        info!(
            "add_auth_token(challenge={}, userId={}, authId={}, authType={:#x}, timestamp={}ms)",
            auth_token.challenge,
            auth_token.userId,
            auth_token.authenticatorId,
            auth_token.authenticatorType.0,
            auth_token.timestamp.milliSeconds,
        );
        if auth_token.userId == 0 {
            error!("Auth token has zero GK SID, indicating an authenticator problem");
        }

        ENFORCEMENTS.add_auth_token(auth_token.clone());
    }

    fn get_auth_tokens_for_credstore(
        &self,
        challenge: Challenge,
        sid: SecureUserId,
        auth_token_max_age_millis: i64,
    ) -> Result<AuthorizationTokens> {
        // If the challenge is zero, return error
        if challenge.0 == 0 {
            return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT))
                .context(ks_err!("Challenge can not be zero."));
        }
        // Obtain the auth token and the timestamp token from the enforcement module.
        let (auth_token, ts_token) =
            ENFORCEMENTS.get_auth_tokens(challenge, sid, auth_token_max_age_millis)?;
        Ok(AuthorizationTokens { authToken: auth_token, timestampToken: ts_token })
    }

    fn get_last_auth_time(
        &self,
        sid: SecureUserId,
        auth_types: &[HardwareAuthenticatorType],
    ) -> Result<i64> {
        let mut max_time: i64 = -1;
        for auth_type in auth_types.iter() {
            if let Some(time) = ENFORCEMENTS.get_last_auth_time(sid, *auth_type) {
                if time.milliseconds() > max_time {
                    max_time = time.milliseconds();
                }
            }
        }

        if max_time >= 0 {
            Ok(max_time)
        } else {
            Err(Error::Rc(ResponseCode::NO_AUTH_TOKEN_FOUND))
                .context(ks_err!("No auth token found"))
        }
    }
}

impl Interface for AuthorizationManager {}

// The AIDL interface necessarily uses raw integer types for user ID / sid, so convert them to
// internal newtypes as soon as they arrive.
impl IKeystoreAuthorization for AuthorizationManager {
    fn addAuthToken(&self, auth_token: &HardwareAuthToken) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::addAuthToken");
        check_keystore_permission(KeystorePerm::AddAuth)
            .context(ks_err!("caller missing AddAuth permissions"))
            .map_err(into_logged_binder)?;

        self.add_auth_token(auth_token);
        Ok(())
    }

    fn onDeviceUnlocked(&self, user_id: i32, password: Option<&[u8]>) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onDeviceUnlocked");
        check_keystore_permission(KeystorePerm::Unlock)
            .context(ks_err!("caller missing Unlock permissions"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let password = match password {
            None => None,
            Some(slice) => Some(
                ZVec::try_from(slice)
                    .context("failed to create ZVec!")
                    .map_err(into_logged_binder)?,
            ),
        };
        let op = LockStateNotification { user, state: LockState::DeviceUnlocked { password } };
        self.update_lock_state(op);
        Ok(())
    }

    fn onDeviceLocked(
        &self,
        user_id: i32,
        unlocking_sids: &[i64],
        weak_unlock_enabled: bool,
    ) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onDeviceLocked");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let unlocking_sids: Vec<_> = unlocking_sids.iter().map(|sid| {
            if *sid == 0 {
                error!("Biometric-unlocking SIDs includes a zero SID, indicating a biometric framework problem");
            }
            SecureUserId(*sid)
        }).collect();
        let op = LockStateNotification {
            user,
            state: LockState::DeviceLocked { unlocking_sids, weak_unlock_enabled },
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onUserStorageLocked(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreMaintenance::onUserStorageLocked");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification { user, state: LockState::UserStorageLocked };
        self.update_lock_state(op);
        Ok(())
    }

    fn onWeakUnlockMethodsExpired(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onWeakUnlockMethodsExpired");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification { user, state: LockState::WeakUnlockMethodsExpired };
        self.update_lock_state(op);
        Ok(())
    }

    fn onNonLskfUnlockMethodsExpired(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onNonLskfUnlockMethodsExpired");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification { user, state: LockState::NonLskfUnlockMethodsExpired };
        self.update_lock_state(op);
        Ok(())
    }

    fn getAuthTokensForCredStore(
        &self,
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    ) -> binder::Result<AuthorizationTokens> {
        let _wp = wd::watch("IKeystoreAuthorization::getAuthTokensForCredStore");
        check_keystore_permission(KeystorePerm::GetAuthToken)
            .context(ks_err!("caller missing GetAuthToken permission"))
            .map_err(into_logged_binder)?;

        let sid = SecureUserId(secure_user_id);
        let challenge = Challenge(challenge);
        self.get_auth_tokens_for_credstore(challenge, sid, auth_token_max_age_millis)
            .map_err(into_logged_binder)
    }

    fn getLastAuthTime(
        &self,
        secure_user_id: i64,
        auth_types: &[HardwareAuthenticatorType],
    ) -> binder::Result<i64> {
        let _wp = wd::watch("IKeystoreAuthorization::getLastAuthTime");
        check_keystore_permission(KeystorePerm::GetLastAuthTime)
            .context(ks_err!("caller missing GetLastAuthTime permission"))
            .map_err(into_logged_binder)?;

        let sid = SecureUserId(secure_user_id);
        self.get_last_auth_time(sid, auth_types).map_err(into_logged_binder)
    }
}
