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

//! Utilities for generating wire types for HAL operations.

/// Declare a collection of related enums for a code and a pair of types.
///
/// An invocation like:
/// ```ignore
/// declare_req_rsp_enums! { GatekeeperOperation  => (PerformOpReq, PerformOpRsp) {
///     Enroll = 0x11 => (EnrollRequest, EnrollResponse),
///     Verify = 0x12 => (VerifyRequest, VerifyResponse),
/// } }
/// ```
/// will emit three `enum` types all of whose variant names are the same (taken from the leftmost
/// column), but whose contents are:
///
/// - the numeric values (second column)
///   ```ignore
///   #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
///   enum GatekeeperOperation {
///       Enroll = 0x11,
///       Verify = 0x12,
///   }
///   ```
///
/// - the types from the third column:
///   ```ignore
///   enum PerformOpReq {
///       Enroll(EnrollRequest),
///       Verify(VerifyRequest),
///   }
///   ```
///
/// - the types from the fourth column:
///   ```ignore
///   #[derive(Debug)]
///   enum PerformOpRsp {
///       Enroll(EnrollResponse),
///       Verify(VerifyResponse),
///   }
//   ```
///
/// Each of these enum types will also get an implementation of [`AsCborValue`]
#[macro_export]
macro_rules! declare_req_rsp_enums {
    {
        $cenum:ident => ($reqenum:ident, $rspenum:ident) {
            $( $cname:ident = $cvalue:expr => ($reqtyp:ty, $rsptyp:ty) , )*
        }
    } => {
        /// Message codes
        #[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, $crate::N)]
        pub enum $cenum {
            $( $cname = $cvalue, )*
        }

        impl $crate::AsCborValue for $cenum {
            /// Create an instance of the enum from a [`Value`], checking that the
            /// value is valid.
            fn from_cbor_value(value: $crate::Value) ->
                Result<Self, $crate::CborError> {
                use core::convert::TryInto;
                // First get the int value as an `i32`.
                let v: i32 = match value {
                    $crate::Value::Integer(i) => i.try_into().map_err(|_| {
                        $crate::CborError::InvalidValue
                    })?,
                    v => return $crate::cbor_type_error(&v, &"int"),
                };
                // Now check it is one of the defined enum values.
                Self::n(v).ok_or($crate::CborError::NonEnumValue(v))
            }
            /// Convert the enum value to a [`Value`].
            fn to_cbor_value(self) -> Result<$crate::Value, $crate::CborError> {
                Ok($crate::Value::Integer((self as i64).into()))
            }
        }

        /// All possible request message types.
        pub enum $reqenum {
            $( $cname($reqtyp), )*
        }

        impl $crate::operations::Code<$cenum> for $reqenum {
            /// Return the message code value corresponding to a request variant.
            fn code(&self) -> $cenum {
                match self {
                    $( Self::$cname(_) => $cenum::$cname, )*
                }
            }
        }

        /// All possible response message types.
        pub enum $rspenum {
            $( $cname($rsptyp), )*
        }

        impl $crate::AsCborValue for $reqenum {
            fn from_cbor_value(value: $crate::Value) -> Result<Self, $crate::CborError> {
                let mut a = match value {
                    $crate::Value::Array(a) => a,
                    _ => return $crate::cbor_type_error(&value, "arr"),
                };
                if a.len() != 2 {
                    return Err($crate::CborError::UnexpectedItem("arr", "arr len 2"));
                }
                let ret_val = a.remove(1);
                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
                match ret_type {
                    $( $cenum::$cname => Ok(Self::$cname(<$reqtyp>::from_cbor_value(ret_val)?)), )*
                }
            }
            fn to_cbor_value(self) -> Result<$crate::Value, $crate::CborError> {
                Ok($crate::Value::Array(match self {
                    $( Self::$cname(val) => {
                        $crate::vec![
                            $cenum::$cname.to_cbor_value()?,
                            val.to_cbor_value()?
                        ]
                    }, )*
                }))
            }
        }

        impl $crate::AsCborValue for $rspenum {
            fn from_cbor_value(value: $crate::Value) -> Result<Self, $crate::CborError> {
                let mut a = match value {
                    $crate::Value::Array(a) => a,
                    _ => return $crate::cbor_type_error(&value, "arr"),
                };
                if a.len() != 2 {
                    return Err($crate::CborError::UnexpectedItem("arr", "arr len 2"));
                }
                let ret_val = a.remove(1);
                let ret_type = <$cenum>::from_cbor_value(a.remove(0))?;
                match ret_type {
                    $( $cenum::$cname => Ok(Self::$cname(<$rsptyp>::from_cbor_value(ret_val)?)), )*
                }
            }
            fn to_cbor_value(self) -> Result<$crate::Value, $crate::CborError> {
                Ok($crate::Value::Array(match self {
                    $( Self::$cname(val) => {
                        $crate::vec![
                            $cenum::$cname.to_cbor_value()?,
                            val.to_cbor_value()?
                        ]
                    }, )*
                }))
            }
        }

        $(
            impl $crate::operations::Code<$cenum> for $reqtyp {
                fn code(&self) -> $cenum {
                    $cenum::$cname
                }
            }
        )*

        $(
            impl $crate::operations::Code<$cenum> for $rsptyp {
                fn code(&self) -> $cenum {
                    $cenum::$cname
                }
            }
        )*
    };
}

/// Trait that associates self with an enum value of the specified type.
///
/// For example, an `enum WhichMsg { Hello, Goodbye }` could be used to distinguish
/// between `struct HelloMsg` and `struct GoodbyeMsg` instances, in which case the
/// latter types would both implement `Code<WhichMsg>` and return `WhichMsg::Hello`
/// and `WhichMsg::Goodbye` respectively from the `code()` method.
pub trait Code<T> {
    /// Return the associated enum value.
    fn code(&self) -> T;
}
