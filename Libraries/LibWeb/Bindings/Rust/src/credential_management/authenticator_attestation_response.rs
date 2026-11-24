/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! AuthenticatorAttestationResponse, https://w3c.github.io/webauthn/#authenticatorattestationresponse

use ak::Utf16String;
use libjs_rust::api::{ArrayBuffer, ArrayBufferShared, Gc, Trace};

use super::authenticator_response::AuthenticatorResponse;
use crate::bindings::interface::{Inherits, Wrappable};
use crate::bindings::{CallContext, WebIdlResult};

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct AuthenticatorAttestationResponse {
    response: AuthenticatorResponse,
    attestation_object: Gc<ArrayBuffer>,
    #[gc(untraced)]
    transports: Vec<Utf16String>,
    #[gc(untraced)]
    authenticator_data: Vec<u8>,
    #[gc(untraced)]
    public_key: Option<Vec<u8>>,
    public_key_algorithm: i32,
}

impl Wrappable for AuthenticatorAttestationResponse {}

impl Inherits<AuthenticatorResponse> for AuthenticatorAttestationResponse {
    fn parent(&self) -> &AuthenticatorResponse {
        &self.response
    }
}

impl AuthenticatorAttestationResponse {
    pub(crate) fn new(
        client_data_json: Gc<ArrayBuffer>,
        attestation_object: Gc<ArrayBuffer>,
        authenticator_data: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            response: AuthenticatorResponse::new(client_data_json),
            attestation_object,
            transports: vec![Utf16String::from_ascii(b"usb")],
            authenticator_data,
            public_key: Some(public_key),
            public_key_algorithm: -7,
        }
    }

    pub(crate) fn attestation_object(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.attestation_object)
    }

    pub(crate) fn get_transports(&self, _: &mut CallContext) -> WebIdlResult<Vec<Utf16String>> {
        Ok(self.transports.clone())
    }

    pub(crate) fn get_authenticator_data(&self, cx: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(ArrayBuffer::create_from_bytes(
            cx.vm(),
            cx.realm(),
            &self.authenticator_data,
            ArrayBufferShared::No,
        ))
    }

    pub(crate) fn get_public_key(&self, cx: &mut CallContext) -> WebIdlResult<Option<Gc<ArrayBuffer>>> {
        Ok(self
            .public_key
            .as_ref()
            .map(|public_key| ArrayBuffer::create_from_bytes(cx.vm(), cx.realm(), public_key, ArrayBufferShared::No)))
    }

    pub(crate) fn get_public_key_algorithm(&self, _: &mut CallContext) -> WebIdlResult<i32> {
        Ok(self.public_key_algorithm)
    }
}
