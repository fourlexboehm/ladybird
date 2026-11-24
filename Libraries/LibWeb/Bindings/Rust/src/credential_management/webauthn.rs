/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use core::ffi::c_void;

use ak::{Base64Alphabet, Span, Utf16String, encode_base64};
use libjs_rust::api::{ArrayBuffer, ArrayBufferShared, EmbedderClass, EmbedderValue, Gc, Realm, Trace, Vm};

use super::authenticator_assertion_response::AuthenticatorAssertionResponse;
use super::authenticator_attestation_response::AuthenticatorAttestationResponse;
use super::authenticator_response::AnyAuthenticatorResponse;
use super::credential::CredentialMediationRequirement;
use super::public_key_credential::{
    AuthenticationExtensionsClientOutputs, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions,
};
use crate::bindings::conversions::{BufferSource, ToJs, UsvString};
use crate::bindings::global_object::window_from_global_object;
use crate::bindings::interface::{Ref, allocate, with_temporary_execution_context};
use crate::bindings::promise::{WebIdlPromise, reject_promise, reject_promise_with_exception, resolve_promise};
use crate::bindings::{CallContext, Exception, WebIdlResult};
use crate::dom::abort_signal::AbortSignal;

/// The values of Web::WebAuthn::UserVerificationRequirement.
#[repr(u8)]
#[derive(Clone, Copy)]
enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

/// The values of Web::WebAuthn::ResidentKeyRequirement.
#[repr(u8)]
#[derive(Clone, Copy)]
enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

/// The values of Web::WebAuthn::Error.
const ERROR_NOT_SUPPORTED: u8 = 1;
const ERROR_INVALID_STATE: u8 = 2;
const ERROR_SECURITY: u8 = 3;
const ERROR_TYPE: u8 = 4;

#[repr(C)]
struct CreationOptionsAbi<'a> {
    rp_name: Span<'a, u8>,
    user_id: Span<'a, u8>,
    user_name: Span<'a, u8>,
    user_display_name: Span<'a, u8>,
    algorithms: Span<'a, i32>,
    resident_key: ResidentKeyRequirement,
}

#[repr(C)]
struct RequestAbi<'a> {
    challenge: Span<'a, u8>,
    has_rp_id: bool,
    rp_id: Span<'a, u8>,
    credentials: Span<'a, Span<'a, u8>>,
    allows_only_unsupported_credentials: bool,
    user_verification: UserVerificationRequirement,
    has_timeout: bool,
    timeout: u32,
    creation: Option<&'a CreationOptionsAbi<'a>>,
}

#[repr(C)]
struct ResponseAbi<'a> {
    client_data_json: Span<'a, u8>,
    raw_id: Span<'a, u8>,
    authenticator_data: Span<'a, u8>,
    attestation_object: Span<'a, u8>,
    public_key: Span<'a, u8>,
    signature: Span<'a, u8>,
    has_user_handle: bool,
    user_handle: Span<'a, u8>,
}

unsafe extern "C" {
    fn web_credentials_request_public_key(
        window: *mut c_void,
        request: *mut c_void,
        signal: *mut c_void,
        options: *const RequestAbi<'_>,
        steps: unsafe extern "C" fn(*mut c_void, *mut c_void, u8, Option<&ResponseAbi<'_>>),
    );
}

#[derive(Trace)]
#[gc(crate = libjs_rust)]
struct Request {
    realm: Gc<Realm>,
    promise: WebIdlPromise,
    signal: Option<Ref<AbortSignal>>,
    creating: bool,
}

static REQUEST_CLASS: EmbedderClass<Request> = EmbedderClass::new("WebAuthnRequest");

impl EmbedderValue for Request {
    const CLASS: &'static EmbedderClass<Self> = &REQUEST_CLASS;
}

fn bytes(buffer: &BufferSource) -> Vec<u8> {
    // SAFETY: Copying bytes neither runs script nor allocates a GC cell.
    unsafe { buffer.with_bytes(<[u8]>::to_vec) }
}

fn string(value: &Utf16String) -> String {
    UsvString::from_utf16_string(value).to_utf8()
}

// https://w3c.github.io/webauthn/#enum-credentialType
fn public_key_credential_ids(descriptors: &[PublicKeyCredentialDescriptor]) -> Vec<Vec<u8>> {
    // NB: An authenticator ignores descriptors of credential types it does not support.
    descriptors
        .iter()
        .filter(|descriptor| string(&descriptor.r#type) == "public-key")
        .map(|descriptor| bytes(&descriptor.id))
        .collect()
}

// https://w3c.github.io/webauthn/#enumdef-userverificationrequirement
fn user_verification(value: &Utf16String) -> UserVerificationRequirement {
    // NB: An unknown value is treated as the default, "preferred".
    match string(value).as_str() {
        "required" => UserVerificationRequirement::Required,
        "discouraged" => UserVerificationRequirement::Discouraged,
        _ => UserVerificationRequirement::Preferred,
    }
}

fn reject(cx: &CallContext, promise: WebIdlPromise, exception: Exception) -> WebIdlResult<()> {
    reject_promise_with_exception(cx.vm(), promise, exception);
    Ok(())
}

// https://w3c.github.io/webauthn/#sctn-createCredential
pub(super) fn create(
    cx: &CallContext,
    promise: WebIdlPromise,
    options: PublicKeyCredentialCreationOptions<'_>,
    signal: Option<Ref<AbortSignal>>,
    mediation: CredentialMediationRequirement,
) -> WebIdlResult<()> {
    // NB: The browser process checks the origin and RP ID, corrects the timeout, and collects the client data.

    // 5. If the length of pkOptions.user.id is not between 1 and 64 bytes (inclusive) then throw a TypeError.
    let user_id = bytes(&options.user.id);
    if !(1..=64).contains(&user_id.len()) {
        return reject(
            cx,
            promise,
            Exception::TypeError(Utf16String::from_ascii(b"user.id must be between 1 and 64 bytes.")),
        );
    }

    // 9. Let credTypesAndPubKeyAlgs be a new list whose items are pairs of PublicKeyCredentialType and a
    //    COSEAlgorithmIdentifier.
    // 10. If pkOptions.pubKeyCredParams’s size
    let algorithms: Vec<i32> = if options.pub_key_cred_params.is_empty() {
        // is zero
        //     Append the following pairs of PublicKeyCredentialType and COSEAlgorithmIdentifier values to
        //     credTypesAndPubKeyAlgs: public-key and -7 ("ES256"), public-key and -257 ("RS256").
        vec![-7, -257]
    } else {
        // is non-zero
        //     For each current of pkOptions.pubKeyCredParams:
        //         1. If current.type does not contain a PublicKeyCredentialType supported by this implementation,
        //            then continue.
        //         2. Let alg be current.alg.
        //         3. Append the pair of current.type and alg to credTypesAndPubKeyAlgs.
        options
            .pub_key_cred_params
            .iter()
            .filter(|parameters| string(&parameters.r#type) == "public-key")
            .map(|parameters| parameters.alg)
            .collect()
    };
    //     If credTypesAndPubKeyAlgs is empty, throw a "NotSupportedError" DOMException.
    if algorithms.is_empty() {
        return reject(
            cx,
            promise,
            Exception::Dom(
                "NotSupportedError",
                Utf16String::from_ascii(b"No supported public key credential type was requested."),
            ),
        );
    }

    let selection = options.authenticator_selection.as_ref();

    // 22. While lifetimeTimer has not expired, ...
    //     If an authenticator becomes available on this client device,
    //         2. If pkOptions.authenticatorSelection is present:
    //             1. If pkOptions.authenticatorSelection.authenticatorAttachment is present and its value is not
    //                equal to authenticator’s authenticator attachment modality, continue.
    // NB: Only cross-platform authenticators are supported, so none ever becomes available for "platform".
    if selection
        .and_then(|selection| selection.authenticator_attachment.as_ref())
        .is_some_and(|attachment| string(attachment) == "platform")
    {
        return reject(
            cx,
            promise,
            Exception::Dom(
                "NotAllowedError",
                Utf16String::from_ascii(b"No platform authenticator is available."),
            ),
        );
    }

    // NB: An unknown residentKey value is treated as not present, in which case requireResidentKey applies.
    let resident_key = match selection
        .and_then(|selection| selection.resident_key.as_ref().map(string))
        .as_deref()
    {
        Some("required") => ResidentKeyRequirement::Required,
        Some("preferred") => ResidentKeyRequirement::Preferred,
        Some("discouraged") => ResidentKeyRequirement::Discouraged,
        _ if selection.is_some_and(|selection| selection.require_resident_key) => ResidentKeyRequirement::Required,
        _ => ResidentKeyRequirement::Discouraged,
    };

    let challenge = bytes(&options.challenge);
    let rp_id = options.rp.id.as_ref().map(string);
    let rp_name = string(&options.rp.parent.name);
    let user_name = string(&options.user.parent.name);
    let user_display_name = string(&options.user.display_name);
    let credential_ids = public_key_credential_ids(&options.exclude_credentials.values());
    let credentials: Vec<_> = credential_ids.iter().map(|id| Span::new(id)).collect();
    let creation = CreationOptionsAbi {
        rp_name: Span::new(rp_name.as_bytes()),
        user_id: Span::new(&user_id),
        user_name: Span::new(user_name.as_bytes()),
        user_display_name: Span::new(user_display_name.as_bytes()),
        algorithms: Span::new(&algorithms),
        resident_key,
    };
    let request = RequestAbi {
        challenge: Span::new(&challenge),
        has_rp_id: rp_id.is_some(),
        rp_id: Span::new(rp_id.as_deref().unwrap_or_default().as_bytes()),
        credentials: Span::new(&credentials),
        allows_only_unsupported_credentials: false,
        user_verification: selection.map_or(UserVerificationRequirement::Preferred, |selection| {
            user_verification(&selection.user_verification)
        }),
        has_timeout: options.timeout.is_some(),
        timeout: options.timeout.unwrap_or_default(),
        creation: Some(&creation),
    };
    start(cx, promise, &request, signal, mediation, true)
}

// https://w3c.github.io/webauthn/#sctn-discover-from-external-source
pub(super) fn get(
    cx: &CallContext,
    promise: WebIdlPromise,
    options: PublicKeyCredentialRequestOptions<'_>,
    signal: Option<Ref<AbortSignal>>,
    mediation: CredentialMediationRequirement,
) -> WebIdlResult<()> {
    // NB: The browser process checks the origin and RP ID, corrects the timeout, and collects the client data.
    let challenge = bytes(&options.challenge);
    let rp_id = options.rp_id.as_ref().map(string);
    let allow_credentials = options.allow_credentials.values();
    let credential_ids = public_key_credential_ids(&allow_credentials);
    let credentials: Vec<_> = credential_ids.iter().map(|id| Span::new(id)).collect();
    let request = RequestAbi {
        challenge: Span::new(&challenge),
        has_rp_id: rp_id.is_some(),
        rp_id: Span::new(rp_id.as_deref().unwrap_or_default().as_bytes()),
        credentials: Span::new(&credentials),
        allows_only_unsupported_credentials: !allow_credentials.is_empty() && credential_ids.is_empty(),
        user_verification: user_verification(&options.user_verification),
        has_timeout: options.timeout.is_some(),
        timeout: options.timeout.unwrap_or_default(),
        creation: None,
    };
    start(cx, promise, &request, signal, mediation, false)
}

fn start(
    cx: &CallContext,
    promise: WebIdlPromise,
    options: &RequestAbi<'_>,
    signal: Option<Ref<AbortSignal>>,
    mediation: CredentialMediationRequirement,
    creating: bool,
) -> WebIdlResult<()> {
    // [[Create]] step 16 and [[DiscoverFromExternalSource]] step 13: If options.signal is present and aborted, throw
    // the options.signal’s abort reason.
    if let Some(signal) = signal
        && signal.aborted()
    {
        reject_promise(cx.vm(), promise, signal.reason());
        return Ok(());
    }
    if matches!(
        mediation,
        CredentialMediationRequirement::Conditional | CredentialMediationRequirement::Silent
    ) {
        return reject(
            cx,
            promise,
            Exception::Dom(
                "NotSupportedError",
                Utf16String::from_ascii(b"This WebAuthn mediation mode is not supported."),
            ),
        );
    }
    let window =
        window_from_global_object(cx.realm().global_object()).expect("CredentialsContainer is exposed on Window");
    let request = REQUEST_CLASS.allocate(cx.vm(), |_| Request {
        realm: cx.realm(),
        promise,
        signal,
        creating,
    });
    // SAFETY: C++ copies the options and roots the request until it calls completed.
    unsafe {
        web_credentials_request_public_key(
            window.as_ptr(),
            request.as_ptr().cast(),
            signal.map_or(core::ptr::null_mut(), |signal| signal.as_ptr().cast()),
            options,
            completed,
        );
    }
    Ok(())
}

fn exception(error: u8) -> Exception {
    let message = Utf16String::from_ascii(b"The WebAuthn operation could not be completed.");
    match error {
        ERROR_NOT_SUPPORTED => Exception::Dom("NotSupportedError", message),
        ERROR_INVALID_STATE => Exception::Dom("InvalidStateError", message),
        ERROR_SECURITY => Exception::Dom("SecurityError", message),
        ERROR_TYPE => Exception::TypeError(message),
        _ => Exception::Dom("NotAllowedError", message),
    }
}

unsafe extern "C" fn completed(vm: *mut c_void, request: *mut c_void, error: u8, response: Option<&ResponseAbi<'_>>) {
    // SAFETY: C++ roots the request and passes a live VM for this callback.
    let vm = unsafe { &*vm.cast::<Vm>() };
    let request = unsafe { REQUEST_CLASS.downcast(core::ptr::NonNull::new(request).unwrap()) }.unwrap();
    with_temporary_execution_context(request.realm, || {
        if let Some(signal) = request.signal
            && signal.aborted()
        {
            reject_promise(vm, request.promise, signal.reason());
            return;
        }
        let Some(response) = response else {
            reject_promise_with_exception(vm, request.promise, exception(error));
            return;
        };
        let buffer = |bytes: Span<'_, u8>| {
            ArrayBuffer::create_from_bytes(vm, request.realm, bytes.as_slice(), ArrayBufferShared::No)
        };
        let client_data = buffer(response.client_data_json);
        let authenticator_response = if request.creating {
            let attestation_object = buffer(response.attestation_object);
            AnyAuthenticatorResponse::AuthenticatorAttestationResponse(allocate(vm, |_| {
                AuthenticatorAttestationResponse::new(
                    client_data,
                    attestation_object,
                    response.authenticator_data.as_slice().to_vec(),
                    response.public_key.as_slice().to_vec(),
                )
            }))
        } else {
            let authenticator_data = buffer(response.authenticator_data);
            let signature = buffer(response.signature);
            let user_handle = response.has_user_handle.then(|| buffer(response.user_handle));
            AnyAuthenticatorResponse::AuthenticatorAssertionResponse(allocate(vm, |_| {
                AuthenticatorAssertionResponse::new(client_data, authenticator_data, signature, user_handle)
            }))
        };
        let id = encode_base64(response.raw_id.as_slice(), Base64Alphabet::Base64Url, true);
        let raw_id = buffer(response.raw_id);
        let credential = allocate(vm, |_| {
            PublicKeyCredential::new(
                UsvString::from_utf16_string(&id),
                raw_id,
                authenticator_response,
                Some(Utf16String::from_ascii(b"cross-platform")),
                AuthenticationExtensionsClientOutputs {},
            )
        });
        match credential.to_js(&CallContext::new(vm, request.realm)) {
            Ok(value) => resolve_promise(vm, request.promise, value),
            Err(error) => reject_promise_with_exception(vm, request.promise, Exception::from(error)),
        }
    });
}
