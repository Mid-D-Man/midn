// crates/midn-proto/src/nas5gs/messages.rs
//! 5GS NAS message type definitions — 3GPP TS 24.501.
//!
//! Structural sibling of `nas::messages` (NAS-EPS/TS 24.301) — same
//! "enum discriminant + per-message IE struct" shape, same critical-path-
//! only field selection (not every optional IE 3GPP allows). Differences
//! from the NAS-EPS set this mirrors:
//!
//!   - `IdentityRequest`/`IdentityResponse` are new — 5G's SUCI concealment
//!     step has no direct NAS-EPS equivalent in this position. See `Suci`.
//!   - `AuthenticationResponse.res_star` is 16 bytes, not 8. 5G-AKA's RES*
//!     is a KDF-derived 128-bit value (TS 33.501 Annex A.4), wider than
//!     legacy Milenage RES's 64 bits. Moderate-high confidence on the
//!     width; the actual RES* derivation is NOT implemented anywhere yet
//!     (needs TS 33.501 Annex A text — same never-fabricate policy as
//!     everywhere else in this codebase).
//!   - `RegistrationRequest`/`Accept`/`Reject`/`Complete` replace
//!     `AttachRequest`/`Accept`/`Complete` (no direct "attach reject" ever
//!     existed on the NAS-EPS side of this codebase, so `RegistrationReject`
//!     is new coverage, not a rename).
//!   - `DeregistrationRequest`/`Accept` replace `DetachRequest`/`Accept`,
//!     same shape.
//!
//! No wire codec yet — that's `nas5gs::codec`, next increment, mirroring
//! `nas::codec`'s byte-oriented TLV format (5G NAS uses the same IE-coding
//! conventions as 4G NAS, TS 24.007 §11 — not ASN.1 PER like NGAP/S1AP).

use bytes::Bytes;

/// Top-level 5GS NAS message discriminant.
#[derive(Debug, Clone, PartialEq)]
pub enum Nas5gsMessage {
    // ── Registration ─────────────────────────────────────────────────────
    /// UE → AMF: initiate registration.
    RegistrationRequest(RegistrationRequest),
    /// AMF → UE: request identity (drives SUCI submission).
    IdentityRequest { identity_type: u8 },
    /// UE → AMF: submit identity (SUCI, GUTI, or PEI depending on request).
    IdentityResponse(IdentityResponse),
    /// AMF → UE: send RAND + AUTN challenge (5G-AKA).
    AuthenticationRequest(AuthenticationRequest),
    /// UE → AMF: send RES* (response to challenge).
    AuthenticationResponse(AuthenticationResponse),
    /// AMF → UE: authentication failed.
    AuthenticationReject,
    /// AMF → UE: activate NAS security (cipher + integrity algorithm).
    SecurityModeCommand(SecurityModeCommand),
    /// UE → AMF: NAS security activated, send NAS MAC.
    SecurityModeComplete,
    /// AMF → UE: registration accepted, assign 5G-GUTI.
    RegistrationAccept(RegistrationAccept),
    /// UE → AMF: registration complete.
    RegistrationComplete,
    /// AMF → UE: registration rejected.
    RegistrationReject { cause: u8 },

    // ── Deregistration ───────────────────────────────────────────────────
    /// UE → AMF / AMF → UE: deregister from network.
    DeregistrationRequest { switch_off: bool },
    /// AMF → UE: deregistration accepted.
    DeregistrationAccept,
}

/// Registration Request IEs — 3GPP TS 24.501 Section 8.2.6.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationRequest {
    /// 5GS registration type: 1=initial, 2=mobility update, 3=periodic update,
    /// 4=emergency (3 bits, TS 24.501 Table 9.11.3.7.1).
    pub registration_type: u8,
    /// ngKSI — Key Set Identifier in AMF (KAMF), successor to LTE's KSI_ASME.
    pub ng_ksi:             u8,
    /// 5G-GUTI, if the UE has one (mobility/periodic update case).
    pub guti:                Option<[u8; 11]>,
    /// UE security capability (5G-EA/5G-IA support bitmap).
    pub ue_security_cap:     u16,
}

/// Identity Response IEs — 3GPP TS 24.501 Section 8.2.10.
///
/// Carries whatever identity type the preceding `IdentityRequest` asked
/// for. `Suci` is the field this codebase actually cares about (SUCI
/// concealment is the point of modeling this message at all); `guti`/`pei`
/// are included for shape completeness.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityResponse {
    pub suci: Option<Suci>,
    pub guti: Option<[u8; 11]>,
    pub pei:  Option<Bytes>,
}

/// Subscription Concealed Identifier — 3GPP TS 23.003 Section 2.2A / TS 33.501 Annex C.
///
/// Models the **null protection scheme** only (`protection_scheme_id == 0`):
/// the SUPI's MSIN travels in the clear inside the SUCI container, just
/// wrapped in SUCI framing rather than sent as a bare IMSI. This is a real,
/// spec-legitimate fallback scheme (used for testing and for USIMs without
/// the home network's public key provisioned) — not a shortcut invented for
/// this codebase.
///
/// Profile A/B (the actual ECIES-based concealment schemes UEs use over the
/// air in production) are NOT modeled — those need real elliptic-curve
/// crypto (X25519/secp256r1 per TS 33.501 Annex C.3) and are exactly the
/// kind of thing this project's policy is to stub with a spec reference
/// rather than approximate from memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suci {
    pub mcc:               [u8; 3],
    pub mnc:                [u8; 3],
    pub routing_indicator: u16,
    /// 0 = null scheme (the only one this codec speaks). Kept as a field
    /// (not hardcoded) so `decode` can reject non-null schemes explicitly
    /// rather than silently misinterpreting protected ciphertext as a
    /// cleartext MSIN.
    pub protection_scheme: u8,
    pub home_network_pki:  u8,
    /// MSIN — in the clear under the null scheme.
    pub msin:               [u8; 5],
}

/// Authentication Request IEs — 3GPP TS 24.501 Section 8.2.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationRequest {
    pub ng_ksi: u8,
    pub rand:   [u8; 16],
    pub autn:   [u8; 16],
}

/// Authentication Response IEs — 3GPP TS 24.501 Section 8.2.2.
///
/// `res_star` is 16 bytes — see module doc for why this differs from
/// NAS-EPS's 8-byte RES.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResponse {
    pub res_star: [u8; 16],
}

/// Security Mode Command IEs — 3GPP TS 24.501 Section 8.2.25.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityModeCommand {
    /// Selected 5G NAS ciphering algorithm (0=5G-EA0, 2=128-5G-EA2 — same
    /// algorithm as 128-EEA2, TS 33.501 reuses the TS 33.401 cipher set).
    pub nas_cipher_alg:      u8,
    /// Selected 5G NAS integrity algorithm (0=5G-IA0, 2=128-5G-IA2 — same
    /// algorithm as 128-EIA2).
    pub nas_integrity_alg:   u8,
    /// Replayed UE security capability (for bidding-down protection).
    pub replayed_ue_sec_cap: u16,
}

/// Registration Accept IEs — 3GPP TS 24.501 Section 8.2.7.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationAccept {
    /// 5GS registration result (3 bits): 1=3GPP access, 2=non-3GPP, 3=both.
    pub registration_result: u8,
    /// Assigned 5G-GUTI.
    pub guti:                 [u8; 11],
    /// 5GS Tracking Area Identity list — PLMN(3)+TAC(3) per entry, matching
    /// `ngap::NgapInitialUeMessage.tai`'s width (see that module's
    /// confidence note on the 3-octet 5G TAC).
    pub tai_list:              Vec<[u8; 6]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_request_fields() {
        let req = AuthenticationRequest {
            ng_ksi: 0x03,
            rand: [0x11; 16],
            autn: [0x22; 16],
        };
        assert_eq!(req.rand[0], 0x11);
        assert_eq!(req.autn[0], 0x22);
    }

    #[test]
    fn suci_null_scheme_shape() {
        let suci = Suci {
            mcc: [2, 3, 4],
            mnc: [1, 5, 0xF], // 2-digit MNC padded with 0xF filler digit
            routing_indicator: 0,
            protection_scheme: 0,
            home_network_pki: 0,
            msin: [0x12, 0x34, 0x56, 0x78, 0x90],
        };
        assert_eq!(suci.protection_scheme, 0, "only the null scheme is modeled");
        assert_eq!(suci.msin.len(), 5);
    }

    #[test]
    fn authentication_response_res_star_is_16_bytes() {
        let res = AuthenticationResponse { res_star: [0xAA; 16] };
        assert_eq!(res.res_star.len(), 16, "5G-AKA RES* is wider than legacy 8-byte RES");
    }
}
