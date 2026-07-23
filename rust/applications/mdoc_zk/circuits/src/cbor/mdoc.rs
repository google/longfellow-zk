use core_algebra::Nat;

use crate::{
    cbor::{
        append_bytes_len, append_text_len,
        constants::{
            K_COSE1_PREFIX, K_COSE1_PREFIX_LEN, K_COSE_SIGN1_SIGNING_HEADER,
            K_DEVICE_AUTHENTICATION_HEADER, K_TAG24,
        },
        parse::{
            find_device_key_coordinate, find_element_by_key, find_key_in_map, get_array, get_bytes,
            CborElement, CborParser, CborValue,
        },
    },
    mso_attribute::concrete::FieldLocator,
};

#[derive(Clone, Debug)]
pub struct ParsedAttr {
    pub name: Vec<u8>,
    pub cbor_value: Vec<u8>,
    pub cbor_issuer_signed_item: Vec<u8>,
    pub mso_digest_offset_in_preimage: usize,
    pub field_locator: FieldLocator,
}

#[derive(Clone, Debug)]
pub struct DeviceKeyInfo {
    pub key_type: i64,
    pub crv: i64,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ParsedMdoc<N> {
    pub issuer_sig_digest: N,
    pub issuer_sig_r: N,
    pub issuer_sig_s: N,
    pub device_pk: (N, N),
    pub device_sig_digest: N,
    pub device_sig_r: N,
    pub device_sig_s: N,
    pub doc_type: String,
    pub doc_type_offset_in_mso: usize,
    pub valid_from_offset_in_mso: usize,
    pub valid_until_offset_in_mso: usize,
    pub device_key_info_offset_in_mso: usize,
    pub value_digests_offset_in_mso: usize,
    pub attrs: Vec<ParsedAttr>,
    pub cbor_mso: Vec<u8>,
}

impl<N> ParsedMdoc<N> {
    pub fn all_attr_ids(&self) -> Vec<&[u8]> {
        self.attrs.iter().map(|a| a.name.as_slice()).collect()
    }

    pub fn get_attribute(&self, name: &[u8]) -> Option<&ParsedAttr> {
        self.attrs.iter().find(|a| a.name == name)
    }
}

#[must_use]
pub fn parse_mdoc<N: Nat<4>>(mdoc: &[u8], transcript: &[u8], doc_type: &str) -> ParsedMdoc<N> {
    use sha2::{Digest, Sha256};

    let mut root_parser = CborParser::new(mdoc);
    let root = root_parser.parse_val().expect("Failed to parse root mdoc");

    let docs_el = find_element_by_key(&root, "documents").expect("documents missing");
    let docs_arr = get_array(&docs_el).expect("documents is not an array");
    let doc0 = docs_arr.first().expect("document 0 missing");

    // Traverse issuerSigned -> issuerAuth to find MSO and issuer signature
    let issuer_signed = find_element_by_key(doc0, "issuerSigned").expect("issuerSigned missing");
    let issuer_auth =
        find_element_by_key(&issuer_signed, "issuerAuth").expect("issuerAuth missing");
    let issuer_auth_arr = get_array(&issuer_auth).expect("issuerAuth is not an array");

    // MSO is the third element of the COSE_Sign1 structure in issuerAuth
    let cbor_mso_wrapped = get_bytes(&issuer_auth_arr[2])
        .expect("Failed to get MSO bytes")
        .clone();

    // Unwrap the Tag 24 wrapping the MSO Map
    let mut mso_unwrap_parser = CborParser::new(&cbor_mso_wrapped);
    let mso_val = mso_unwrap_parser
        .parse_val()
        .expect("Failed to parse wrapped MSO");
    let cbor_mso_map_bytes = if let CborValue::Tag(24, ref bstr_el) = mso_val.value {
        if let CborValue::Bytes(ref b) = bstr_el.value {
            b.clone()
        } else {
            panic!("Expected Bytes inside Tag 24");
        }
    } else {
        panic!("Expected Tag 24");
    };

    // Calculate signed message hash `issuer_sig_digest` on the MSO bytes
    let cbor_mso = format_cose_sign1_message(&cbor_mso_wrapped);
    let mut hasher = Sha256::new();
    hasher.update(&cbor_mso);
    let issuer_sig_digest = N::from_bytes_be(&hasher.finalize());

    let mut map_parser = CborParser::new(&cbor_mso_map_bytes);
    let mso_map = map_parser.parse_val().expect("Failed to parse MSO map");
    let dev_key_info_el =
        find_element_by_key(&mso_map, "deviceKeyInfo").expect("deviceKeyInfo missing");
    let dev_key_el = find_element_by_key(&dev_key_info_el, "deviceKey").expect("deviceKey missing");

    // Extract device public key coordinates (keep original big-endian
    // coordinates)
    let dpkx_bytes =
        find_device_key_coordinate(&dev_key_el, &cbor_mso_map_bytes, 0x21).expect("dpkx missing");
    let dpkx = N::from_bytes_be(&dpkx_bytes);
    let dpky_bytes =
        find_device_key_coordinate(&dev_key_el, &cbor_mso_map_bytes, 0x22).expect("dpky missing");
    let dpky = N::from_bytes_be(&dpky_bytes);

    // Issuer signature is the fourth element of issuerAuth COSE_Sign1 structure
    let issuer_sig_bytes = get_bytes(&issuer_auth_arr[3]).expect("Failed to get issuer signature");
    let issuer_sig_r = N::from_bytes_be(&issuer_sig_bytes[0..32]);
    let issuer_sig_s = N::from_bytes_be(&issuer_sig_bytes[32..64]);

    // Traverse deviceSigned -> deviceAuth -> deviceSignature to get device
    // signature
    let device_signed = find_element_by_key(doc0, "deviceSigned").expect("deviceSigned missing");
    let device_auth =
        find_element_by_key(&device_signed, "deviceAuth").expect("deviceAuth missing");
    let device_signature =
        find_element_by_key(&device_auth, "deviceSignature").expect("deviceSignature missing");
    let device_signature_arr =
        get_array(&device_signature).expect("deviceSignature is not an array");

    // Device signature is the fourth element of deviceSignature COSE_Sign1
    // structure
    let device_sig_bytes =
        get_bytes(&device_signature_arr[3]).expect("Failed to get device signature");
    let device_sig_r = N::from_bytes_be(&device_sig_bytes[0..32]);
    let device_sig_s = N::from_bytes_be(&device_sig_bytes[32..64]);

    let hash_tr_bytes = compute_transcript_hash(transcript, doc_type);
    let device_sig_digest = N::from_bytes_be(&hash_tr_bytes);

    // Locate offset indices in raw CBOR map_bytes for MSO fields
    let doc_type_entry =
        find_key_in_map(&mso_map, "docType").expect("docType key not found in MSO");
    let valid_from =
        find_key_in_map(&mso_map, "validFrom").expect("validFrom key not found in MSO");
    let valid_until =
        find_key_in_map(&mso_map, "validUntil").expect("validUntil key not found in MSO");
    let device_key_info =
        find_key_in_map(&mso_map, "deviceKeyInfo").expect("deviceKeyInfo key not found in MSO");
    let value_digests =
        find_key_in_map(&mso_map, "valueDigests").expect("valueDigests key not found in MSO");

    let attrs = extract_attrs(&root, mdoc, &mso_map);

    ParsedMdoc {
        cbor_mso,
        issuer_sig_digest,
        issuer_sig_r,
        issuer_sig_s,
        device_pk: (dpkx, dpky),
        device_sig_digest,
        device_sig_r,
        device_sig_s,
        doc_type: doc_type.to_string(),
        doc_type_offset_in_mso: doc_type_entry.k,
        valid_from_offset_in_mso: valid_from.k,
        valid_until_offset_in_mso: valid_until.k,
        device_key_info_offset_in_mso: device_key_info.k,
        value_digests_offset_in_mso: value_digests.k,
        attrs,
    }
}

fn extract_attrs(root: &CborElement, mdoc_bytes: &[u8], mso_map: &CborElement) -> Vec<ParsedAttr> {
    let mut attrs = Vec::new();
    let docs_el = find_element_by_key(root, "documents").expect("documents missing");
    let docs_arr = get_array(&docs_el).expect("documents is not an array");
    let doc0 = docs_arr.first().expect("document 0 missing");
    let issuer_signed = find_element_by_key(doc0, "issuerSigned").expect("issuerSigned missing");
    let namespaces_el =
        find_element_by_key(&issuer_signed, "nameSpaces").expect("nameSpaces missing");

    if let CborValue::Map(ns_pairs) = &namespaces_el.value {
        for (ns_key, ns_val) in ns_pairs {
            let ns_name = match &ns_key.value {
                CborValue::Text(s) => s.as_str(),
                _ => continue,
            };
            let items_arr = match get_array(ns_val) {
                Some(arr) => arr,
                _ => continue,
            };
            for signed_item_el in items_arr {
                // Extracts the raw IssuerSignedItem bytes wrapped in Tag 24
                let cbor_issuer_signed_item_wrapped =
                    &mdoc_bytes[signed_item_el.start..signed_item_el.end];
                let cbor_issuer_signed_item_map =
                    get_bytes(signed_item_el).expect("Expected bytes inside Tag 24 attribute");
                let mut attr_parser = CborParser::new(cbor_issuer_signed_item_map);
                let signed_item = attr_parser
                    .parse_val()
                    .expect("Failed to parse attribute map");

                let element_id_el = find_element_by_key(&signed_item, "elementIdentifier")
                    .expect("elementIdentifier missing");
                let element_id = match &element_id_el.value {
                    CborValue::Text(s) => s.clone(),
                    _ => panic!("Expected elementIdentifier to be text"),
                };
                let element_value_el = find_element_by_key(&signed_item, "elementValue")
                    .expect("elementValue value missing");

                let name = element_id.as_bytes().to_vec();
                let cbor_value =
                    &cbor_issuer_signed_item_map[element_value_el.start..element_value_el.end];

                let witness = compute_witness(
                    name,
                    cbor_value.to_vec(),
                    cbor_issuer_signed_item_wrapped,
                    &signed_item,
                    mso_map,
                    ns_name,
                );

                attrs.push(witness);
            }
        }
    }
    attrs
}

fn compute_witness(
    name: Vec<u8>,
    cbor_value: Vec<u8>,
    cbor_issuer_signed_item: &[u8],
    inner_map: &CborElement,
    mso_map: &CborElement,
    namespace: &str,
) -> ParsedAttr {
    use crate::cbor::parse::find_digest_offset;

    let pairs = if let CborValue::Map(pairs) = &inner_map.value {
        pairs
    } else {
        panic!("Expected Map inside issuer_signed_items tag payload");
    };
    assert_eq!(
        pairs.len(),
        4,
        "Expected exactly 4 pairs inside issuer_signed_items map"
    );

    let mut slots = [None; 4];

    let mut length = [0usize; 4];
    let mut digest_id = None;

    for (i, (k, v)) in pairs.iter().enumerate() {
        let key_str = if let CborValue::Text(s) = &k.value {
            s
        } else {
            panic!("Expected text key inside issuer_signed_items map");
        };

        length[i] = v.end - k.start;

        match key_str.as_str() {
            "digestID" => {
                slots[0] = Some(i);
                if let CborValue::Integer(n) = v.value {
                    digest_id = Some(n);
                } else {
                    panic!("Expected integer digestID");
                }
            }
            "random" => slots[1] = Some(i),
            "elementIdentifier" => slots[2] = Some(i),
            "elementValue" => slots[3] = Some(i),
            _ => panic!("Unknown key inside issuer_signed_items: {key_str}"),
        }
    }

    let slot0 = slots[0].expect("digestID key not found in issuer_signed_items");
    let slot1 = slots[1].expect("random key not found in issuer_signed_items");
    let slot2 = slots[2].expect("elementIdentifier key not found in issuer_signed_items");
    let slot3 = slots[3].expect("elementValue key not found in issuer_signed_items");

    let permutation = (slot3 << 6) | (slot2 << 4) | (slot1 << 2) | slot0;

    let mut offsets = [0usize; 4];
    // Subtracting inner_map.end (the inner CBOR map payload length) from the
    // total item length (cbor_issuer_signed_item.len()) gives the exact length
    // of the prefix headers (Tag 24 + ByteString header). Adding 1 accounts for
    // the 1-byte CBOR map header (0xA4), yielding the exact starting byte index
    // of slot 0 across any attribute size without hardcoding magic numbers.
    offsets[0] = (cbor_issuer_signed_item.len() - inner_map.end) + 1;
    for i in 1..4 {
        offsets[i] = offsets[i - 1] + length[i - 1];
    }

    let digest_id_val = digest_id.expect("Missing digestID");

    let mso_digest_offset_in_preimage = find_digest_offset(mso_map, namespace, digest_id_val)
        .expect("Failed to find digest offset in MSO");

    ParsedAttr {
        name,
        cbor_value,
        cbor_issuer_signed_item: cbor_issuer_signed_item.to_vec(),
        mso_digest_offset_in_preimage,
        field_locator: FieldLocator {
            slot_position: offsets,
            length,
            permutation,
        },
    }
}

#[must_use]
pub fn compute_transcript_hash(transcript: &[u8], doc_type: &str) -> Vec<u8> {
    // Construct the DeviceAuthentication structure:
    // DeviceAuthentication = [
    //   "DeviceAuthentication",
    //   SessionTranscript,
    //   docType,
    //   deviceNameSpaces
    // ]
    let device_authentication_header = K_DEVICE_AUTHENTICATION_HEADER.to_vec();
    let mut doc_type_bytes = Vec::new();
    append_text_len(&mut doc_type_bytes, doc_type.len());
    doc_type_bytes.extend_from_slice(doc_type.as_bytes());

    let device_name_spaces_bytes = vec![0xD8, 0x18, 0x41, 0xA0]; // Tag 24 wrapping an empty map

    let mut device_authentication_cbor = device_authentication_header;
    device_authentication_cbor.extend_from_slice(transcript);
    device_authentication_cbor.extend_from_slice(&doc_type_bytes);
    device_authentication_cbor.extend_from_slice(&device_name_spaces_bytes);

    // Construct the COSE_Sign1 structure:
    // COSE_Sign1 = [
    //   protected,
    //   unprotected,
    //   payload,
    //   signature
    // ]
    let mut cose_sign1_bytes = K_COSE_SIGN1_SIGNING_HEADER.to_vec();

    let da_len = device_authentication_cbor.len();
    // Payload length includes the Tag 24 prefix and the byte string header of
    // the payload
    let payload_len = da_len + if da_len < 256 { 4 } else { 5 };
    append_bytes_len(&mut cose_sign1_bytes, payload_len);
    cose_sign1_bytes.extend_from_slice(&K_TAG24);
    append_bytes_len(&mut cose_sign1_bytes, da_len);
    cose_sign1_bytes.extend_from_slice(&device_authentication_cbor);

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&cose_sign1_bytes);
    hasher.finalize().to_vec()
}

fn format_cose_sign1_message(cbor_mso: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(K_COSE1_PREFIX_LEN + 2 + cbor_mso.len());
    buf.extend_from_slice(&K_COSE1_PREFIX);
    buf.push(((cbor_mso.len() >> 8) & 0xff) as u8);
    buf.push((cbor_mso.len() & 0xff) as u8);
    buf.extend_from_slice(cbor_mso);
    buf
}
