// Copyright 2025 Google LLC.
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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ATTRIBUTE_IDS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ATTRIBUTE_IDS_H_

#include <string_view>

namespace proofs {

struct MdocAttribute {
  std::string_view identifier;
  std::string_view documentspec;
};

constexpr const char* kMDLNamespace = "org.iso.18013.5.1";
constexpr const char* kAAMVANamespace = "org.iso.18013.5.1.aamva";
constexpr const char* kEUAVNamespace = "eu.europa.ec.av.1";
constexpr const char* kEUDIPIDNamespace = "eu.europa.ec.eudi.pid.1";
constexpr const char* kISO23220Namespace = "org.iso.23220.1";
constexpr const char* kISO23220PhotoIDNamespace = "org.iso.23220.photoID.1";
constexpr const char* kISO23220DTCNamespace = "org.iso.23220.dtc.1";
constexpr const char* kAadhaarNamespace = "in.gov.uidai.aadhaar.1";

constexpr const char* kSupportedNamespaces[] = {
    kMDLNamespace,         kAAMVANamespace,    kEUAVNamespace,
    kEUDIPIDNamespace,     kISO23220Namespace, kISO23220PhotoIDNamespace,
    kISO23220DTCNamespace, kAadhaarNamespace};

constexpr const char* kIDPassDocType = "com.google.wallet.idcard.1";
constexpr const char* kMDLDocType = "org.iso.18013.5.1.mDL";
constexpr const char* kEUAVDocType = "eu.europa.ec.av.1";
constexpr const char* kEUDIPIDDocType = "eu.europa.ec.eudi.pid.1";
constexpr const char* kISO23220PhotoIDDocType = "org.iso.23220.photoID.1";
constexpr const char* kAadhaarDocType = "in.gov.uidai.aadhaar.1";

// Extracted from
// https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20WG%2010_N2549_ISO-IEC%2018013-5-%20Personal%20identification%20%E2%80%94%20ISO-compliant%20driving%20licence%20%E2%80%94%20Part%205-%20Mobile%20driving%20lic.pdf
// https://www.aamva.org/getmedia/bb4fee66-592d-4d39-813a-8fdfd910268a/MobileDLGuidelines1-5.pdf
constexpr MdocAttribute kMdocAttributes[] = {
    {"family_name", kMDLNamespace},
    {"given_name", kMDLNamespace},
    {"birth_date", kMDLNamespace},
    {"issue_date", kMDLNamespace},
    {"expiry_date", kMDLNamespace},
    {"issuing_country", kMDLNamespace},
    {"issuing_authority", kMDLNamespace},
    {"document_number", kMDLNamespace},
    {"portrait", kMDLNamespace},
    {"driving_privileges", kMDLNamespace},
    {"un_distinguishing_sign", kMDLNamespace},
    {"administrative_number", kMDLNamespace},
    {"sex", kMDLNamespace},
    {"height", kMDLNamespace},
    {"weight", kMDLNamespace},
    {"eye_colour", kMDLNamespace},
    {"hair_colour", kMDLNamespace},
    {"birth_place", kMDLNamespace},
    {"resident_address", kMDLNamespace},
    {"portrait_capture_date", kMDLNamespace},
    {"age_in_years", kMDLNamespace},
    {"age_birth_year", kMDLNamespace},
    {"age_over_10", kMDLNamespace},
    {"age_over_11", kMDLNamespace},
    {"age_over_12", kMDLNamespace},
    {"age_over_13", kMDLNamespace},
    {"age_over_14", kMDLNamespace},
    {"age_over_15", kMDLNamespace},
    {"age_over_16", kMDLNamespace},
    {"age_over_17", kMDLNamespace},
    {"age_over_18", kMDLNamespace},
    {"age_over_19", kMDLNamespace},
    {"age_over_20", kMDLNamespace},
    {"age_over_21", kMDLNamespace},
    {"age_over_23", kMDLNamespace},
    {"age_over_25", kMDLNamespace},
    {"age_over_50", kMDLNamespace},
    {"age_over_55", kMDLNamespace},
    {"age_over_60", kMDLNamespace},
    {"age_over_65", kMDLNamespace},
    {"age_over_70", kMDLNamespace},
    {"age_over_75", kMDLNamespace},
    {"issuing_jurisdiction", kMDLNamespace},
    {"nationality", kMDLNamespace},
    {"resident_city", kMDLNamespace},
    {"resident_state", kMDLNamespace},
    {"resident_postal_code", kMDLNamespace},
    {"resident_country", kMDLNamespace},
    {"biometric_template_face", kMDLNamespace},
    {"biometric_template_voice", kMDLNamespace},
    {"biometric_template_finger", kMDLNamespace},
    {"biometric_template_iris", kMDLNamespace},
    {"biometric_template_retina", kMDLNamespace},
    {"biometric_template_hand_geometry", kMDLNamespace},
    {"biometric_template_keystroke", kMDLNamespace},
    {"biometric_template_signature_sign", kMDLNamespace},
    {"biometric_template_lip_movement", kMDLNamespace},
    {"biometric_template_thermal_face", kMDLNamespace},
    {"biometric_template_thermal_hand", kMDLNamespace},
    {"biometric_template_gait", kMDLNamespace},
    {"biometric_template_body_odor", kMDLNamespace},
    {"biometric_template_dna", kMDLNamespace},
    {"biometric_template_ear", kMDLNamespace},
    {"biometric_template_finger_geometry", kMDLNamespace},
    {"biometric_template_palm_geometry", kMDLNamespace},
    {"biometric_template_vein_pattern", kMDLNamespace},
    {"biometric_template_foot_print", kMDLNamespace},
    {"family_name_national_character", kMDLNamespace},
    {"given_name_national_character", kMDLNamespace},
    {"signature_usual_mark", kMDLNamespace},

    {"name_suffix", kAAMVANamespace},
    {"organ_donor", kAAMVANamespace},
    {"veteran", kAAMVANamespace},
    {"family_name_truncation", kAAMVANamespace},
    {"given_name_truncation", kAAMVANamespace},
    {"aka_family_name.v2", kAAMVANamespace},
    {"aka_given_name.v2", kAAMVANamespace},
    {"aka_suffix", kAAMVANamespace},
    {"weight_range", kAAMVANamespace},
    {"race_ethnicity", kAAMVANamespace},
    {"sex", kAAMVANamespace},
    {"first_name", kAAMVANamespace},
    {"middle_names", kAAMVANamespace},
    {"first_name_truncation", kAAMVANamespace},
    {"middle_names_truncation", kAAMVANamespace},
    {"EDL_credential", kAAMVANamespace},
    {"EDL_credential.v2", kAAMVANamespace},
    {"DHS_compliance", kAAMVANamespace},
    {"resident_county", kAAMVANamespace},
    {"resident_county.v2", kAAMVANamespace},
    {"hazmat_endorsement_expiration_date", kAAMVANamespace},
    {"CDL_indicator", kAAMVANamespace},
    {"CDL_non_domiciled", kAAMVANamespace},
    {"CDL_non_domiciled.v2", kAAMVANamespace},
    {"DHS_compliance_text", kAAMVANamespace},
    {"DHS_temporary_lawful_status", kAAMVANamespace},

    {"family_name", kEUDIPIDNamespace},
    {"given_name", kEUDIPIDNamespace},
    {"birth_date", kEUDIPIDNamespace},
    {"age_in_years", kEUDIPIDNamespace},
    {"age_birth_year", kEUDIPIDNamespace},
    {"age_equal_or_over", kEUDIPIDNamespace},
    {"age_over_18", kEUDIPIDNamespace},
    {"age_over_21", kEUDIPIDNamespace},
    {"family_name_birth", kEUDIPIDNamespace},
    {"given_name_birth", kEUDIPIDNamespace},
    {"birth_place", kEUDIPIDNamespace},
    {"place_of_birth", kEUDIPIDNamespace},
    {"birth_country", kEUDIPIDNamespace},
    {"birth_state", kEUDIPIDNamespace},
    {"birth_city", kEUDIPIDNamespace},
    {"address", kEUDIPIDNamespace},
    {"resident_address", kEUDIPIDNamespace},
    {"resident_country", kEUDIPIDNamespace},
    {"resident_state", kEUDIPIDNamespace},
    {"resident_city", kEUDIPIDNamespace},
    {"resident_postal_code", kEUDIPIDNamespace},
    {"resident_street", kEUDIPIDNamespace},
    {"resident_house_number", kEUDIPIDNamespace},
    {"sex", kEUDIPIDNamespace},
    {"nationality", kEUDIPIDNamespace},
    {"issuance_date", kEUDIPIDNamespace},
    {"expiry_date", kEUDIPIDNamespace},
    {"issuing_authority", kEUDIPIDNamespace},
    {"document_number", kEUDIPIDNamespace},
    {"personal_administrative_number", kEUDIPIDNamespace},
    {"issuing_jurisdiction", kEUDIPIDNamespace},
    {"issuing_country", kEUDIPIDNamespace},
    {"portrait", kEUDIPIDNamespace},
    {"email_address", kEUDIPIDNamespace},
    {"mobile_phone_number", kEUDIPIDNamespace},

    {"family_name_unicode", kISO23220Namespace},
    {"given_name_unicode", kISO23220Namespace},
    {"birth_date", kISO23220Namespace},
    {"portrait", kISO23220Namespace},
    {"issue_date", kISO23220Namespace},
    {"expiry_date", kISO23220Namespace},
    {"issuing_authority_unicode", kISO23220Namespace},
    {"issuing_country", kISO23220Namespace},
    {"age_in_years", kISO23220Namespace},
    {"age_over_13", kISO23220Namespace},
    {"age_over_16", kISO23220Namespace},
    {"age_over_18", kISO23220Namespace},
    {"age_over_21", kISO23220Namespace},
    {"age_over_25", kISO23220Namespace},
    {"age_over_60", kISO23220Namespace},
    {"age_over_62", kISO23220Namespace},
    {"age_over_65", kISO23220Namespace},
    {"age_over_68", kISO23220Namespace},
    {"age_birth_year", kISO23220Namespace},
    {"portrait_capture_date", kISO23220Namespace},
    {"birthplace", kISO23220Namespace},
    {"name_at_birth", kISO23220Namespace},
    {"resident_address_unicode", kISO23220Namespace},
    {"resident_city_unicode", kISO23220Namespace},
    {"resident_postal_code", kISO23220Namespace},
    {"resident_country", kISO23220Namespace},
    {"resident_city_latin1", kISO23220Namespace},
    {"sex", kISO23220Namespace},
    {"nationality", kISO23220Namespace},
    {"document_number", kISO23220Namespace},
    {"issuing_subdivision", kISO23220Namespace},
    {"family_name_latin1", kISO23220Namespace},
    {"given_name_latin1", kISO23220Namespace},

    {"person_id", kISO23220PhotoIDNamespace},
    {"birth_country", kISO23220PhotoIDNamespace},
    {"birth_state", kISO23220PhotoIDNamespace},
    {"birth_city", kISO23220PhotoIDNamespace},
    {"administrative_number", kISO23220PhotoIDNamespace},
    {"resident_street", kISO23220PhotoIDNamespace},
    {"resident_house_number", kISO23220PhotoIDNamespace},
    {"travel_document_number", kISO23220PhotoIDNamespace},
    {"resident_state", kISO23220PhotoIDNamespace},

    {"dtc_version", kISO23220DTCNamespace},
    {"dtc_sod", kISO23220DTCNamespace},
    {"dtc_dg1", kISO23220DTCNamespace},
    {"dtc_dg2", kISO23220DTCNamespace},
    {"dtc_dg3", kISO23220DTCNamespace},
    {"dtc_dg4", kISO23220DTCNamespace},
    {"dtc_dg5", kISO23220DTCNamespace},
    {"dtc_dg6", kISO23220DTCNamespace},
    {"dtc_dg7", kISO23220DTCNamespace},
    {"dtc_dg8", kISO23220DTCNamespace},
    {"dtc_dg9", kISO23220DTCNamespace},
    {"dtc_dg10", kISO23220DTCNamespace},
    {"dtc_dg11", kISO23220DTCNamespace},
    {"dtc_dg12", kISO23220DTCNamespace},
    {"dtc_dg13", kISO23220DTCNamespace},
    {"dtc_dg14", kISO23220DTCNamespace},
    {"dtc_dg15", kISO23220DTCNamespace},
    {"dtc_dg16", kISO23220DTCNamespace},
    {"dg_content_info", kISO23220DTCNamespace},

    // https://ageverification.dev/av-doc-technical-specification/docs/architecture-and-technical-specifications/#411-attribute-set
    {"age_over_18", kEUAVNamespace},
    {"age_over_13", kEUAVNamespace}, /* The rest of these are optional. */
    {"age_over_15", kEUAVNamespace},
    {"age_over_16", kEUAVNamespace},
    {"age_over_21", kEUAVNamespace},
    {"age_over_23", kEUAVNamespace},
    {"age_over_25", kEUAVNamespace},
    {"age_over_27", kEUAVNamespace},
    {"age_over_28", kEUAVNamespace},
    {"age_over_40", kEUAVNamespace},
    {"age_over_60", kEUAVNamespace},
    {"age_over_65", kEUAVNamespace},
    {"age_over_67", kEUAVNamespace},
    {"portrait", kEUAVNamespace},

    // Aadhaar attributes
    {"credential_issuing_date", kAadhaarNamespace},
    {"enrolment_date", kAadhaarNamespace},
    {"enrolment_number", kAadhaarNamespace},
    {"is_nri", kAadhaarNamespace},
    {"resident_image", kAadhaarNamespace},
    {"resident_name", kAadhaarNamespace},
    {"local_resident_name", kAadhaarNamespace},
    {"age_above18", kAadhaarNamespace},
    {"age_above60", kAadhaarNamespace},
    {"age_above75", kAadhaarNamespace},
    {"dob", kAadhaarNamespace},
    {"gender", kAadhaarNamespace},
    {"building", kAadhaarNamespace},
    {"local_building", kAadhaarNamespace},
    {"locality", kAadhaarNamespace},
    {"local_locality", kAadhaarNamespace},
    {"street", kAadhaarNamespace},
    {"local_street", kAadhaarNamespace},
    {"landmark", kAadhaarNamespace},
    {"local_landmark", kAadhaarNamespace},
    {"vtc", kAadhaarNamespace},
    {"local_vtc", kAadhaarNamespace},
    {"sub_district", kAadhaarNamespace},
    {"local_sub_district", kAadhaarNamespace},
    {"district", kAadhaarNamespace},
    {"local_district", kAadhaarNamespace},
    {"state", kAadhaarNamespace},
    {"local_state", kAadhaarNamespace},
    {"po_name", kAadhaarNamespace},
    {"local_po_name", kAadhaarNamespace},
    {"pincode", kAadhaarNamespace},
    {"address", kAadhaarNamespace},
    {"local_address", kAadhaarNamespace},
    {"mobile", kAadhaarNamespace},
    {"masked_mobile", kAadhaarNamespace},
    {"email", kAadhaarNamespace},
    {"masked_email", kAadhaarNamespace},
    {"masked_uid", kAadhaarNamespace},
    {"aadhaar_type", kAadhaarNamespace},
    {"expires_on", kAadhaarNamespace},
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ATTRIBUTE_IDS_H_
