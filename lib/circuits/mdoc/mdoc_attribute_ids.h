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

// Extracted from
// https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20WG%2010_N2549_ISO-IEC%2018013-5-%20Personal%20identification%20%E2%80%94%20ISO-compliant%20driving%20licence%20%E2%80%94%20Part%205-%20Mobile%20driving%20lic.pdf
// https://www.aamva.org/getmedia/bb4fee66-592d-4d39-813a-8fdfd910268a/MobileDLGuidelines1-5.pdf
constexpr MdocAttribute kMdocAttributes[] = {
    {"family_name", "eu.europa.ec.eudi.pid.1"},
    {"given_name", "eu.europa.ec.eudi.pid.1"},
    {"birth_date", "eu.europa.ec.eudi.pid.1"},
    {"age_over_18", "eu.europa.ec.eudi.pid.1"},
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ATTRIBUTE_IDS_H_
