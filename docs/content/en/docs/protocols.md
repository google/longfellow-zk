---
title: Using ZK in Identity Protocols
date: 2025-09-25
weight: 3
---

### How to request a ZK proof via openid

Here is a proposed method to use the openid4vp framework to request a ZK proof.  Openid4vp is an under-specified framework designed to encapsulate any specific identity format.  One idea is for the `dcql_query` element to contain enough information to identity a ZK system, a ZK circuit, and a ZK theorem which defines the set of acceptable respose messages.

In the example below, the only differences with a standard `mdoc` request occur in the `format` and `meta` components: the special `mso_mdoc_zk` format value, and 
the inclusion of `zk_system_type` and `verifier_message`, which are defined in the ISO 18013-5 second edition, section 10.3.4.

```json
{
  "response_type": "vp_token",
  "response_mode": "dc_api",
  "nonce": "nonce",
  "dcql_query": {
    "credentials": [{
      "id": "cred1",
      "format": "mso_mdoc_zk",
      "meta": {
        "doctype_value": "org.iso.18013.5.1.mDL"
        "zk_system_type": [
         {
          "system": "longfellow-libzk-v1",
           "circuit_hash": "f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f",
           "num_attributes": 1,
           "version": 1
         }
       ],
       "verifier_message": "challenge"
      },
     "claims": [{
         "path": ["org.iso.18013.5.1", "family_name"]
      }]
    }]
  },
  "client_metadata": {
  "jwks": {
  "keys": [
     {
        "kid": "verifier",
        "use": "enc",
        "alg": "ECDH-ES",
        "kty": "EC",
        "crv": "P-256",
        "x": "1234567890",
        "y": "1234567890"
     }
   ]
  },
  "authorization_encrypted_response_alg": "ECDH-ES",
  "authorization_encrypted_response_enc": "A128GCM"
 }
}
```

