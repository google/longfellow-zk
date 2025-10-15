# Test Vectors

This section contains test vectors. Each test vector in specifies the configuration information and inputs. All values are encoded in hexadecimal strings.

## Test Vectors for Merkle Tree

### Vector 1

- Leaves:
  4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a
  dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986
  084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5
  e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71
  e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db
- Root: f22f4501ffd3bdffcecc9e4cd6828a4479aeedd6aa484eb7c1f808ccf71c6e76
- Proof for leaves (0,1): 
  084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5
  f03808f5b8088c61286d505e8e93aa378991d9889ae2d874433ca06acabcd493
- Proof for leaves (1,3):
  e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db
  084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5
  4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a

## Test Vectors for Circuit

### Vector 1

- Description: Circuit C(n, m, s) = 0 if and only if n is the m-th s-gonal number in F_p128.  This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m.
- Field: 2^128^ - 2^108^ + 1 (Field ID 6)
- Depth: 3 Quads: 11 Terms: 11
- Serialization: 01060000010000010000020000040000020000040000ffffffffffffffffffffffffffefffff00000000000000000000000000f0ffff01000000000000000000000000000000fdffffffffffffffffffffffffefffff030000060000030000000000020000000000000000000000080000040000010000000000030000020000020000020000040000080000000000000000000000020000060000000000000000000000040000000000000000030000090000020000000000020000020000020000000000020000020000020000000000020000040000000000000000020000030000030000040000020000

## Test Vectors for Sumcheck
### Vector 1

- Description: Circuit C(n, m, s) = 0 if and only if n is the m-th s-gonal number in F_p128.  This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m.
- Field: 2^128^ - 2^108^ + 1 (Field id 6)
- Fiat-Shamir initialized with
- Serialization: 90e734c42b5f14ee432a0ed95ba2ada05c3f9ecc9b026ded61f00bf57434f93c6f70e9c8b6e3de005ba8b4da93b5fa35fc3efae1e6068399c7f7d009ab5a2711084c97cd5a6e28dd30c598907b328d81915e487c34dbf80aa5da14f0621011a33d838a7b0d9a03533c63c6606f5360f88cf97c728630afdcb9755894a6f5c9068e1fc29f97efc125ba580de64089c6e72433de2a3267b90daeaf418ac8a3df3bbddc6cb141c764c8262346baac2e28033778b1a71f153ba571e80ab29951f9440ba93fede225a35accf6e0114d5240ae92df02d2870e5258ebba416f3d815e1554b05627998fc9d3bf354b89394b27b39f69c6538dbc968a779369e47f214252e0955624e9f4d6dc2a95cf41c57703b8749b959315458d4076f0daf5fdbde23e16c10394ac884ab9cad0782e8f472cb4edb69682d17465363691aafc31b83cd764fb909b50e2fe907fd2137566ddb8c47cc13974957e7f76180860571035f7a4d2658a82e1be8fe155353bc10feae9541365926f0646b4a5351907cbd5d9dbb4

## Test Vectors for Ligero

### Vector 1

- Description: Circuit C(n, m, s) = 0 if and only if n is the m-th s-gonal number in F_p128.  This circuit verifies that 2n = (s-2)m^2 - (s - 4)*m.
- Field: 2^128^ - 2^108^ + 1 (Field id 6)
- Witness vector: [1, 45, 5, 6]
- Pad elements: [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4]
- Parameters:
    - NREQ: 6
    - RATE: 4
    - WR: 20
    - QR: 2
    - NROW: 7
    - NQ: 1
    - BLOCK: 51
- Commitment: 738d2ffb3a8bf24e7aedb94be59041fb2dc13da30fe6b05ebe5126ef8fc36ec2
- Proof size: 3180 bytes
- Proof: fa8d88a73b3a0f9c067658c45bb394a602000000000000000000000000000000fa8d8...2cd5f61cd2b2eb84c79e1707cbad0048fcd820c716584f31991cf1628fb041



## Test Vectors for libzk

