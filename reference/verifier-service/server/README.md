# Simple Backend server for processing ZK-mdoc proofs

This simple go server exports a HTTP interface to running the Longfellow ZK-mdoc verifier.  Namely, it verifies a given proof with respect to its claims and returns either an OK or a FAIL response, along with all of the claimed attributes.

## Building in container

Provided Dockerfile allows to compile both server and library, run tests and start the HTTP server. Note that you have to indicate the root of the whole repository for the container. It needs access to the Longfellow ZK C++ library and the circuits.

```
$ cd <root-of-the-repository>/reference/verifier-service
$ docker build -t zk -f Dockerfile ../..
$ docker run -it -p 8888:8888 zk
```

## Building locally

The first step is to build the Longfellow ZK library that can be called by the Golang backend server

```
$ cd <root-of-the-repository>
$ CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B build --install-prefix <root-of-the-repository>/reference/verifier-service/install
$ cd build
$ make install 
```

Then you can link to the required library and build as follows:

```
cd <root-of-the-repository>/reference/verifier-service/server
$ go build 
```

This creates a `server` binary in the directory. You can start it and give it the circuits folder from the main Longfellow ZK library

```
$ ./server -circuit_dir ../../../lib/circuits/mdoc/circuits
2025/09/09 19:53:24 Reading from dir circuits
2025/09/09 19:53:25 Read 31bc7c86c71871dad73619e7da7c5a379221602a3f28ea991b05da1ef656d13c
2025/09/09 19:53:26 Read 3546d1e1a59142ded29a26d30ae4155d682b0f7f2b1a78a1cc63f94b211cbda0
2025/09/09 19:53:27 Read 40b2b68088f1d4c93a42edf01330fed8cac471cdae2b192b198b4d4fc41c9083
2025/09/09 19:53:28 Read 446ffab2fc5bfc71d748dec8ec1785f33b8f399b6ff50d1e0a4a9facd7e66c62
2025/09/09 19:53:29 Read 5249dac202b61e03361a2857867297ee7b1d96a8a4c477d15a4560bde29f704f
2025/09/09 19:53:31 Read 77aa19bdb547b68a30deb37b94d3a506222a455806afcddda88d591493e9a689
2025/09/09 19:53:31 Read 7bcb1a2aee2fbd9907aeef97003fe68fbdaccca94bb048f6079877f7b2caee7c
2025/09/09 19:53:32 Read 89288b9aa69d2120d211618fcca8345deb4f85d2e710c220cc9c059bbee4c91f
2025/09/09 19:53:34 Read 99a5da3739df68c87c7a380cc904bb275dbd4f1b916c3d297ba9d15ee86dd585
2025/09/09 19:53:35 Read bd3168ea0a9096b4f7b9b61d1c210dac1b7126a9ec40b8bc770d4d485efce4e9
2025/09/09 19:53:36 Read c27195e03e22c9ab4efe9e1dabd2c33aa8b2429cc4e86410c6f12542d3c5e0a1
2025/09/09 19:53:37 Read c87721054ae14f3a54462ba975a3cf53e65ec648196528053da82067e103e64e
2025/09/09 19:53:38 Read d260f7ef1bc82a25ad174d61a9611ba4a6e0c8f2f8520d2b6ea1549c79abcd55
2025/09/09 19:53:39 Read f51b7248b364462854d306326abded169854697d752d3bb6d9a9446ff7605ddb
2025/09/09 19:53:40 Read f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f
2025/09/09 19:53:41 Read fa5fadfb2a916d3b71144e9b412eff78f71fd6a6d4607eac10de66b195868b7a
2025/09/09 19:53:41 adding Issuer CA CN=MVMProdCA,OU=IT,O=Arizona Department of Transportation,L=Phoenix,ST=US-AZ,C=US
2025/09/09 19:53:41 adding Issuer CA CN=MVMProdCA,OU=IT,O=Arizona Department of Transportation,L=Phoenix,ST=Arizona,C=US
2025/09/09 19:53:41 adding Issuer CA CN=MVMTestCA,OU=IT,O=Arizona Department of Transportation,L=Phoenix,ST=US-AZ,C=US
2025/09/09 19:53:41 adding Issuer CA CN=California DMV IACA Root,O=CA-DMV,ST=US-CA,C=US
2025/09/09 19:53:41 adding Issuer CA CN=Colorado Root Certificate,OU=CO DRIVES,O=Colorado Department of Revenue,L=Denver,ST=US-CO,C=US
2025/09/09 19:53:41 adding Issuer CA CN=CO DRIVES Root,OU=Colorado DRIVES,O=Colorado Department of Revenue,ST=Colorado,C=US
2025/09/09 19:53:41 adding Issuer CA CN=Georgia Root Certificate Authority,OU=DRIVES,O=Georgia Department of Driver Services,L=Conyers,ST=US-GA,C=US
2025/09/09 19:53:41 adding Issuer CA CN=Georgia Root Certificate Authority,OU=DRIVES,O=Georgia Department of Driver Services,L=Conyers,ST=US-GA,C=US
2025/09/09 19:53:41 adding Issuer CA CN=Fast Enterprises Root,O=Maryland MVA,L=Glen Burnie,ST=US-MD,C=US
2025/09/09 19:53:41 adding Issuer CA CN=New Mexico Root Certificate Authority,OU=New Mexico Motor Vehicle Division,O=New Mexico Taxation and Revenue Department,L=Santa Fe,ST=US-NM,C=US
2025/09/09 19:53:41 adding Issuer CA CN=UL TESTING Staging DS,O=Google,C=ZZ
2025/09/09 19:53:41 adding Issuer CA CN=TEST USE ONLY GICI Staging Root,OU=Wallet,O=Google LLC,C=UT
2025/09/09 19:53:41 adding Issuer CA CN=Identity Credential Root IACA,OU=Wallet,O=Google LLC,C=US
2025/09/09 19:53:41 adding Issuer CA CN=Payground Root,O=Google,C=ZZ
2025/09/09 19:53:41 adding Issuer CA CN=Payground Document Signer,O=Google,C=ZZ
2025/09/09 19:53:41 adding Issuer CA CN=TEST USE ONLY GICI Staging Root,OU=Wallet,O=Google LLC,C=ZZ
2025/09/09 19:53:41 adding Issuer CA CN=Identity Credential Root IACA,OU=Wallet,O=Google LLC,C=XG
{"time":"2025-09-09T19:53:41.486950371Z","level":"INFO","msg":"Starting server","addr":":8888"}
```

There are a few command line flags:
```
  -cacerts <file>
    	File containing issuer CA certs (default "certs.pem")
  -circuit_dir <director>
    	Directory from which to load circuits (default "circuits")
  -port string
    	Listening port (default ":8888")
```

## Running

There must be a `circuits` directory that contains all of the circuits used by the system. This directory is part of the main Longfellow ZK repository, so the server should run out of the box.

## Testing the server

We provide a sample input that you can use to test the service. With the service running in another window, you can use

```
$ curl -X POST -H "Content-Type: application/json" --data-binary @reference/verifier-service/server/examples/post1.json  http://localhost:8888/zkverify
{"Status":true,"Claims":{"org.iso.18013.5.1":[{"ElementIdentifier":"age_over_18","ElementValue":"9Q=="}]}}
```

The return json indicates that the proof was verified (`Status`) with respect to the `Claims`.  If the proof fails, then `Status` will be false, and the `Message` component will include a reason.

You may also need a list of the valid circuits that the server can interpret when you form your web request. You can retrieve this list from the `/specs` endpoint.

```
$ curl localhost:8888/specs
[{"system":"longfellow-libzk-v1","circuit_hash":"f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f","num_attributes":1,"version":5},{"system":"longfellow-libzk-v1","circuit_hash":"f51b7248b364462854d306326abded169854697d752d3bb6d9a9446ff7605ddb","num_attributes":2,"version":5},{"system":"longfellow-libzk-v1","circuit_hash":"c27195e03e22c9ab4efe9e1dabd2c33aa8b2429cc4e86410c6f12542d3c5e0a1","num_attributes":3,"version":5},{"system":"longfellow-libzk-v1","circuit_hash":"fa5fadfb2a916d3b71144e9b412eff78f71fd6a6d4607eac10de66b195868b7a","num_attributes":4,"version":5},{"system":"longfellow-libzk-v1","circuit_hash":"89288b9aa69d2120d211618fcca8345deb4f85d2e710c220cc9c059bbee4c91f","num_attributes":1,"version":4},{"system":"longfellow-libzk-v1","circuit_hash":"d260f7ef1bc82a25ad174d61a9611ba4a6e0c8f2f8520d2b6ea1549c79abcd55","num_attributes":2,"version":4},{"system":"longfellow-libzk-v1","circuit_hash":"77aa19bdb547b68a30deb37b94d3a506222a455806afcddda88d591493e9a689","num_attributes":3,"version":4},{"system":"longfellow-libzk-v1","circuit_hash":"31bc7c86c71871dad73619e7da7c5a379221602a3f28ea991b05da1ef656d13c","num_attributes":4,"version":4},{"system":"longfellow-libzk-v1","circuit_hash":"bd3168ea0a9096b4f7b9b61d1c210dac1b7126a9ec40b8bc770d4d485efce4e9","num_attributes":1,"version":3},{"system":"longfellow-libzk-v1","circuit_hash":"40b2b68088f1d4c93a42edf01330fed8cac471cdae2b192b198b4d4fc41c9083","num_attributes":2,"version":3},{"system":"longfellow-libzk-v1","circuit_hash":"99a5da3739df68c87c7a380cc904bb275dbd4f1b916c3d297ba9d15ee86dd585","num_attributes":3,"version":3},{"system":"longfellow-libzk-v1","circuit_hash":"5249dac202b61e03361a2857867297ee7b1d96a8a4c477d15a4560bde29f704f","num_attributes":4,"version":3}]
```
