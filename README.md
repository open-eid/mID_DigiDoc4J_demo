 # How to sign DD4J container with Estonian Mobile ID
 
 Project "mIDwDD4J" is an example how to sign and create digital 
 signature containers with DigiDoc4j Java library and
 Estonian Mobile ID.
 
 ## How to use it
  - run pom.xml by Maven, command is: `mvn clean install`
  - run CreateMobilIdContainerTest.testCreateContainerWithMobile() method 
   
 ## Instruction  
 http://www.id.ee/index.php?id=30340
 mid.wsdl: https://tsp.demo.sk.ee/v2/mid.wsdl
 dds_literal.wsdl: https://tsp.demo.sk.ee/dds_literal.wsdl

 It is possible to sign BDOC, ASIC-E and DDOC containers with Mobile ID DigiDoc Service by using
 two step external signing process.
 
 Here's an example of doing two step external signing
 Signer's certificate can be retrieved by using DigiDocService GetMobileCertificate request
 Digest can be signed using MobileIdService MobileSignHashRequest request
 DigiDocService can be used with the following steps:

 1. Get the Mobile ID user's signer certificate (GetMobileCertificate request in DigiDocService)
 2. Create a container to be signed (using ContainerBuilder)
 3. Calculate digest to be signed (dataToSign.getDigestToSign())
 4. Sign the digest with Mobile ID (using MobileSignHash and GetMobileSignHashStatus requests
 in MobileIdServices)
 5. Finalize the signature (dataToSign.finalize(signatureValue))
 6. Add the signature to the container (container.addSignature(signature))

 You need to request separate permissions from SK (Sertifitseerimiskeskus) to access the
 GetMobileCertificate and MobileSignHashRequest services. These two calls need special permissions
 in addition to the rest of the Mobile ID access.

 We can provide configuration. "Configuration.Mode.TEST" should be used for testing.
 http://open-eid.github.io/digidoc4j/org/digidoc4j/Configuration.html

 https://github.com/open-eid/digidoc4j/wiki
 https://github.com/open-eid/digidoc4j/wiki/Questions-&-Answers#how-to-sign-with-estonian-mobile-id
 http://sk-eid.github.io/dds-documentation/api/api_docs/#digital-signature-api

 Test numbers:
 http://www.id.ee/?id=36373
 