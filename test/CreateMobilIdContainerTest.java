import eu.europa.esig.dss.DSSUtils;
import org.apache.axis2.AxisFault;
import org.digidoc4j.*;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;
import ws.dds.gen.GetMobileCertificate;
import ws.dds.gen.GetMobileCertificateResponse;
import ws.dds.service.DigiDocServiceStub;
import ws.mid.gen.*;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertTrue;

/**

 How to sign DD4J container with Estonian Mobile ID
 https://github.com/open-eid/digidoc4j/wiki

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

 The use of DigiDocService MobileCreateSignature is deprecated and the signature response as a
 full XAdES signature cannot be added to BDOC/ASIC-E containers. Do not use it
 See the full DigiDocService specification and WSDL

 You need to request separate permissions from SK (Sertifitseerimiskeskus) to access the
 GetMobileCertificate and MobileSignHashRequest services. These two calls need special permissions
 in addition to the rest of the Mobile ID access.
 */
public class CreateMobilIdContainerTest {

    private final String DICI_DOC_TARGET_ENDPOINT = "https://tsp.demo.sk.ee/";

    private final String ID_CODE = "11412090004";
    private final String PHONE_NUMBER = "+37200000766";
    private final String MESSAGE_TO_DISPLAY= "Test";
    private final String SERVICE_NAME = "Testimine";
    private final String RETURN_CERT_DATA = "bothRSA";
    private final String COUNTRY = "EE";

    private final String SAVE_AS_FILE = "testFiles/test-MobilIdContainer.bdoc";
    private final String DATA_FILE = "testFiles/test.txt";

    private final String NIME_TYPE = "text/plain";

    private final String TSL_LOCATION = "https://open-eid.github.io/test-TL/tl-mp-test-EE.xml";

    private MobileId mobileId;
    private DigiDocServiceStub digiDocServiceStub;
    private Configuration configuration;


    @Before
    public void setUp() throws AxisFault {
        MobileIdService mobileIdService = new MobileIdService();
        mobileId = mobileIdService.getMobileIdService();

        digiDocServiceStub = new DigiDocServiceStub(DICI_DOC_TARGET_ENDPOINT);

        configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setTslLocation(TSL_LOCATION);

        deleteContainer();
    }

    /**
     * Create DD4J container with mobil ID
     *
     * @throws IOException
     * @throws ParserConfigurationException
     * @throws SAXException
     */
    @Test
    public void testCreateContainerWithMobile() throws IOException, ParserConfigurationException, SAXException {

        //Create a container with a text file to be signed
        Container container = ContainerBuilder.
                aContainer().
                withDataFile(DATA_FILE, NIME_TYPE).
                withConfiguration(configuration).
                build();

        //Get the certificate
        X509Certificate signingCert = getSignerCertForMobilId();

        //Get the data to be signed by the user
        DataToSign dataToSign = SignatureBuilder.
                aSignature(container).
                withSigningCertificate(signingCert).
                withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
                withSignatureProfile(SignatureProfile.LT).
                buildDataToSign();

        //Sign the digest
        byte[] signatureValue = signDigestSomewhereRemotely(dataToSign, HashType.SHA_256);

        //Finalize the signature with OCSP response and timestamp (or timemark)
        Signature signature = dataToSign.finalize(signatureValue);

        //Add signature to the container
        container.addSignature(signature);

        //Save the container as a .bdoc file
        container.saveAsFile(SAVE_AS_FILE);

        ValidationResult validationResult = container.validate();

        assertTrue(validationResult.isValid());
        assertTrue(validationResult.getErrors().isEmpty());
        assertTrue(isTestContainerExist());

        deleteContainer();
    }

    private byte[] signDigestSomewhereRemotely(DataToSign dataToSign, HashType hashType) {

        String sessionIdType = getMobileSignHash(dataToSign, hashType);
        byte[] signatureValue = getSignature(sessionIdType);
        return signatureValue;
    }

    /**
     * Use GetMobileSignHashStatus request in MobileIdService
     *
     * @param sessionIdType
     * @return
     */
    private byte[] getSignature(String sessionIdType) {

        GetMobileSignHashStatusRequest mobileSignHashStatusRequest = new GetMobileSignHashStatusRequest();
        mobileSignHashStatusRequest.setSesscode(sessionIdType);
        mobileSignHashStatusRequest.setWaitSignature(true);

        GetMobileSignHashStatusResponse mobileSignHashStatusResponse = mobileId.getMobileSignHashStatus(mobileSignHashStatusRequest);
        return mobileSignHashStatusResponse.getSignature();
    }

    /**
     * Sign the digest with Mobile ID (using MobileSignHash request in MobileIdService)
     *
     * @param dataToSign
     * @param hashType
     * @return
     */
    private String getMobileSignHash(DataToSign dataToSign, HashType hashType) {

        String hash = DatatypeConverter.printHexBinary(dataToSign.getDigestToSign());

        MobileSignHashRequest mobileSignHashRequest = new MobileSignHashRequest();
        mobileSignHashRequest.setIDCode(ID_CODE);
        mobileSignHashRequest.setPhoneNo(PHONE_NUMBER);
        mobileSignHashRequest.setLanguage(LanguageType.EST);
        mobileSignHashRequest.setServiceName(SERVICE_NAME);
        mobileSignHashRequest.setMessageToDisplay(MESSAGE_TO_DISPLAY);
        mobileSignHashRequest.setHash(hash);
        mobileSignHashRequest.setHashType(hashType);
        mobileSignHashRequest.setKeyID(KeyID.RSA);

        MobileSignHashResponse mobileSignHashResponse =  mobileId.mobileSignHash(mobileSignHashRequest);

        return mobileSignHashResponse.getSesscode();
    }

    /**
     * Get the Mobile ID user's signer certificate (GetMobileCertificate request in DigiDocService)
     *
     * @return
     */
    private X509Certificate getSignerCertForMobilId(){

        try {
            GetMobileCertificate mobileCertificate = new GetMobileCertificate();
            mobileCertificate.setIDCode(ID_CODE);
            mobileCertificate.setCountry(COUNTRY);
            mobileCertificate.setPhoneNo(PHONE_NUMBER);
            mobileCertificate.setReturnCertData(RETURN_CERT_DATA);

            GetMobileCertificateResponse mobileCertificateResponse = digiDocServiceStub.getMobileCertificate(mobileCertificate);
            byte[] bytes = mobileCertificateResponse.getSignCertData().getBytes();

            return DSSUtils.loadCertificate(bytes).getCertificate();

        } catch (RemoteException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Check if test container exist
     *
     * @return
     */
    private boolean isTestContainerExist(){
        File file = new File(SAVE_AS_FILE);
        return file.exists();
    }

    /**
     * Delete test container
     *
     */
    private void deleteContainer(){

        File file = new File(SAVE_AS_FILE);
        if(file.exists()){
            file.delete();
        }
    }
}
