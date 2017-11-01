import eu.europa.esig.dss.DSSUtils;
import org.digidoc4j.*;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;
import ws.gen.*;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.ws.Holder;
import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertTrue;

/**
 How to sign DD4J container with Estonian Mobile ID

 It is possible to sign BDOC, ASIC-E and DDOC containers with Mobile ID DigiDoc Service.
 Signer's certificate can be retrieved by using DigiDocService GetMobileCertificate request
 Digest can be signed using MobileIdService MobileSignHashRequest request

 We can provide configuration. "Configuration.Mode.TEST" should be used for testing.
 http://open-eid.github.io/digidoc4j/org/digidoc4j/Configuration.html

 1. Get the Mobile ID user's signer certificate (GetMobileCertificate request in DigiDocService)
 2. Create a container to be signed (using ContainerBuilder)
 3. Calculate digest to be signed (dataToSign.getDigestToSign())
 4. Sign the digest with Mobile ID (using MobileSignHash and GetMobileSignHashStatus requests
 in MobileIdServices)
 5. Finalize the signature (dataToSign.finalize(signatureValue))
 6. Add the signature to the container (container.addSignature(signature))
 */
public class CreateMobilIdContainerTest {

    private final String ID_CODE = "11412090004";
    private final String PHONE_NUMBER = "+37200000766";
    private final String MESSAGE_TO_DISPLAY= "Test";
    private final String SERVICE_NAME = "Testimine";
    private final String RETURN_CERT_DATA = "signRSA";
    private final String COUNTRY = "EE";

    private final String SAVE_AS_FILE = "src/test/resources/testFiles/test-MobilIdContainer.bdoc";
    private final String DATA_FILE = "src/test/resources/testFiles/test.txt";

    private final String NIME_TYPE = "text/plain";

    private final String TSL_LOCATION = "https://open-eid.github.io/test-TL/tl-mp-test-EE.xml";
    private final String SSL_TRUSTSTORE_PATH = "src/main/resources/sslca.jks";
    private final String SSL_TRUSTSTORE_PW = "sslcakeystore";

    private MobileId mobileId;
    private DigiDocServicePortType digiDocServicePortType;
    private Configuration configuration;


    @Before
    public void setUp(){
        MobileIdService mobileIdService = new MobileIdService();
        mobileId = mobileIdService.getMobileIdService();

        DigiDocService digiDocService = new DigiDocService();
        digiDocServicePortType = digiDocService.getDigiDocService();

        configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setTslLocation(TSL_LOCATION);
        configuration.setSslTruststorePath(SSL_TRUSTSTORE_PATH);
        configuration.setSslTruststorePassword(SSL_TRUSTSTORE_PW);

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
    public void testCreateContainerWithMobile() {

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
        byte[] signatureValue = signDigest(dataToSign, HashType.SHA_256);

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

    private byte[] signDigest(DataToSign dataToSign, HashType hashType) {

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

        final String idCode = ID_CODE;
        final String country = COUNTRY;
        final String phoneNo = PHONE_NUMBER;
        final String returnCertData = RETURN_CERT_DATA;

        Holder<String> authCertStatus = new Holder<String>();
        Holder<String> signCertStatus = new Holder<String>();
        Holder<String> authCertData = new Holder<String>();
        Holder<String> signCertData = new Holder<String>();

        digiDocServicePortType.getMobileCertificate(idCode, country, phoneNo, returnCertData, authCertStatus, signCertStatus,
                authCertData, signCertData);

        byte[] convertToDER = DSSUtils.convertToDER(signCertData.value);
        return DSSUtils.loadCertificate(convertToDER).getCertificate();
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
