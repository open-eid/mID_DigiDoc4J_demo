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


    @Test
    public void testCreateContainerWithMobile() throws IOException, ParserConfigurationException, SAXException {

        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        configuration.setTslLocation(TSL_LOCATION);

        //Create a container with a text file to be signed
        Container container = ContainerBuilder.
                aContainer().
                withDataFile(DATA_FILE, NIME_TYPE).
                withConfiguration(configuration).
                build();

        //Get the certificate (with a browser plugin, for example)
        X509Certificate signingCert = getSignerCertForMobilId();

        //Get the data to be signed by the user
        DataToSign dataToSign = SignatureBuilder.
                aSignature(container).
                withSigningCertificate(signingCert).
                withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
                withSignatureProfile(SignatureProfile.LT).
                buildDataToSign();

        byte[] signatureValue = signDigestSomewhereRemotely(dataToSign, HashType.SHA_256);


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

    private byte[] getSignature(String sessionIdType) {

        GetMobileSignHashStatusRequest mobileSignHashStatusRequest = new GetMobileSignHashStatusRequest();
        mobileSignHashStatusRequest.setSesscode(sessionIdType);
        mobileSignHashStatusRequest.setWaitSignature(true);

        GetMobileSignHashStatusResponse mobileSignHashStatusResponse = mobileId.getMobileSignHashStatus(mobileSignHashStatusRequest);
        return mobileSignHashStatusResponse.getSignature();
    }

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

    private boolean isTestContainerExist(){
        File file = new File(SAVE_AS_FILE);
        return file.exists();
    }

    private void deleteContainer(){

        File file = new File(SAVE_AS_FILE);
        if(file.exists()){
            file.delete();
        }
    }
}
