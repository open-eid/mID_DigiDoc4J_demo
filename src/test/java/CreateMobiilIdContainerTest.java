import org.apache.axis2.AxisFault;
import org.junit.Before;
import org.junit.Test;
import ws.mid.gen.*;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

public class CreateMobiilIdContainerTest {

    private final String MOBIL_ID_TARGET_ENDPOINT = "https://tsp.demo.sk.ee/v2/";
    private final String DICI_DOC_TARGET_ENDPOINT = "https://tsp.demo.sk.ee/";

    private final String ID_CODE = "11412090004";
    private final String PHONE_NUMBER = "+37200000766";
    private final String TESTIMINE = "Testimine";
    private final String RETURN_CERT_DATA = "bothRSA";
    private final String COUNTRY = "EE";

    private final String SAVE_AS_FILE = "testFiles/tmp/test-MobiilIdContainer.bdoc";
    private final String DATA_FILE = "testFiles/helper-files/test.txt";

    private final String NIME_TYPE = "text/plain";


    @Before
    public void setUp() throws AxisFault {

    }

    @Test
    public void atest(){

        MobileIdService b = new MobileIdService();
        MobileId u = b.getMobileIdService();

        MobileSignHashRequest mobileSignHashRequest = new MobileSignHashRequest();
        mobileSignHashRequest.setIDCode(ID_CODE);
        mobileSignHashRequest.setPhoneNo(PHONE_NUMBER);
        mobileSignHashRequest.setLanguage(LanguageType.EST);
        mobileSignHashRequest.setServiceName(TESTIMINE);
        mobileSignHashRequest.setMessageToDisplay(TESTIMINE);
        mobileSignHashRequest.setHash("d7793f072e0b55c07ce1e1b4e3d010654b2ef2f990a714378ed330a00ba28ed7");
        mobileSignHashRequest.setHashType(HashType.SHA_256);
        mobileSignHashRequest.setKeyID(KeyID.RSA);

        MobileSignHashResponse mobileSignHashResponse =  u.mobileSignHash(mobileSignHashRequest);



    }



}
