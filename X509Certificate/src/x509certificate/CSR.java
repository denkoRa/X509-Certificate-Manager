/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package x509certificate;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import sun.security.x509.X500Name;
import static x509certificate.KeyPairUnit.keyPairMap;
import sun.security.pkcs10.*;
/**
 *
 * @author Rade
 */
public class CSR {

    public static Map<String, String> SubjectAndIssuerMap = new HashMap<>();
    public static Map<String, CSR> CSRMap = new HashMap<>();
    
    private PKCS10 pkcs10;

    public PKCS10 getPkcs10() {
        return pkcs10;
    }

    public void setPkcs10(PKCS10 pkcs10) {
        this.pkcs10 = pkcs10;
    }
    
    
    public CSR(String csrName, String kpName) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CSRException {
        KeyPairUnit kpu = keyPairMap.get(kpName);
        SubjectAndIssuerMap.put(csrName, kpName);
        X500Name name = new X500Name(((X509SelfSigned) kpu.getCert()).getSubjectDN().getName());
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(kpu.getPk());
        PKCS10 pkcs10 = new PKCS10(kpu.getCert().getPublicKey());
        pkcs10.encodeAndSign(name, signature);
        if (CSRMap.containsKey(csrName)) {
            throw new CSRException("CSR " + csrName + " already exists!");
        }
        CSRMap.put(csrName, this);    
        
    }

}
