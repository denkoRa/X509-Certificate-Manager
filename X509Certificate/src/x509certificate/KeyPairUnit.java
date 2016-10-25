/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package x509certificate;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.IssuerAlternativeNameExtension;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;

/**
 *
 * @author Rade
 */
public class KeyPairUnit {
    
    
    
    public static Map<String, KeyPairUnit> keyPairMap = new HashMap<>();
    
    private PrivateKey pk;
    private Certificate cert;

    public KeyPairUnit(PrivateKey pk, Certificate cert) {
        this.pk = pk;
        this.cert = cert;
    }

    public PrivateKey getPk() {
        return pk;
    }

    public void setPk(PrivateKey pk) {
        this.pk = pk;
    }

    public Certificate getCert() {
        return cert;
    }

    public void setCert(Certificate cert) {
        this.cert = cert;
    }
    
    public static KeyPairUnit createKeyPairAndStoreIt(String keyPairName, CertificateVersion certVersion, CertificateValidity certValidity, CertificateSerialNumber certSerial, X500Name subject, KeyPair keyPair, X500Name issuer, IssuerAlternativeNameExtension IANE, BasicConstraintsExtension BCE, KeyUsageExtension KUE) {
        X509SelfSigned selfSignedCert = new X509SelfSigned(certVersion, certValidity, certSerial, subject, keyPair, issuer, IANE, BCE, KUE);
        KeyPairUnit pairUnit = new KeyPairUnit(keyPair.getPrivate(), selfSignedCert);
        keyPairMap.put(keyPairName, pairUnit);
        return null;
    }
    
}
