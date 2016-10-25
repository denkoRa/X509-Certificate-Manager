/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package x509certificate;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;
import sun.misc.BASE64Encoder;
import sun.security.util.DerValue;

import sun.security.x509.*;
import static x509certificate.CSR.CSRMap;
import static x509certificate.KeyPairUnit.keyPairMap;

/**
 *
 * @author Rade
 */
public class X509SelfSigned extends X509Certificate {

    public static Map<String, Certificate> SignedCertificates = new HashMap<>();

    private X509CertImpl impl = null;
    private X509CertInfo info = null;

    public X509SelfSigned(X509CertImpl impl, X509CertInfo info) {
        this.impl = impl;
        this.info = info;
    }

    

    public X509SelfSigned(CertificateVersion cv, CertificateValidity cVal, CertificateSerialNumber csn,
            X500Name subject, KeyPair kp, X500Name issuer, IssuerAlternativeNameExtension ian,
            BasicConstraintsExtension bce, KeyUsageExtension kue) {

        try {
            info = new X509CertInfo();
            info.set(X509CertInfo.VERSION, cv);
            info.set(X509CertInfo.VALIDITY, cVal);
            info.set(X509CertInfo.SERIAL_NUMBER, csn);
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid)));
            info.set(X509CertInfo.SUBJECT, subject);
            info.set(X509CertInfo.KEY, new CertificateX509Key(kp.getPublic()));
            info.set(X509CertInfo.ISSUER, issuer);
            impl = new X509CertImpl(info);
            CertificateExtensions exts = new CertificateExtensions();
            boolean ext = false;
            if (ian != null) {
                exts.set(IssuerAlternativeNameExtension.IDENT, ian);
                ext = true;
            }
            if (bce != null) {
                exts.set(BasicConstraintsExtension.IDENT, bce);
                ext = true;
            }
            if (kue != null) {
                exts.set(KeyUsageExtension.IDENT, kue);
                ext = true;
            }
            if (ext) {
                info.set(X509CertInfo.EXTENSIONS, exts);
            }

            impl.sign(kp.getPrivate(), "SHA1withRSA");
        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.

    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getVersion() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getIssuerDN();
    }

    @Override
    public Principal getSubjectDN() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getSubjectDN();
    }

    @Override
    public Date getNotBefore() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getNotAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getTBSCertificate();
    }

    @Override
    public byte[] getSignature() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getSignature();
    }

    @Override
    public String getSigAlgName() {
        // throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getSigAlgParams();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getIssuerUniqueID();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getSubjectUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getKeyUsage();
    }

    @Override
    public int getBasicConstraints() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getBasicConstraints();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getEncoded();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.

    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String toString() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        //if (!signed) return info.toString();
        return impl.toString();
    }

    @Override
    public PublicKey getPublicKey() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getPublicKey();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.hasUnsupportedCriticalExtension();
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getCriticalExtensionOIDs();
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getNonCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        return impl.getExtensionValue(oid);
    }

    public void setInfo(X509CertInfo info) {
        this.info = info;
    }

    public void setImpl(X509CertImpl impl) {
        this.impl = impl;
    }

    public X509CertImpl getImpl() {
        return impl;
    }

    public X509CertInfo getInfo() {
        return info;
    }

    public static void signCertificate(String signedCertName, String csrName, String kpName) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        X509SelfSigned signer = (X509SelfSigned) keyPairMap.get(kpName).getCert();
        X500Name subject = new X500Name(signer.getSubjectDN().getName());
        CSR csr = CSRMap.get(csrName);
        String toSign = CSR.SubjectAndIssuerMap.get(csrName);

        X509CertImpl signedCert = new X509CertImpl(X509SelfSigned.getInfo(subject, keyPairMap.get(toSign)));
        signedCert.sign(keyPairMap.get(kpName).getPk(), "SHA1withRSA");
        keyPairMap.remove(toSign);
        SignedCertificates.put(signedCertName, signedCert);

    }

    public static void exportKeys(String filePath, char[] password, String kpName, boolean withAES) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        Certificate[] cc = new Certificate[1];
        cc[0] = keyPairMap.get(kpName).getCert();
        keyStore.setKeyEntry(kpName, keyPairMap.get(kpName).getPk(), password, cc);
        FileOutputStream fos = new FileOutputStream(filePath);
        keyStore.store(fos, password);
        fos.close();
        if (withAES) {
            AESFileEncryption AES = new AESFileEncryption();
            AES.encrypt(filePath);
        }
    }

    public static void importKeys(char[] password, String filePath, String certName, String importedName, boolean withAES) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        AESFileEncryption AES = null;
        if (withAES)
             AES = new AESFileEncryption();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        
        
        if (withAES) keyStore.load(AES.getDecryptedInputStream(filePath), password);
        else keyStore.load(new FileInputStream(filePath), password);
        
        
        Certificate certificate =  keyStore.getCertificate(certName);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(certName, password);
        X509CertInfo x509CertInfo = new X509CertInfo(new DerValue(certificate.getEncoded()).data.getDerValue());
	X509CertImpl x509CertImpl = new X509CertImpl(x509CertInfo);
        X509SelfSigned x509SelfSigned = new X509SelfSigned(x509CertImpl, x509CertInfo);
        keyPairMap.put(importedName, new KeyPairUnit(privateKey, x509SelfSigned));
    }

    public static X509CertInfo getInfo(X500Name issuer, KeyPairUnit kpu) throws CertificateException, IOException {
        X509SelfSigned ssCert = (X509SelfSigned) kpu.getCert();
        ssCert.getInfo().set(X509CertInfo.ISSUER, issuer);
        return ssCert.getInfo();
    }

    public static void exportCertificate(String filePath, Certificate cert) throws CertificateEncodingException, FileNotFoundException, IOException {
        BASE64Encoder bs64 = new BASE64Encoder();
        byte[] content = cert.getEncoded();
        FileOutputStream fos = new FileOutputStream(filePath);
        bs64.encode(content, fos);
    }

}
