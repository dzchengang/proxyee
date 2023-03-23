package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.crt.CertUtil;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class CertTest {
    public static void main(String[] args) throws Exception {
        List<X509Certificate> certificates = CertUtil.loadCertificateList(new FileInputStream("D:\\test_data\\app\\cert\\7603389_lefuapp.lefuyunma.com.pem"));

        for (X509Certificate certificate:certificates){
           System.out.println(certificate.getPublicKey());
           System.out.println(certificate.getSignature());

        }

        PrivateKey privateKey = CertUtil.loadPrivateKey(new FileInputStream("D:\\test_data\\app\\cert\\key_out.key"),"RSA");

System.out.println(privateKey.getAlgorithm());
    }
}
