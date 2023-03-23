package com.github.monkeywie.proxyee.crt;

import cn.hutool.core.codec.Base64Decoder;
import cn.hutool.core.io.FastByteArrayOutputStream;
import cn.hutool.core.io.IoUtil;

import java.io.*;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class CertUtil {

    private static KeyFactory keyFactory = null;

    private static KeyFactory getKeyFactory() {
        if (keyFactory == null) {
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                // Unexpected anomalies
                throw new IllegalStateException(e);
            }
        }
        return keyFactory;
    }

    /**
     * 生成RSA公私密钥对,长度为2048
     */
    public static KeyPair genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048, new SecureRandom());
        return keyPairGen.genKeyPair();
    }

    /**
     * 从文件加载RSA私钥
     * openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out ca_private.der
     */
    public static PrivateKey loadPriKey(byte[] bts)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bts);
        return getKeyFactory().generatePrivate(privateKeySpec);
    }

    /**
     * 从文件加载RSA私钥
     * openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out ca_private.der
     */
    public static PrivateKey loadPriKey(String path) throws Exception {
        return loadPriKey(Files.readAllBytes(Paths.get(path)));
    }

    /**
     * 从文件加载RSA私钥 openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out
     * ca_private.der
     */
    public static PrivateKey loadPriKey(URI uri) throws Exception {
        return loadPriKey(Paths.get(uri).toString());
    }

    /**
     * 从文件加载RSA私钥
     * openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ca.key -out ca_private.der
     */
    public static PrivateKey loadPriKey(InputStream inputStream)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] bts = new byte[1024];
        int len;
        while ((len = inputStream.read(bts)) != -1) {
            outputStream.write(bts, 0, len);
        }
        inputStream.close();
        outputStream.close();
        return loadPriKey(outputStream.toByteArray());
    }

    /**
     * 从文件加载RSA公钥
     * openssl rsa -in ca.key -pubout -outform DER -out ca_pub.der
     */
    public static PublicKey loadPubKey(byte[] bts) throws Exception {
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bts);
        return getKeyFactory().generatePublic(publicKeySpec);
    }

    /**
     * 从文件加载RSA公钥
     * openssl rsa -in ca.key -pubout -outform DER -out ca_pub.der
     */
    public static PublicKey loadPubKey(String path) throws Exception {
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Files.readAllBytes(Paths.get(path)));
        return getKeyFactory().generatePublic(publicKeySpec);
    }

    /**
     * 从文件加载RSA公钥
     * openssl rsa -in ca.key -pubout -outform DER -out ca_pub.der
     */
    public static PublicKey loadPubKey(URI uri) throws Exception {
        return loadPubKey(Paths.get(uri).toString());
    }

    /**
     * 从文件加载RSA公钥
     * openssl rsa -in ca.key -pubout -outform DER -out ca_pub.der
     */
    public static PublicKey loadPubKey(InputStream inputStream) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] bts = new byte[1024];
        int len;
        while ((len = inputStream.read(bts)) != -1) {
            outputStream.write(bts, 0, len);
        }
        inputStream.close();
        outputStream.close();
        return loadPubKey(outputStream.toByteArray());
    }

    /**
     * 从文件加载证书
     */
    public static X509Certificate loadCert(InputStream inputStream) throws CertificateException, IOException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);
        }finally {
            inputStream.close();
        }
    }

    /**
     * 从文件加载证书
     */
    public static X509Certificate loadCert(String path) throws Exception {
        return loadCert(new FileInputStream(path));
    }

    /**
     * 从文件加载证书
     */
    public static X509Certificate loadCert(URI uri) throws Exception {
        return loadCert(Paths.get(uri).toString());
    }

    /**
     * 读取ssl证书使用者信息
     */
    public static String getSubject(InputStream inputStream) throws Exception {
        X509Certificate certificate = loadCert(inputStream);
        //读出来顺序是反的需要反转下
        List<String> tempList = Arrays.asList(certificate.getIssuerDN().toString().split(", "));
        return IntStream.rangeClosed(0, tempList.size() - 1)
                .mapToObj(i -> tempList.get(tempList.size() - i - 1)).collect(Collectors.joining(", "));
    }

    /**
     * 读取ssl证书使用者信息
     */
    public static String getSubject(X509Certificate certificate) throws Exception {
        //读出来顺序是反的需要反转下
        List<String> tempList = Arrays.asList(certificate.getIssuerDN().toString().split(", "));
        return IntStream.rangeClosed(0, tempList.size() - 1)
                .mapToObj(i -> tempList.get(tempList.size() - i - 1)).collect(Collectors.joining(", "));
    }

    /**
     * 动态生成服务器证书,并进行CA签授
     *
     * @param issuer 颁发机构
     */
    public static X509Certificate genCert(String issuer, PrivateKey caPriKey, Date caNotBefore,
                                          Date caNotAfter, PublicKey serverPubKey,
                                          String... hosts) throws Exception {
        return CertUtilsLoader.generateServerCert(issuer, caPriKey, caNotBefore, caNotAfter, serverPubKey, hosts);
    }

    /**
     * 生成CA服务器证书
     */
    public static X509Certificate genCACert(String subject, Date caNotBefore, Date caNotAfter,
                                            KeyPair keyPair) throws Exception {
        return CertUtilsLoader.generateCaCert(subject, caNotBefore, caNotAfter, keyPair);
    }

    /**
     * 设置所使用的生成器名称.
     * @param generatorName 欲使用的生成器所属名称, 如果为 null 则恢复默认生成器.
     * @throws NoSuchElementException 如果指定名称不存在所属生成器则抛出该异常.
     */
    public static void setCertGenerator(String generatorName) {
        CertUtilsLoader.setSelectionGenerator(
                generatorName == null ? CertUtilsLoader.DEFAULT_GENERATOR_NAME : generatorName);
    }

    /**
     * 获取当前所选择的生成器名称.
     * @return 返回指定要使用的生成器名称.
     */
    public static String getCertGenerator() {
        return CertUtilsLoader.getCurrentSelectionGenerator();
    }

    /**
     * 获取证书集合
     * @param publicKey
     * @return
     * @throws CertificateException
     * @throws FileNotFoundException
     */
    public static List<X509Certificate> loadCertificateList(String publicKey) throws CertificateException, FileNotFoundException {
        InputStream inputStream = new ByteArrayInputStream(publicKey.getBytes(StandardCharsets.UTF_8));
        return loadCertificateList(inputStream);
    }

    /**
     * 获取证书集合
     * @param inputStream
     * @return
     * @throws CertificateException
     * @throws FileNotFoundException
     */
    public static List<X509Certificate> loadCertificateList(InputStream inputStream) throws CertificateException, FileNotFoundException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificateList= (List<X509Certificate>) fact.generateCertificates(inputStream);
        return certificateList;
    }

    /**
     * 真私钥构造
     * @param inputStream
     * @param algo
     * @return
     * @throws Exception
     */
    public static PrivateKey loadPrivateKey(InputStream inputStream, String algo) throws Exception{
        String privateKey = IoUtil.read(inputStream, Charset.defaultCharset());
        return loadPrivateKey(privateKey,algo);
    }

    /**
     * 真私钥构造
     * @param privateKey
     * @param algo
     * @return
     * @throws Exception
     */
    public static PrivateKey loadPrivateKey(String privateKey, String algo) throws Exception{
        //openssl pkcs8 -topk8 -inform PEM -outform PEM -in 8061958_sdsoft.topcio.cn.key -out a.key -nocrypt
        // 获取密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(algo);
        // 构建密钥规范 进行Base64解码
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64Decoder.decode(privateKey));
        // 生成私钥
        return keyFactory.generatePrivate(spec);
    }

    public static void main(String[] args) throws Exception {
        //生成ca证书和私钥
        KeyPair keyPair = CertUtil.genKeyPair();
        File caCertFile = new File("./ca.crt");
        if (caCertFile.exists()) {
            caCertFile.delete();
        }

        Files.write(Paths.get(caCertFile.toURI()),
                CertUtil.genCACert(
                        "C=CN, ST=GD, L=SZ, O=lee, OU=study, CN=Proxyee",
                        new Date(),
                        new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(3650)),
                        keyPair)
                        .getEncoded());

        File caPriKeyFile = new File("./ca_private.der");
        if (caPriKeyFile.exists()) {
            caPriKeyFile.delete();
        }

        Files.write(caPriKeyFile.toPath(),
                new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()).getEncoded());
    }
}
