package pia4java;

import com.google.common.base.Preconditions;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class PiaTrustManager implements X509TrustManager {
  private final Logger logger = Logger.getLogger(getClass().getCanonicalName());

  // https://github.com/pia-foss/manual-connections/blob/master/ca.rsa.4096.crt
  private static final String PIA_TRUST_STORE = "props/ca.rsa.4096.crt";

  private final X509TrustManager trustManager;

  public PiaTrustManager() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    KeyStore keyStore = loadDefaultJavaKeystore();
    List<Certificate> certificates = new pia4java.PemCertificateLoader().loadCertificates(Paths.get(PIA_TRUST_STORE));

    for (int i = 0; i < certificates.size(); i++) {
      keyStore.setCertificateEntry("cert-" + i, certificates.get(i));
    }

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(keyStore);

    TrustManager[] trustManagers = tmf.getTrustManagers();
    Preconditions.checkState(trustManagers.length > 0, "No trust managers found");
    Preconditions.checkState(trustManagers[0] instanceof X509TrustManager,
        "Unexpected trust manager type: " + trustManagers[0].getClass().getName());

    trustManager = (X509TrustManager) trustManagers[0];
  }

  private KeyStore loadDefaultJavaKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
    String javaHome = System.getProperty("java.home");
    String cacertsPath = System.getProperty(
        "javax.net.ssl.keyStore", javaHome + "/lib/security/cacerts");
    String cacertsPassword = System.getProperty(
        "javax.net.ssl.keyStorePassword", "changeit");
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    try (FileInputStream fis = new FileInputStream(cacertsPath)) {
      keyStore.load(fis, cacertsPassword.toCharArray());
    }
    return keyStore;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    trustManager.checkClientTrusted(chain, authType);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    trustManager.checkServerTrusted(chain, authType);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return Arrays.copyOf(trustManager.getAcceptedIssuers(), trustManager.getAcceptedIssuers().length);
  }
}
