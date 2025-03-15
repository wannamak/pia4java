package pia4java;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PemCertificateLoader {
  public List<Certificate> loadCertificates(Path pemCertificateFile) throws IOException, CertificateException {
    String pemContent = new String(Files.readAllBytes(pemCertificateFile));
    return readCertificates(pemContent);
  }

  private List<Certificate> readCertificates(String pemContent) throws CertificateException {
    List<Certificate> certificates = new ArrayList<>();
    Pattern certPattern = Pattern.compile(
        "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        Pattern.DOTALL
    );
    Matcher matcher = certPattern.matcher(pemContent);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    while (matcher.find()) {
      String certContent = matcher.group(1).replaceAll("\\s", "");
      byte[] decodedCert = Base64.getDecoder().decode(certContent);

      Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(decodedCert));
      certificates.add(certificate);
    }

    return certificates;
  }
}
