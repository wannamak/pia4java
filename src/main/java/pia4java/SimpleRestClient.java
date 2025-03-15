package pia4java;

import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class SimpleRestClient<T> {
  private final Logger logger = Logger.getLogger(getClass().getCanonicalName());
  private final TrustManager trustManager;

  private enum Method {
    GET,
    POST
  }

  public SimpleRestClient(TrustManager trustManager) {
    this.trustManager = trustManager;
  }

  public T get(Map<String, String> parameters, String urlString, Class resultClazz)
      throws IOException, NoSuchAlgorithmException, KeyManagementException {
    return invoke(Method.GET, parameters, urlString, resultClazz);
  }

  public T post(Map<String, String> parameters, String urlString, Class resultClazz)
      throws IOException, NoSuchAlgorithmException, KeyManagementException {
    return invoke(Method.POST, parameters, urlString, resultClazz);
  }

  private T invoke(Method method, Map<String, String> parameters, String urlString, Class resultClazz)
      throws IOException, NoSuchAlgorithmException, KeyManagementException {
    List<String> keyValues = new ArrayList<>();
    for (String key : parameters.keySet()) {
      keyValues.add(String.format("%s=%s",
          URLEncoder.encode(key, StandardCharsets.UTF_8),
          URLEncoder.encode(parameters.get(key), StandardCharsets.UTF_8)));
    }
    String postDataString = Joiner.on('&').join(keyValues);
    byte[] postData = null;
    if (method == Method.POST) {
      postData = postDataString.getBytes(StandardCharsets.UTF_8);
    } else {
      urlString = urlString + "?" + postDataString;
    }

    SSLContext sslContext = SSLContext.getInstance("SSL");
    sslContext.init(null, new TrustManager[]{trustManager}, null);
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    HttpsURLConnection.setFollowRedirects(false);
    URL url = new URL(urlString);
    HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
    connection.setConnectTimeout(5000); // 5 seconds connectTimeout
    connection.setReadTimeout(5000); // 5 seconds socketTimeout
    if (method == Method.POST) {
      connection.setRequestMethod("POST");
      connection.setDoOutput(true);
      connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      connection.setRequestProperty("Content-Length", Integer.toString(postData.length));
    }
    connection.setUseCaches(false);

    String content;
    try (Closeable ignored = connection::disconnect) {
      if (method == Method.POST) {
        connection.getOutputStream().write(postData);
      } else {
        connection.connect();
      }
      Preconditions.checkState(connection.getResponseCode() == HttpURLConnection.HTTP_OK,
          "Non-OK response " + connection.getResponseCode());
      InputStream inputStream = connection.getInputStream();
      StringBuilder sb = new StringBuilder();
      for (int c; (c = inputStream.read()) >= 0;) {
        sb.append((char) c);
      }
      content = sb.toString();
    }

    logger.fine("Retrieved [" + content + "]");

    Gson gson = new GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
        .create();
    return (T) gson.fromJson(content, resultClazz);
  }
}
