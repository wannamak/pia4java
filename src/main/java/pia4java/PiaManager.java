package pia4java;

import com.google.common.base.MoreObjects;
import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import com.google.protobuf.TextFormat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class PiaManager {
  private static final Logger logger = Logger.getLogger(PiaManager.class.getCanonicalName());
  private static final String PIA_GET_TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token";
  private static final String PIA_ADD_KEY_URL_FORMAT_SPEC = "https://%s:%s/addKey";
  private static final File PIA_WIREGUARD_CONF_PATH = new File("/etc/wireguard/pia.conf");
  private final Proto.PiaConfig config;
  private final PiaTrustManager trustManager;

  public static void main(String args[]) throws Exception {
     Preconditions.checkState(args.length == 2,
         "up|down|restart");
     PiaManager piaManager = new PiaManager(loadConfig(args[0]));
     switch (args[1]) {
       case "up" -> piaManager.connect();
       case "down" -> piaManager.disconnect();
       case "restart" -> { piaManager.disconnect(); piaManager.connect(); }
       default -> throw new IllegalStateException("Unrecognized command " + args[1]);
     }
  }

  public PiaManager(Proto.PiaConfig config) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
    this.config = config;
    this.trustManager = new pia4java.PiaTrustManager();
  }

  public void connect() throws IOException, NoSuchAlgorithmException, KeyManagementException, InterruptedException {
    String[] allowedIps = new String[0];
    if (config.hasTargetDomain()) {
      CommandResult result = runCommand("",
          new String[]{"dig", "+short", config.getTargetDomain()});
      Preconditions.checkState(result.exitValue == 0, result);
      allowedIps = result.stdout.split("\\n");
    }

    String token = retrieveToken();

    CommandResult result = runCommand("", new String[] { "wg", "genkey" });
    Preconditions.checkState(result.exitValue == 0, result);
    String privateKey = result.stdout;
    logger.fine("Private key [" + privateKey + "]");

    result = runCommand(privateKey, new String[] { "wg", "pubkey" });
    Preconditions.checkState(result.exitValue == 0, result);
    String publicKey = result.stdout;
    logger.fine("Public  key [" + publicKey + "]");

    AddKeyResponse addKeyResponse = addKey(token, publicKey);
    logger.fine("Add key     [" + addKeyResponse + "]");

    String wireguardConfiguration = addKeyResponse.getWireGuardConfiguration(privateKey, allowedIps);

    Files.deleteIfExists(PIA_WIREGUARD_CONF_PATH.toPath());
    Files.writeString(PIA_WIREGUARD_CONF_PATH.toPath(), wireguardConfiguration);

    result = runCommand("", new String[] { "wg-quick", "up", "pia" });
    Preconditions.checkState(result.exitValue == 0, result);
  }

  public void disconnect() throws IOException, InterruptedException {
    CommandResult result = runCommand("", new String[] { "wg-quick", "down", "pia" });
    if (result.exitValue != 0
        && result.stderr.contains("is not a WireGuard interface")) {
      return;
    }
    Preconditions.checkState(result.exitValue == 0, result);
  }

  private static class TokenResponse {
    String token;
  }

  public String retrieveToken() throws IOException, NoSuchAlgorithmException, KeyManagementException {
    Map<String, String> params = Maps.newLinkedHashMap();
    params.put("username", config.getPiaUsername());
    params.put("password", config.getPiaPassword());
    TokenResponse tokenResponse =
        new pia4java.SimpleRestClient<TokenResponse>(trustManager).post(
            params, PIA_GET_TOKEN_URL, TokenResponse.class);
    return tokenResponse.token;
  }

  public static class AddKeyResponse {
    String status;
    String serverKey;
    int serverPort;
    String serverIp;
    String serverVip;
    String peerIp;
    String peerPubkey;
    String[] dnsServers;

    @Override
    public String toString() {
      return MoreObjects.toStringHelper(this)
          .add("status", status)
          .add("serverKey", serverKey)
          .add("serverPort", serverPort)
          .add("serverIp", serverIp)
          .add("serverVip", serverVip)
          .add("peerIp", peerIp)
          .add("peerPubkey", peerPubkey)
          .add("dnsServers", Arrays.toString(dnsServers))
          .omitNullValues()
          .toString();
    }

    String getWireGuardConfiguration(String privateKey, String[] allowedIps) {
      String allowedIpsCombined = "";
      if (allowedIps.length > 0) {
        for (int i = 0; i < allowedIps.length; i++) {
          if (i > 0) {
            allowedIpsCombined += ", ";
          }
          allowedIpsCombined += allowedIps[i] + "/32";
        }
      } else {
        allowedIpsCombined = "0.0.0.0/0";
      }
      return String.format(
          "[Interface]\n" +
          "Address = %s\n" +
          "PrivateKey = %s\n" +
          "[Peer]\n" +
          "PublicKey = %s\n" +
          "AllowedIPs = %s\n" +
          "Endpoint = %s:%d\n",
          peerIp,
          privateKey,
          serverKey,
          allowedIpsCombined,
          serverIp,
          serverPort
      );
    }
  }

  private AddKeyResponse addKey(String token, String publicKey)
      throws IOException, NoSuchAlgorithmException, KeyManagementException {
    Map<String, String> params = Map.of("pt", token, "pubkey", publicKey);
    pia4java.SimpleRestClient<AddKeyResponse> client = new pia4java.SimpleRestClient<>(trustManager);
    AddKeyResponse response =
        client.get(params,
            PIA_ADD_KEY_URL_FORMAT_SPEC.formatted(
                config.getPiaWireguardServer(),
                config.getPiaWireguardPort()),
            AddKeyResponse.class);
    Preconditions.checkState(response.status.equals("OK"), response.status);
    return response;
  }

  private static class CommandResult {
    final String stdout;
    final String stderr;
    final int exitValue;
    CommandResult(String stdout, String stderr, int exitValue) {
      this.stdout = stdout;
      this.stderr = stderr;
      this.exitValue = exitValue;
    }

    @Override
    public String toString() {
      return MoreObjects.toStringHelper(this)
          .add("stdout", stdout)
          .add("stderr", stderr)
          .add("exitValue", exitValue)
          .toString();
    }
  }

  private static final int WAIT_FOR_PROCESS_SECONDS = 5;

  private CommandResult runCommand(String inputToCommand, String[] command)
      throws IOException, InterruptedException {
    Runtime runtime = Runtime.getRuntime();
    Process process = runtime.exec(command);

    if (!inputToCommand.isEmpty()) {
      OutputStream outputStream = process.getOutputStream();
      outputStream.write(inputToCommand.getBytes(StandardCharsets.UTF_8));
      outputStream.close();
    }

    String stderr = new String(process.getErrorStream().readAllBytes()).stripTrailing();
    String stdout = new String(process.getInputStream().readAllBytes()).stripTrailing();
    Preconditions.checkState(process.waitFor(WAIT_FOR_PROCESS_SECONDS, TimeUnit.SECONDS));
    return new CommandResult(stdout, stderr, process.exitValue());
  }

  private static Proto.PiaConfig loadConfig(String path) throws IOException {
    Proto.PiaConfig.Builder builder = pia4java.Proto.PiaConfig.newBuilder();
    logger.fine("Reading config from " + path);
    try (BufferedReader br = new BufferedReader(new FileReader(path))) {
      TextFormat.merge(br, builder);
    }
    return builder.build();
  }
}
