package org.certificatetransparency.ctlog.utils;

import java.io.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Base64;
import org.certificatetransparency.ctlog.CertificateInfo;
import org.certificatetransparency.ctlog.LogInfo;
import org.certificatetransparency.ctlog.LogSignatureVerifier;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.serialization.CTConstants;
import org.certificatetransparency.ctlog.serialization.CryptoDataLoader;
import org.certificatetransparency.ctlog.serialization.Deserializer;

import com.google.common.io.Files;
import com.google.protobuf.InvalidProtocolBufferException;

/** Utility for verifying a log's signature from an SCT. */
public class VerifySignature {
  public static void main(String[] args) throws IOException {
    if (args.length < 3) {
      System.out.println(
          String.format(
              "Usage: %s <certificates chain> <sct> <log public key>",
              VerifySignature.class.getSimpleName()));
      System.out.println(
          "<sct> can be set to 'null' in which case embedded SCTs in the leaf certificate will be extracted and verified.");
      System.out.println(
          "<log public key> may point to a directory containing multiple public keys which will be matched agains the correct SCT to verify.");
      return;
    }

    String pemFile = args[0];
    String sctFile = args[1];
    String logPublicKeyFileorDir = args[2];

    List<Certificate> certs = CryptoDataLoader.certificatesFromFile(new File(pemFile));
    if (certs.isEmpty()) {
      System.out.println("ERROR: Certificates chain does not contain any certificates.");
      System.exit(-1);
    }
    byte[] sctBytes = null;
    List<Ct.SignedCertificateTimestamp> scts = new ArrayList<>();
    if ("null".equals(sctFile)) {
      System.out.println("No SCTs as input, assuming there are some in the cert");
      X509Certificate leafCert = (X509Certificate) certs.get(0);
      if (CertificateInfo.hasEmbeddedSCT(leafCert)) {
        // Get the SCT(s) from the certificate
        System.out.println("The leafcert does have some SCTs");
        scts = parseSCTsFromCert(leafCert);
      }
    } else {
      sctBytes = Files.toByteArray(new File(sctFile));
      try {
        scts.add(Ct.SignedCertificateTimestamp.parseFrom(sctBytes));
      } catch (InvalidProtocolBufferException e) {
        System.out.println("Not a protocol buffer. Trying reading as binary");
        scts.add(Deserializer.parseSCTFromBinary(new ByteArrayInputStream(sctBytes)));
      }
    }
    if (scts.isEmpty()) {
      System.out.println(
          "ERROR: Certificate does not contain SCTs, and no SCTs provided as input.");
      System.exit(-1);
    }

    // Read log keys
    Map<String, LogInfo> logInfos = readLogKeys(logPublicKeyFileorDir);

    // Verify the SCTs one at a time
    boolean success = true;
    for (Ct.SignedCertificateTimestamp sct : scts) {
      String id = Base64.toBase64String(sct.getId().getKeyId().toByteArray());
      System.out.println("SCT to verify with keyID: " + id);
      System.out.println(sct.toString());
      LogInfo logInfo = logInfos.get(id);
      if (logInfo == null) {
        System.out.println(
            "No log with ID: "
                + id
                + " found among loaded log keys, skipping verification with FAILURE");
        success = false;
      } else {
        LogSignatureVerifier verifier = new LogSignatureVerifier(logInfo);
        if (verifier.verifySignature(sct, certs)) {
          System.out.println("Signature verified OK.");
        } else {
          System.out.println("Signature verification FAILURE.");
          success = false;
        }
      }
    }
    if (!success) {
      System.exit(-1);
    }
  }

  public static List<Ct.SignedCertificateTimestamp> parseSCTsFromCert(X509Certificate leafCert)
      throws IOException {
    byte[] bytes = leafCert.getExtensionValue(CTConstants.SCT_CERTIFICATE_OID);
    List<Ct.SignedCertificateTimestamp> scts = new ArrayList<>();
    ASN1Primitive p = ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(bytes).getOctets());
    DEROctetString o = (DEROctetString) p;
    // These are serialized SCTs, we must de-serialize them into an array with one SCT each
    Ct.SignedCertificateTimestamp[] sctsFromCert = parseSCTsFromCertExtension(o.getOctets());
    for (Ct.SignedCertificateTimestamp signedCertificateTimestamp : sctsFromCert) {
      scts.add(signedCertificateTimestamp);
    }
    return scts;
  }

  /**
   * Reads CT log public key from a file, or all keys that reside in a directory
   *
   * @param logPublicKeyFileorDir a public key PEM file or a directory with public key PEM files
   * @return Map with id, LogInfo, a LogInfo can thus be obtained from the map if you know the log
   *     ID
   */
  private static Map<String, LogInfo> readLogKeys(String logPublicKeyFileorDir) {
    Map<String, LogInfo> logInfos = new HashMap<>();
    File file = new File(logPublicKeyFileorDir);
    if (file.isDirectory()) {
      // Read all public keys in the directory into a hashmap
      // then choose the correct one based on Log ID
      File[] files = file.listFiles();
      for (File keyfile : files) {
        LogInfo logInfo = LogInfo.fromKeyFile(keyfile.getAbsolutePath());
        String id = Base64.toBase64String(logInfo.getID());
        System.out.println("Log ID: " + id + ", " + keyfile.getAbsolutePath());
        if (logInfos.put(id, logInfo) != null) {
          System.out.println(
              "A logInfo with ID "
                  + id
                  + " was already present, replacing the old entry with this one.");
        }
      }
    } else {
      LogInfo logInfo = LogInfo.fromKeyFile(logPublicKeyFileorDir);
      System.out.println(
          "Log ID: " + Base64.toBase64String(logInfo.getID()) + ", " + file.getAbsolutePath());
      logInfos.put(Base64.toBase64String(logInfo.getID()), logInfo);
    }
    return logInfos;
  }

  private static Ct.SignedCertificateTimestamp[] parseSCTsFromCertExtension(byte[] extensionvalue)
      throws IOException {
    List<Ct.SignedCertificateTimestamp> sctList = new ArrayList<>();
    ByteArrayInputStream bis = new ByteArrayInputStream(extensionvalue);

    // The first two bytes represent the total length (which we ignore)
    int totalLength = readUint16(bis);

    // Continue reading while there are at least 2 bytes (for the next opaque16 length)
    while (bis.available() > 2) {
      byte[] sctBytes = readOpaque16(bis);
      sctList.add(Deserializer.parseSCTFromBinary(new ByteArrayInputStream(sctBytes)));
    }
    return sctList.toArray(new Ct.SignedCertificateTimestamp[0]);
  }

  // Helper method to read uint16
  private static int readUint16(InputStream in) throws IOException {
    int high = in.read();
    int low = in.read();

    if (high < 0 || low < 0) {
      throw new IOException("EOF while reading uint16");
    }

    return (high << 8) | low;
  }

  private static byte[] readOpaque16(InputStream is) throws IOException {
    int length = readUint16(is);
    byte[] data = new byte[length];
    int totalRead = 0;
    while (totalRead < length) {
      int bytesRead = is.read(data, totalRead, length - totalRead);
      if (bytesRead < 0) {
        throw new EOFException("Unexpected end of stream while reading opaque16");
      }
      totalRead += bytesRead;
    }
    return data;
  }
}
