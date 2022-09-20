// Copyright 2018-2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callouts.xmldsig;

import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.XmlUtils;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.dsig.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public abstract class XmlDsigCalloutBase {
  private static final String _varprefix = "xmldsig_";
  private static final String variableReferencePatternString = "(.*?)\\{([^\\{\\} ]+?)\\}(.*?)";
  private static final Pattern variableReferencePattern =
      Pattern.compile(variableReferencePatternString);
  protected Map properties; // read-only

  public static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

  public XmlDsigCalloutBase(Map properties) {
    this.properties = properties;
  }

  static String varName(String s) {
    return _varprefix + s;
  }

  protected Document getDocument(MessageContext msgCtxt) throws Exception {
    String source = getSimpleOptionalProperty("source", msgCtxt);
    if (source == null) {
      return XmlUtils.parseXml(msgCtxt.getMessage().getContentAsStream());
    }
    String text = (String) msgCtxt.getVariable(source);
    if (text == null) {
      throw new IllegalStateException("source variable resolves to null");
    }
    Document doc = XmlUtils.parseXml(text);
    String reformSignedInfo = getSimpleOptionalProperty("reform-signedinfo", msgCtxt);
    if ("true".equals(reformSignedInfo)) {
      NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
      if (nl.getLength() == 0) {
        throw new RuntimeException("Couldn't find 'Signature' element");
      }
      Element element = (Element) nl.item(0);
      nl = element.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
      if (nl.getLength() == 0) {
        throw new RuntimeException("Couldn't find 'SignedInfo' element");
      }
      Element signedInfo = (Element) nl.item(0);
      removeWhitespaceTextNodes(signedInfo);
    }
    return doc;
  }

  private void removeWhitespaceTextNodes(Node currentNode) {
    // remove descendant text nodes that are empty/whitespace
    NodeList children = currentNode.getChildNodes();
    for (int i = children.getLength() - 1; i >= 0; i--) {
      Node n = (Node) children.item(i);
      if (n.getNodeType() == Node.TEXT_NODE) {
        String t = n.getTextContent();
        if (t == null || t.trim().equals("")) {
          currentNode.removeChild(n);
        }
      } else if (n.getNodeType() == Node.ELEMENT_NODE) {
        removeWhitespaceTextNodes(n);
      }
    }
  }

  protected boolean getDebug() {
    String value = (String) this.properties.get("debug");
    if (value == null) return false;
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  protected String getOutputVar(MessageContext msgCtxt) throws Exception {
    String dest = getSimpleOptionalProperty("output-variable", msgCtxt);
    if (dest == null) {
      return "message.content";
    }
    return dest;
  }

  protected String getSimpleOptionalProperty(String propName, MessageContext msgCtxt) {
    String value = (String) this.properties.get(propName);
    if (value == null) {
      return null;
    }
    value = value.trim();
    if (value.equals("")) {
      return null;
    }
    value = resolvePropertyValue(value, msgCtxt);
    if (value == null || value.equals("")) {
      return null;
    }
    return value;
  }

  protected String getSimpleRequiredProperty(String propName, MessageContext msgCtxt)
      throws IllegalStateException {
    String value = (String) this.properties.get(propName);
    if (value == null) {
      throw new IllegalStateException(propName + " resolves to an empty string");
    }
    value = value.trim();
    if (value.equals("")) {
      throw new IllegalStateException(propName + " resolves to an empty string");
    }
    value = resolvePropertyValue(value, msgCtxt);
    if (value == null || value.equals("")) {
      throw new IllegalStateException(propName + " resolves to an empty string");
    }
    return value;
  }

  // If the value of a property contains any pairs of curlies,
  // eg, {apiproxy.name}, then "resolve" the value by de-referencing
  // the context variables whose names appear between curlies.
  private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      Object v = msgCtxt.getVariable(matcher.group(2));
      if (v != null) {
        sb.append((String) v);
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  protected void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    String error = exc1.toString();
    msgCtxt.setVariable(varName("exception"), error);
    // System.out.printf("Exception: %s\n", error);
    int ch = error.lastIndexOf(':');
    if (ch >= 0) {
      msgCtxt.setVariable(varName("error"), error.substring(ch + 2).trim());
    } else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }

  enum KeyIdentifierType {
    NOT_SPECIFIED,
    X509_CERT_DIRECT,
    X509_CERT_DIRECT_AND_ISSUER_SERIAL,
    // THUMBPRINT,
    // BST_DIRECT_REFERENCE,
    RSA_KEY_VALUE,
    X509_ISSUER_SERIAL;

    static KeyIdentifierType fromString(String s) {
      for (KeyIdentifierType t : KeyIdentifierType.values()) {
        if (t.name().equals(s)) return t;
      }
      return KeyIdentifierType.NOT_SPECIFIED;
    }
  }

  protected KeyIdentifierType getKeyIdentifierType(MessageContext msgCtxt) throws Exception {
    String kitString = getSimpleOptionalProperty("key-identifier-type", msgCtxt);
    if (kitString == null) return KeyIdentifierType.RSA_KEY_VALUE;
    kitString = kitString.trim().toUpperCase();
    KeyIdentifierType t = KeyIdentifierType.fromString(kitString);
    if (t == KeyIdentifierType.NOT_SPECIFIED) {
      msgCtxt.setVariable(varName("warning"), "unrecognized key-identifier-type");
      return KeyIdentifierType.RSA_KEY_VALUE;
    }
    return t;
  }

  enum IssuerNameStyle {
    NOT_SPECIFIED,
    COMMON_NAME,
    DN
  }

  protected IssuerNameStyle getIssuerNameStyle(MessageContext msgCtxt) {
    String insString = getSimpleOptionalProperty("issuer-name-style", msgCtxt);
    if (insString == null) return IssuerNameStyle.COMMON_NAME;
    insString = insString.trim().toUpperCase();
    if (insString.equals("COMMON_NAME")) return IssuerNameStyle.COMMON_NAME;
    if (insString.equals("DN")) return IssuerNameStyle.DN;
    msgCtxt.setVariable(varName("warning"), "unrecognized issuer-name-style");
    return IssuerNameStyle.COMMON_NAME;
  }

  protected String getSigningMethod(MessageContext msgCtxt) throws Exception {
    String signingMethod = getSimpleOptionalProperty("signing-method", msgCtxt);
    if (signingMethod == null) return null;
    signingMethod = signingMethod.trim();
    // warn on invalid values
    if (!signingMethod.toLowerCase().equals("rsa-sha1")
        && !signingMethod.toLowerCase().equals("rsa-sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for signing-method");
      return "rsa-sha256";
    }
    return signingMethod;
  }

  protected String getDigestMethod(MessageContext msgCtxt) throws Exception {
    String digestMethod = getSimpleOptionalProperty("digest-method", msgCtxt);
    if (digestMethod == null) return null;
    digestMethod = digestMethod.trim();
    // warn on invalid values
    if (!digestMethod.toLowerCase().equals("sha1")
        && !digestMethod.toLowerCase().equals("sha256")) {
      msgCtxt.setVariable(varName("WARNING"), "invalid value for digest-method");
      return "sha256";
    }
    return digestMethod;
  }

  protected boolean getOmitCertValidityCheck(MessageContext msgCtxt) throws Exception {
    String value = (String) this.properties.get("omit-certificate-validity-check");
    if (value == null) return false;
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  protected static void checkCertificateValidity(
      X509Certificate certificate, MessageContext msgCtxt) {
    try {
      // check notBefore and notAfter dates
      certificate.checkValidity();
    } catch (CertificateExpiredException cee) {
      throw new RuntimeException("The embedded certificate is expired.");
    } catch (CertificateNotYetValidException cnyve) {
      throw new RuntimeException("The embedded certificate is not yet valid.");
    }
  }

  protected static void emitCertificateInformation(
      X509Certificate certificate, MessageContext msgCtxt) throws InvalidNameException {
    msgCtxt.setVariable(
        varName("cert-notAfter"),
        DateTimeFormatter.ISO_INSTANT.format(certificate.getNotAfter().toInstant()));
    msgCtxt.setVariable(
        varName("cert-notBefore"),
        DateTimeFormatter.ISO_INSTANT.format(certificate.getNotBefore().toInstant()));
    msgCtxt.setVariable(
        varName("cert-subject-cn"), getCommonName(certificate.getSubjectX500Principal()));
    msgCtxt.setVariable(varName("cert-subject"), certificate.getSubjectX500Principal().toString());
    msgCtxt.setVariable(
        varName("cert-issuer-cn"), getCommonName(certificate.getIssuerX500Principal()));
    msgCtxt.setVariable(varName("cert-issuer"), certificate.getIssuerX500Principal().toString());
    msgCtxt.setVariable(varName("cert-serial"), certificate.getSerialNumber().toString(16));
  }

  protected static String reformIndents(String s) {
    return s.trim().replaceAll("([\\r|\\n|\\r\\n] *)", "\n");
  }

  protected static String getCommonName(X500Principal principal) throws InvalidNameException {
    LdapName ldapDN = new LdapName(principal.getName());
    String cn = null;
    for (Rdn rdn : ldapDN.getRdns()) {
      // System.out.println(rdn.getType() + " -> " + rdn.getValue());
      if (rdn.getType().equals("CN")) {
        cn = rdn.getValue().toString();
      }
    }
    return cn;
  }

  protected static Certificate certificateFromEncoded(String encoded) throws KeyException {
    return certificateFromPEM(
        "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----");
  }

  protected static Certificate certificateFromPEM(String certificateString) throws KeyException {
    try {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
      certificateString = reformIndents(certificateString);
      Certificate certificate =
          certFactory.generateCertificate(
              new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8)));
      return certificate;
    } catch (Exception ex) {
      throw new KeyException("cannot instantiate certificate", ex);
    }
  }

  protected static String getThumbprintBase64(X509Certificate certificate)
      throws NoSuchAlgorithmException, CertificateEncodingException {
    return Base64.getEncoder()
        .encodeToString(MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded()));
  }

  protected static String getThumbprintHex(X509Certificate certificate)
      throws NoSuchAlgorithmException, CertificateEncodingException {
    return DatatypeConverter.printHexBinary(
            MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded()))
        .toLowerCase();
  }

  protected static String getThumbprintHexSha256(X509Certificate certificate)
      throws NoSuchAlgorithmException, CertificateEncodingException {
    return DatatypeConverter.printHexBinary(
        MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))
        .toLowerCase();
  }

  protected static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }
}
