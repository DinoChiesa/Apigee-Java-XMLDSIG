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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Validate extends XmlDsigCalloutBase implements Execution {

  public Validate(Map properties) {
    super(properties);
  }

  private static PublicKey decodePublicKey(String publicKeyPemString)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    PEMParser pr = new PEMParser(new StringReader(publicKeyPemString));
    Object o = pr.readObject();
    if (o instanceof SubjectPublicKeyInfo) {
      SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) o;
      RSAPublicKey pubKey = RSAPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey());

      PublicKey publicKey =
          KeyFactory.getInstance("RSA")
              .generatePublic(
                  new RSAPublicKeySpec(pubKey.getModulus(), pubKey.getPublicExponent()));

      return publicKey;
    }
    throw new IllegalStateException("Didn't find an RSA Public Key");
  }

  private PublicKey getPublicKey(MessageContext msgCtxt) throws Exception {
    String publicKeyPemString = getSimpleOptionalProperty("public-key", msgCtxt);
    if (publicKeyPemString == null) return null;
    publicKeyPemString = publicKeyPemString.trim();

    // clear any leading whitespace on each line
    publicKeyPemString = publicKeyPemString.replaceAll("([\\r|\\n] +)", "\n");
    return decodePublicKey(publicKeyPemString);
  }

  private String getCertificateThumbprint(MessageContext msgCtxt) throws Exception {
    String thumbprint = getSimpleOptionalProperty("certificate-thumbprint", msgCtxt);
    if (thumbprint == null) return null;
    thumbprint = thumbprint.trim();
    return thumbprint;
  }

  private static Element getXmlDsigElementByPath(Element subtreeRoot, String path)
      throws Exception {
    String[] parts = path.split("/");
    Element currentElement = subtreeRoot;
    for (int i = 0; i < parts.length; i++) {
      NodeList nl = currentElement.getElementsByTagNameNS(XMLSignature.XMLNS, parts[i]);
      if (nl.getLength() == 0) {
        throw new RuntimeException(String.format("Couldn't find '%s' element", parts[i]));
      }
      currentElement = (Element) nl.item(0);
    }
    return currentElement;
  }

  private static boolean validate_RSA(Document doc, ValidateConfiguration config) throws Exception {

    // Validate just the first signature. Will not handle multiple
    // distinct signatures.
    Element signatureElement = getXmlDsigElementByPath(doc.getDocumentElement(), "Signature");

    if ((config.signingMethod != null) || (config.digestMethod != null)) {
      Element signedInfo = getXmlDsigElementByPath(signatureElement, "SignedInfo");
      if (config.signingMethod != null) {
        Element signatureMethod = getXmlDsigElementByPath(signedInfo, "SignatureMethod");
        String algorithm = signatureMethod.getAttribute("Algorithm");
        if ((config.signingMethod.equals("rsa-sha1") && !RSA_SHA1.equals(algorithm))
            || (config.signingMethod.equals("rsa-sha256") && !RSA_SHA256.equals(algorithm))) {
          throw new RuntimeException("Unacceptable SignatureMethod Algorithm");
        }
      }

      if (config.digestMethod != null) {
        Element digestMethod = getXmlDsigElementByPath(signedInfo, "Reference/DigestMethod");
        String algorithm = digestMethod.getAttribute("Algorithm");
        if ((config.digestMethod.equals("sha1") && !DigestMethod.SHA1.equals(algorithm))
            || (config.digestMethod.equals("sha256") && !DigestMethod.SHA256.equals(algorithm))) {
          throw new RuntimeException("Unacceptable DigestMethod Algorithm");
        }
      }
    }
    PublicKey publicKey = null;
    if (config.keyIdentifierType == KeyIdentifierType.X509_CERT_DIRECT) {
      // obtain public key from cert at this xpath: Signature/KeyInfo/X509Data/X509Certificate
      Element x509CertElement =
          getXmlDsigElementByPath(signatureElement, "KeyInfo/X509Data/X509Certificate");

      String certString =
          "-----BEGIN CERTIFICATE-----\n"
              + x509CertElement.getTextContent()
              + "\n-----END CERTIFICATE-----";

      X509Certificate embeddedCertificate = (X509Certificate) certificateFromPEM(certString);
      String thumbprint_sha1 = getThumbprintHex(embeddedCertificate);
      if (!thumbprint_sha1.equals(config.certificateThumbprint_sha1)) {
        throw new RuntimeException("Untrusted thumbprint on certificate");
      }
      publicKey = embeddedCertificate.getPublicKey();
    } else {
      // KeyIdentifierType.RSA_KEY_VALUE
      if (config.publicKey == null) {
          throw new IllegalStateException("the configuration does not supply a public key");
      }
      publicKey = config.publicKey;
    }
    KeySelector ks = KeySelector.singletonKeySelector(publicKey);
    DOMValidateContext vc = new DOMValidateContext(ks, signatureElement);
    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    XMLSignature signature = signatureFactory.unmarshalXMLSignature(vc);
    return signature.validate(vc);
  }

  static class ValidateConfiguration {
    public PublicKey publicKey;
    public String certificateThumbprint_sha1;
    public String signingMethod;
    public String digestMethod;
    public KeyIdentifierType keyIdentifierType;

    public ValidateConfiguration() {
      keyIdentifierType = KeyIdentifierType.RSA_KEY_VALUE;
    }

    public ValidateConfiguration withKey(PublicKey key) {
      this.publicKey = key;
      return this;
    }

    public ValidateConfiguration withKeyIdentifierType(KeyIdentifierType kit) {
      this.keyIdentifierType = kit;
      return this;
    }

    public ValidateConfiguration withCertificateThumbprint(String certificateThumbprint) {
      this.certificateThumbprint_sha1 = certificateThumbprint;
      return this;
    }

    public ValidateConfiguration withSigningMethod(String signingMethod) {
      this.signingMethod = signingMethod;
      return this;
    }

    public ValidateConfiguration withDigestMethod(String digestMethod) {
      this.digestMethod = digestMethod;
      return this;
    }
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      Document document = getDocument(msgCtxt);
      ValidateConfiguration validateConfiguration =
          new ValidateConfiguration()
              .withKeyIdentifierType(getKeyIdentifierType(msgCtxt))
              .withKey(getPublicKey(msgCtxt))
              .withCertificateThumbprint(getCertificateThumbprint(msgCtxt))
              .withSigningMethod(getSigningMethod(msgCtxt))
              .withDigestMethod(getDigestMethod(msgCtxt));

      PublicKey publicKey = getPublicKey(msgCtxt);
      boolean isValid = validate_RSA(document, validateConfiguration);
      msgCtxt.setVariable(varName("valid"), isValid);
      return ExecutionResult.SUCCESS;
    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      if (getDebug()) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
  }
}
