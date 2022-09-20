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
import com.google.apigee.util.ThrowingSideEffect;
import com.google.apigee.util.ThrowingSupplier;
import com.google.apigee.xml.Namespaces;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import javax.naming.InvalidNameException;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class Sign extends XmlDsigCalloutBase implements Execution {

  public Sign(Map properties) {
    super(properties);
  }

  private static String sign_RSA(Document doc, SignConfiguration config, MessageContext msgCtxt)
      throws InstantiationException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          KeyException, MarshalException, XMLSignatureException, TransformerException,
          CertificateEncodingException, InvalidNameException {
    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");

    ThrowingSideEffect<InvalidNameException> maybeCheckCert =
        () -> {
          if (config.certificate == null) {
            throw new IllegalStateException("missing certificate");
          }
          emitCertificateInformation(config.certificate, msgCtxt);

          if (!config.omitCertValidityCheck) {
            checkCertificateValidity(config.certificate, msgCtxt);
          }
        };

    ThrowingSupplier<Element, InvalidNameException> issuerSerialMaker =
        () -> {
          Element x509IssuerName = doc.createElementNS(Namespaces.XMLDSIG, "X509IssuerName");
          if (config.issuerNameStyle == IssuerNameStyle.COMMON_NAME) {
            x509IssuerName.setTextContent(
                "CN=" + getCommonName(config.certificate.getSubjectX500Principal()));
          } else {
            x509IssuerName.setTextContent(config.certificate.getSubjectDN().getName());
          }
          Element x509SerialNumber = doc.createElementNS(Namespaces.XMLDSIG, "X509SerialNumber");
          x509SerialNumber.setTextContent(config.certificate.getSerialNumber().toString());

          Element x509IssuerSerial = doc.createElementNS(Namespaces.XMLDSIG, "X509IssuerSerial");
          x509IssuerSerial.appendChild(x509IssuerName);
          x509IssuerSerial.appendChild(x509SerialNumber);
          return x509IssuerSerial;
        };

    String digestMethodUri =
        ((config.digestMethod != null) && (config.digestMethod.toLowerCase().equals("sha256")))
            ? DigestMethod.SHA256
            : DigestMethod.SHA1;
    DigestMethod digestMethod = signatureFactory.newDigestMethod(digestMethodUri, null);

    Transform transform =
        signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
    // Transform transform =
    //     signatureFactory.newTransform(
    //         "http://www.w3.org/2001/10/xml-exc-c14n#", (TransformParameterSpec) null);
    Reference reference =
        signatureFactory.newReference(
            "", digestMethod, Collections.singletonList(transform), null, null);

    // add <SignatureMethod Algorithm="..."?>
    String signingMethodUri =
        ((config.signingMethod != null) && (config.signingMethod.toLowerCase().equals("rsa-sha1")))
            ? RSA_SHA1
            : RSA_SHA256;

    SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(signingMethodUri, null);

    CanonicalizationMethod canonicalizationMethod =
        signatureFactory.newCanonicalizationMethod(
            CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);

    // Create the SignedInfo
    SignedInfo signedInfo =
        signatureFactory.newSignedInfo(
            canonicalizationMethod, signatureMethod, Collections.singletonList(reference));

    KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
    KeyInfo keyInfo = null;
    if (config.keyIdentifierType == KeyIdentifierType.RSA_KEY_VALUE) {
      // <KeyInfo>
      //   <KeyValue>
      //     <RSAKeyValue>
      //       <Modulus>B6PenDyT58LjZlG6LYD27IFCh1yO+4...yCP9YNDtsLZftMLoQ==</Modulus>
      //       <Exponent>AQAB</Exponent>
      //     </RSAKeyValue>
      //   </KeyValue>
      // </KeyInfo>
      Element keyValue = doc.createElementNS(Namespaces.XMLDSIG, "KeyValue");
      Element rsaKeyValue = doc.createElementNS(Namespaces.XMLDSIG, "RSAKeyValue");
      Element modulus = doc.createElementNS(Namespaces.XMLDSIG, "Modulus");
      Element exponent = doc.createElementNS(Namespaces.XMLDSIG, "Exponent");

      RSAPrivateKey configPrivateKey = (RSAPrivateKey) config.privatekey;
      final byte[] keyModulus = configPrivateKey.getModulus().toByteArray();
      String encodedModulus = Base64.getEncoder().encodeToString(keyModulus);
      modulus.setTextContent(encodedModulus);
      // final byte[] publicExponent = configPrivateKey.getPublicExponent().toByteArray();
      // String encodedPublicExponent = Base64.getEncoder().encodeToString(publicExponent);
      exponent.setTextContent("AQAB");
      rsaKeyValue.appendChild(modulus);
      rsaKeyValue.appendChild(exponent);
      keyValue.appendChild(rsaKeyValue);
      XMLStructure structure = new DOMStructure(keyValue);
      keyInfo = kif.newKeyInfo(Collections.singletonList(structure));

    } else if ((config.keyIdentifierType == KeyIdentifierType.X509_CERT_DIRECT)
        || (config.keyIdentifierType == KeyIdentifierType.X509_CERT_DIRECT_AND_ISSUER_SERIAL)) {
      // <KeyInfo>
      //   <X509Data>
      //     <X509Certificate>MIICAjCCAWugAw....AQnI7IYAAKzz7BQnulQ=</X509Certificate>
      //   </X509Data>
      // </KeyInfo>
      //
      // -or-
      //
      // <KeyInfo>
      //   <X509Data>
      //     <X509IssuerSerial>
      //       <X509IssuerName>CN=creditoexpress</X509IssuerName>
      //       <X509SerialNumber>1323432320</X509SerialNumber>
      //     </X509IssuerSerial>
      //     <X509Certificate>MIICAjCCAWugAw....AQnI7IYAAKzz7BQnulQ=</X509Certificate>
      //   </X509Data>
      // </KeyInfo>
      //
      maybeCheckCert.invoke();

      Element x509Data = doc.createElementNS(Namespaces.XMLDSIG, "X509Data");
      if (config.keyIdentifierType == KeyIdentifierType.X509_CERT_DIRECT_AND_ISSUER_SERIAL) {
        x509Data.appendChild(issuerSerialMaker.get());
      }

      Element x509Certificate = doc.createElementNS(Namespaces.XMLDSIG, "X509Certificate");
      x509Certificate.setTextContent(
          Base64.getEncoder().encodeToString(config.certificate.getEncoded()));
      x509Data.appendChild(x509Certificate);
      XMLStructure structure = new DOMStructure(x509Data);
      keyInfo = kif.newKeyInfo(Collections.singletonList(structure));
    } else if (config.keyIdentifierType == KeyIdentifierType.X509_ISSUER_SERIAL) {
      // <KeyInfo>
      //   <X509Data>
      //     <X509IssuerSerial>
      //       <X509IssuerName>CN=creditoexpress</X509IssuerName>
      //       <X509SerialNumber>1323432320</X509SerialNumber>
      //     </X509IssuerSerial>
      //   </X509Data>
      // </KeyInfo>
      //
      maybeCheckCert.invoke();
      Element x509Data = doc.createElementNS(Namespaces.XMLDSIG, "X509Data");
      x509Data.appendChild(issuerSerialMaker.get());
      XMLStructure structure = new DOMStructure(x509Data);
      keyInfo = kif.newKeyInfo(Collections.singletonList(structure));
    } else {
      throw new IllegalStateException("unsupported KeyInfo format");
    }

    // DOMSignContext signingContext = new DOMSignContext(config.privatekey,
    // wssecHeader);
    DOMSignContext signingContext = new DOMSignContext(config.privatekey, doc.getDocumentElement());
    XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
    signature.sign(signingContext);

    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer trans = tf.newTransformer();

    // emit the resulting document
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.transform(new DOMSource(doc), new StreamResult(baos));
    return new String(baos.toByteArray(), StandardCharsets.UTF_8);
  }

  private static RSAPrivateKey decodeKey(String privateKeyPemString, String password)
      throws IOException, OperatorCreationException, PKCSException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    if (password == null) password = "";

    PEMParser pr = null;
    try {
      pr = new PEMParser(new StringReader(privateKeyPemString));
      Object o = pr.readObject();

      if (o == null) {
        throw new IllegalStateException("Parsed object is null.  Bad input.");
      }
      if (!((o instanceof PEMEncryptedKeyPair)
          || (o instanceof PKCS8EncryptedPrivateKeyInfo)
          || (o instanceof PrivateKeyInfo)
          || (o instanceof PEMKeyPair))) {
        // System.out.printf("found %s\n", o.getClass().getName());
        throw new IllegalStateException(
            "Didn't find OpenSSL key. Found: " + o.getClass().getName());
      }

      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (o instanceof PEMKeyPair) {
        // eg, "openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048"
        return (RSAPrivateKey) converter.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo());
      }

      if (o instanceof PrivateKeyInfo) {
        // eg, "openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem"
        return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) o);
      }

      if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
        // eg, "openssl genpkey -algorithm rsa -aes-128-cbc -pkeyopt rsa_keygen_bits:2048 -out
        // private-encrypted.pem"
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo =
            (PKCS8EncryptedPrivateKeyInfo) o;
        JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
            new JceOpenSSLPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decryptorProvider =
            decryptorProviderBuilder.build(password.toCharArray());
        PrivateKeyInfo privateKeyInfo =
            pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
      }

      if (o instanceof PEMEncryptedKeyPair) {
        // eg, "openssl genrsa -aes256 -out private-encrypted-aes-256-cbc.pem 2048"
        PEMDecryptorProvider decProv =
            new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
        KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    } finally {
      if (pr != null) {
        pr.close();
      }
    }
    throw new IllegalStateException("unknown PEM object");
  }

  private RSAPrivateKey getPrivateKey(MessageContext msgCtxt) throws Exception {
    String privateKeyPemString = getSimpleRequiredProperty("private-key", msgCtxt);
    privateKeyPemString = privateKeyPemString.trim();

    // clear any leading whitespace on each line
    privateKeyPemString = reformIndents(privateKeyPemString);
    String privateKeyPassword = getSimpleOptionalProperty("private-key-password", msgCtxt);
    if (privateKeyPassword == null) privateKeyPassword = "";
    return decodeKey(privateKeyPemString, privateKeyPassword);
  }

  protected X509Certificate getCertificate(MessageContext msgCtxt)
      throws NoSuchAlgorithmException, InvalidNameException, KeyException,
          CertificateEncodingException {
    String certificateString = getSimpleOptionalProperty("certificate", msgCtxt);
    if (certificateString == null) return null;
    certificateString = certificateString.trim();
    X509Certificate certificate = (X509Certificate) certificateFromPEM(certificateString);
    X500Principal principal = certificate.getIssuerX500Principal();
    msgCtxt.setVariable(varName("cert-issuer-cn"), getCommonName(principal));
    msgCtxt.setVariable(varName("cert-sha1-thumbprint"), getThumbprintHex(certificate));
    msgCtxt.setVariable(varName("cert-sha256-thumbprint"), getThumbprintHexSha256(certificate));
    return certificate;
  }

  static class SignConfiguration {
    public RSAPrivateKey privatekey; // required
    public X509Certificate certificate; // required
    public String signingMethod;
    public String digestMethod;
    public IssuerNameStyle issuerNameStyle;
    public KeyIdentifierType keyIdentifierType;
    public boolean omitCertValidityCheck;

    public SignConfiguration() {
      keyIdentifierType = KeyIdentifierType.RSA_KEY_VALUE;
    }

    public SignConfiguration withKey(RSAPrivateKey key) {
      this.privatekey = key;
      return this;
    }

    public SignConfiguration withKeyIdentifierType(KeyIdentifierType kit) {
      this.keyIdentifierType = kit;
      return this;
    }

    public SignConfiguration withIssuerNameStyle(IssuerNameStyle issuerNameStyle) {
      this.issuerNameStyle = issuerNameStyle;
      return this;
    }

    public SignConfiguration withCertificate(X509Certificate certificate) {
      this.certificate = certificate;
      return this;
    }

    public SignConfiguration withSigningMethod(String signingMethod) {
      this.signingMethod = signingMethod;
      return this;
    }

    public SignConfiguration withDigestMethod(String digestMethod) {
      this.digestMethod = digestMethod;
      return this;
    }

    public SignConfiguration withOmitCertValidityCheck(boolean omitCertValidityCheck) {
      this.omitCertValidityCheck = omitCertValidityCheck;
      return this;
    }
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      Document document = getDocument(msgCtxt);
      SignConfiguration signConfiguration =
          new SignConfiguration()
              .withKey(getPrivateKey(msgCtxt))
              .withKeyIdentifierType(getKeyIdentifierType(msgCtxt))
              .withCertificate(getCertificate(msgCtxt))
              .withIssuerNameStyle(getIssuerNameStyle(msgCtxt))
              .withSigningMethod(getSigningMethod(msgCtxt))
              .withDigestMethod(getDigestMethod(msgCtxt))
              .withOmitCertValidityCheck(getOmitCertValidityCheck(msgCtxt));

      String resultingXmlString = sign_RSA(document, signConfiguration, msgCtxt);
      String outputVar = getOutputVar(msgCtxt);
      msgCtxt.setVariable(outputVar, resultingXmlString);
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
