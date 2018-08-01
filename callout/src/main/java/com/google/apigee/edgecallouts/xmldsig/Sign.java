// Copyright 2018 Google LLC
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

package com.google.apigee.edgecallouts.xmldsig;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.XmlUtils;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.Map;
import javax.xml.crypto.MarshalException;
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
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.lang3.exception.ExceptionUtils;
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


public class Sign extends XmlDsigCalloutBase implements Execution {

    public Sign (Map properties) {
        super(properties);
    }

    private static byte[] sign_RSA_SHA256(Document doc, KeyPair kp)
        throws InstantiationException,
               NoSuchAlgorithmException,
               InvalidAlgorithmParameterException,
               KeyException,
               MarshalException,
               XMLSignatureException,
               TransformerException
    {
        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");

        DigestMethod digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA256, null);
        Transform transform = signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        Reference reference = signatureFactory.newReference("", digestMethod, Collections.singletonList(transform), null, null);
        SignatureMethod signatureMethod = signatureFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
        CanonicalizationMethod canonicalizationMethod =
            signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                                                       (C14NMethodParameterSpec) null);

        // Create the SignedInfo
        SignedInfo signedInfo = signatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod,
                                                               Collections.singletonList(reference));

        KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        DOMSignContext signingContext = new DOMSignContext(kp.getPrivate(), doc.getDocumentElement());

        XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, kif.newKeyInfo(Collections.singletonList(kv)));
        signature.sign(signingContext);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();

        // output the resulting document
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        trans.transform(new DOMSource(doc), new StreamResult(baos));
        return baos.toByteArray();
    }


    private static KeyPair readKeyPair(String privateKeyPemString, String password)
        throws IOException, OperatorCreationException, PKCSException, InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (password == null) password = "";

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PEMParser pr = new PEMParser(new StringReader(privateKeyPemString));
        Object o = pr.readObject();

        if (o == null || !((o instanceof PEMKeyPair) || (o instanceof PEMEncryptedKeyPair) || (o instanceof PKCS8EncryptedPrivateKeyInfo)) ) {
            //System.out.printf("found %s\n", o.getClass().getName());
            throw new IllegalStateException("Didn't find OpenSSL key");
        }

        if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
            // produced by "openssl genpkey" or the series of commands reqd to sign an ec key
            //LOGGER.info("decodePrivateKey, encrypted PrivateKeyInfo");
            PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) o;
            JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
            InputDecryptorProvider decryptorProvider = decryptorProviderBuilder.build(password.toCharArray());
            PrivateKeyInfo privateKeyInfo = pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
            PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);

            BigInteger publicExponent = BigInteger.valueOf(65537);
            PublicKey publicKey = KeyFactory
                .getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(((RSAPrivateKey)privateKey).getPrivateExponent(), publicExponent));
            return new KeyPair(publicKey, privateKey);
        }

        KeyPair kp;
        if (o instanceof PEMEncryptedKeyPair) {
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().setProvider("BC")
                .build(password.toCharArray());
            return converter.getKeyPair(((PEMEncryptedKeyPair)o).decryptKeyPair(decProv));
        }

        return converter.getKeyPair((PEMKeyPair)o);
    }

    private KeyPair getPrivateKey(MessageContext msgCtxt) throws Exception {
        String privateKeyPemString = getSimpleRequiredProperty("private-key", msgCtxt);
        privateKeyPemString = privateKeyPemString.trim();

        // clear any leading whitespace on each line
        privateKeyPemString = privateKeyPemString.replaceAll("([\\r|\\n] +)","\n");
        String privateKeyPassword = getSimpleOptionalProperty("private-key-password", msgCtxt);
        return readKeyPair(privateKeyPemString, privateKeyPassword);
    }

    public ExecutionResult execute (final MessageContext msgCtxt,
                                    final ExecutionContext execContext) {
        try {
            Document document = getDocument(msgCtxt);
            KeyPair keypair = getPrivateKey(msgCtxt);
            byte[] resultBytes = sign_RSA_SHA256(document, keypair);
            String outputVar = getOutputVar(msgCtxt);
            msgCtxt.setVariable(outputVar, new String(resultBytes, StandardCharsets.UTF_8));
            return ExecutionResult.SUCCESS;
        }
        catch (IllegalStateException exc1) {
            setExceptionVariables(exc1,msgCtxt);
            return ExecutionResult.ABORT;
        }
        catch (Exception e) {
            if (getDebug()) {
                System.out.println(ExceptionUtils.getStackTrace(e));
            }
            setExceptionVariables(e,msgCtxt);
            msgCtxt.setVariable(varName("stacktrace"), ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }
    }

}
