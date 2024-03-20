// Copyright 2018-2024 Google LLC.
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

import com.apigee.flow.execution.ExecutionResult;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestXmlDsigValidateCallout extends TestBase {

  private static final String publicKey1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0tNLWzRT7BcP2RMUr9wx\n"
          + "cQRaF8CoQ3mqXvC2FCuZu5Grb5T3+5cM1qylNMOoGJyWfIMIJ6WN+ZkwqjrwlOH0\n"
          + "Z2S7InnLkBPlbom5H8zRayvTZFvAq7GZAHkpWRCRLJS3TM2B/np/+sws3mkVJCW3\n"
          + "Td1NdvJMb1VIz1+AXfyEzzza4xLfbKWbL6qyIKtW0XDePJB7zbAjEVVxZqVxk4FC\n"
          + "h/ZpKJHLlT6m0tt8VxuZUunCfEUFwACVOVD+ddW4h6XbqMqjKk947j29S8QFg87a\n"
          + "vRTKgI7VN0C2D2lmq4y7E+wkNeMNrVGdaVj/yXgBaocqd9sff9yeKESS8HRk28FG\n"
          + "PQIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  private static final String publicKey2 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5+DmkBmXNfLurOyXzWs\n"
          + "QsDpSr2zNjB0tas+FC/ksEgL5DOJTdQLr/2wCoKnWMvt3bX69gNdKY74O+rBlPd2\n"
          + "2mwvX1ZzHKkbPN5KqTuwAWjU1G6prlDncEnMw20MLhgevRkP2H6ECFPLEB+tk2+W\n"
          + "vLbo51+pqgmYe0g+jky53y9XOf0EJi5GNDEolfp9TTbGMkAIrQ4/gU5DXnYuLwqB\n"
          + "ehn7C+GcdnSDYlzlTdH7TNlpDErMmQrpKsTgw5H3HBgVoqzld9bNwfwzXNYAn88S\n"
          + "1y8UFhFXEkiU2MpxrGMc+naLLVEpjnXIPbLB4zDg0pyiQ5ogpAdBAApPLzcBn8G1\n"
          + "RQIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  @Test
  public void emptySource() throws Exception {
    String signedXml1 = getResourceFileContents("documents", "SignedXml-1.xml");
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", signedXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "emptySource() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void missingPublicKey() throws Exception {
    String signedXml1 = getResourceFileContents("documents", "SignedXml-1.xml");
    String expectedError = "the configuration does not supply a public key";

    msgCtxt.setVariable("message.content", signedXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("debug", "true");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNotNull(exception, "missingPublicKey() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "missingPublicKey() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void rubbishPublicKey() throws Exception {
    String signedXml1 = getResourceFileContents("documents", "SignedXml-1.xml");
    String expectedError = "Didn't find an RSA Public Key";
    msgCtxt.setVariable("message.content", signedXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("public-key", "this-is-not-a-valid-public-key");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNotNull(exception, "rubbishPublicKey() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "rubbishPublicKey() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void badKey1() throws Exception {
    String signedXml1 = getResourceFileContents("documents", "SignedXml-1.xml");
    msgCtxt.setVariable("message.content", signedXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("public-key", publicKey2);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "badKey1() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "badKey1() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertFalse(isValid, "badKey1() valid");
    System.out.println("=========================================================");
  }

  @Test
  public void disallowedTransform() throws Exception {
    String signedXml2 = getResourceFileContents("documents", "SignedXml-2.xml");
    String expectedError = "Couldn't find 'Signature' element";
    msgCtxt.setVariable("message.content", signedXml2);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("debug", "true");
    props.put("public-key", publicKey1);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");

    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertFalse(isValid, "disallowedTransform() valid");
    System.out.println("=========================================================");
  }

  @Test
  public void validResult() throws Exception {
    String signedXml1 = getResourceFileContents("documents", "SignedXml-1.xml");
    msgCtxt.setVariable("message.content", signedXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("public-key", publicKey1);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "validResult() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "validResult() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertTrue(isValid, "validResult() valid");
    System.out.println("=========================================================");
  }

  @Test
  public void modifiedSignedInfo() throws Exception {
    String signedXml1_modified = getResourceFileContents("documents", "SignedXml-1-modified.xml");
    msgCtxt.setVariable("message.content", signedXml1_modified);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("public-key", publicKey1);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");

    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "modifiedSignedInfo() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "modifiedSignedInfo() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertFalse(isValid, "modifiedSignedInfo() valid");
    System.out.println("=========================================================");
  }

  @Test
  public void modifiedSignedInfo_withReform() throws Exception {
    String signedXml1_modified = getResourceFileContents("documents", "SignedXml-1-modified.xml");
    msgCtxt.setVariable("message.content", signedXml1_modified);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("reform-signedinfo", "true");
    props.put("public-key", publicKey1);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");

    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "modifiedSignedInfo_withReform() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "modifiedSignedInfo_withReform() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertTrue(isValid, "modifiedSignedInfo_withReform() valid");
    System.out.println("=========================================================");
  }

  @DataProvider(name = "filesWithEmbeddedCert")
  protected Object[][] getNamesOfSignedFiles() {
    String[] filenames =
        new String[] {
          "signed--key-identifier-x509-cert-direct.xml",
          "signed--key-identifier-x509-cert-direct-and-issuer-serial.xml"
        };
    return toDataProvider(filenames);
  }

  @Test(dataProvider = "filesWithEmbeddedCert")
  public void embeddedCert_sha256(int ix, String filename) throws Exception {
    String signedXml = getResourceFileContents("documents", filename);
    String trustedThumbprint = "0067b84f4d5f8425888cc28b99238a3c71b5c50274a22d336695f462ffe169ed";

    msgCtxt.setVariable("message.content", signedXml);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("key-identifier-type", "x509_cert_direct");
    props.put("certificate-thumbprints-s256", trustedThumbprint);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "embeddedCert() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "embeddedCert() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertTrue(isValid, "embeddedCert() valid");

    String notBefore = (String) msgCtxt.getVariable("xmldsig_cert-notBefore");
    Assert.assertEquals("2022-09-16T22:36:35Z", notBefore);
    System.out.println("=========================================================");
  }

  @Test(dataProvider = "filesWithEmbeddedCert")
  public void embeddedCert_sha1(int ix, String filename) throws Exception {
    String signedXml = getResourceFileContents("documents", filename);
    String trustedThumbprint = "1043ca08045649e215402ef6c4a77d33190b8c02";

    msgCtxt.setVariable("message.content", signedXml);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("key-identifier-type", "x509_cert_direct");
    props.put("certificate-thumbprints", trustedThumbprint);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "embeddedCert() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "embeddedCert() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertTrue(isValid, "embeddedCert() valid");

    String notBefore = (String) msgCtxt.getVariable("xmldsig_cert-notBefore");
    Assert.assertEquals("2022-09-16T22:36:35Z", notBefore);
    System.out.println("=========================================================");
  }

  @Test
  public void missingCert() throws Exception {
    String signedXml1 = getResourceFileContents("documents", "SignedXml-1.xml");

    String trustedThumbprint = "1043ca08045649e215402ef6c4a77d33190b8c02";
    String expectedError = "Couldn't find 'X509Data' element";

    msgCtxt.setVariable("message.content", signedXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("key-identifier-type", "x509_cert_direct");
    props.put("certificate-thumbprint", trustedThumbprint);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");

    System.out.println("=========================================================");
  }

  @Test
  public void integratedDeveloperPortalAuthnRequest() throws Exception {
    String signedXml = getResourceFileContents("documents", "SAMLRequest-base64-decoded.xml");
    String trustedThumbprintSHA256 =
        "db63b94bf7401b16858e53cb10317bd9b09e6415f355229440a550ab797731ca";

    msgCtxt.setVariable("message.content", signedXml);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("key-identifier-type", "x509_cert_direct");
    props.put("certificate-thumbprints-s256", trustedThumbprintSHA256);

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "embeddedCert() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "embeddedCert() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertTrue(isValid, "embeddedCert() valid");

    String notBefore = (String) msgCtxt.getVariable("xmldsig_cert-notBefore");
    Assert.assertEquals(notBefore, "2021-10-19T09:13:08Z");
    String notAfter = (String) msgCtxt.getVariable("xmldsig_cert-notAfter");
    Assert.assertEquals(notAfter, "2026-10-18T09:13:08Z");
    System.out.println("=========================================================");
  }
}
