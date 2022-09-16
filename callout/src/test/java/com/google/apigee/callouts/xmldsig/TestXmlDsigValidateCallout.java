// Copyright 2018-2022 Google LLC.
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

  private static final String signedXml1 =
      "<?xml version='1.0' encoding='UTF-8' standalone='no'?><purchaseOrder xmlns='http://tempuri.org/po.xsd' orderDate='2017-05-20'>\n"
          + "    <shipTo country='US'>\n"
          + "        <name>Alice Smith</name>\n"
          + "        <street>123 Maple Street</street>\n"
          + "        <city>Mill Valley</city>\n"
          + "        <state>CA</state>\n"
          + "        <zip>90952</zip>\n"
          + "    </shipTo>\n"
          + "    <billTo country='US'>\n"
          + "        <name>Robert Smith</name>\n"
          + "        <street>8 Oak Avenue</street>\n"
          + "        <city>Old Town</city>\n"
          + "        <state>PA</state>\n"
          + "        <zip>95819</zip>\n"
          + "    </billTo>\n"
          + "    <comment>Hurry, my lawn is going wild!</comment>\n"
          + "    <items>\n"
          + "        <item partNum='872-AA'>\n"
          + "            <productName>Lawnmower</productName>\n"
          + "            <quantity>1</quantity>\n"
          + "            <USPrice>148.95</USPrice>\n"
          + "            <comment>Confirm this is electric</comment>\n"
          + "        </item>\n"
          + "        <item partNum='926-AA'>\n"
          + "            <productName>Baby Monitor</productName>\n"
          + "            <quantity>1</quantity>\n"
          + "            <USPrice>39.98</USPrice>\n"
          + "            <shipDate>2018-05-21</shipDate>\n"
          + "        </item>\n"
          + "    </items>\n"
          + "<Signature xmlns='http://www.w3.org/2000/09/xmldsig#'><SignedInfo><CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/><SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'/><Reference URI=''><Transforms><Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'/></Transforms><DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/><DigestValue>1wIK6YeSoMz7WH622eUOtLryj1G9ohm5Dd//Kg3WLak=</DigestValue></Reference></SignedInfo><SignatureValue>Tg06XoumiHfFvEcrweYbGSpAc7VhzYIXhUtDTPvykJ+AbAgTJkMS/eYaTmiOdYHQnTuQLnVV0Zcd\n"
          + "4U5u7nSTUNoKrFdo/gqD/elhWvqdUtWwVWffgyowQ7/KseIF5ua5nc7EnLTHGbhJPD4q3fs/T3cb\n"
          + "Z9YNYGRfYiaceFp/wPT8eRlvJfzm17CT7/bv7YTy4IJhJxCI9L6FGwbTlePzCQE3NbFLpCYYgLfj\n"
          + "6RvU0vmvXEvxR4T858V1Vb2dhbXdZA3qAhZfYbnCAuD+KWlezMKobXHlBR5Hs3yqmsCl9y4dMwck\n"
          + "L3ZMAzVche9ykXTirb3U8X9Fyp5OpJzCN2d0zw==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>B6PenDyGOg0P5vb5DfJ13DmjJi82KdPT58LjZlG6LYD27IFCh1yO+4ygJAxfIB00muiIuB8YyQ3T\n"
          + "JKgkJdEWcVTGL1aomN0PuHTHP67FfBPHgmCM1+wEtm6tn+uoxyvQhLkB1/4Ke0VA7wJx4LB5Nxoo\n"
          + "/4GCYZp+m/1DAqTvDy99hRuSTWt+VJacgPvfDMA2akFJAwUVSJwh/SyFZf2yqonzfnkHEK/hnC81\n"
          + "vACs6usAj4wR04yj5yElXW+pQ5Vk4RUwR6Q0E8nKWLfYFrXygeYUbTSQEj0f44DGVHOdMdT+BoGV\n"
          + "5SJ1ITs+peOCYjhVZvdngyCP9YNDtsLZftMLoQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature></purchaseOrder>\n";


  private static final String signedXml2 =
"<SOAP-ENV:Envelope\n"
+ "  xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'>\n"
+ "  <SOAP-ENV:Header>\n"
+ "    <SOAP-SEC:Signature\n"
+ "      xmlns:SOAP-SEC='http://schemas.xmlsoap.org/soap/security/2000-12'\n"
+ "    SOAP-ENV:actor='some-URI'\n"
+ "      SOAP-ENV:mustUnderstand='1'>\n"
+ "      <ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>\n"
+ "    <ds:SignedInfo>\n"
+ "          <ds:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'/>\n"
+ "          <ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'/>\n"
+ "          <ds:Reference URI='#Body'>\n"
+ "            <ds:Transforms>\n"
+ "             <ds:Transform Algorithm='http://www.w3.org/TR/1999/REC-xslt-19991116'>\n"
+ "              <xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'\n"
+ "                 xmlns:java='http://xml.apache.org/xslt/java'>\n"
+ "                <xsl:template match='/' xmlns:sys='java:java.lang.System' xmlns:thread='java:java.lang.Thread' >\n"
+ "                  <xsl:value-of select='sys:printf(&quot;hello world\n&quot;)' />\n"
+ "                  <xsl:value-of select='thread:sleep(20000)' />\n"
+ "                </xsl:template>\n"
+ "              </xsl:stylesheet>\n"
+ "             </ds:Transform>\n"
+ "            </ds:Transforms>\n"
          + "<ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/><ds:DigestValue>1wIK6YeSoMz7WH622eUOtLryj1G9ohm5Dd//Kg3WLak=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Tg06XoumiHfFvEcrweYbGSpAc7VhzYIXhUtDTPvykJ+AbAgTJkMS/eYaTmiOdYHQnTuQLnVV0Zcd\n"
          + "4U5u7nSTUNoKrFdo/gqD/elhWvqdUtWwVWffgyowQ7/KseIF5ua5nc7EnLTHGbhJPD4q3fs/T3cb\n"
          + "Z9YNYGRfYiaceFp/wPT8eRlvJfzm17CT7/bv7YTy4IJhJxCI9L6FGwbTlePzCQE3NbFLpCYYgLfj\n"
          + "6RvU0vmvXEvxR4T858V1Vb2dhbXdZA3qAhZfYbnCAuD+KWlezMKobXHlBR5Hs3yqmsCl9y4dMwck\n"
          + "L3ZMAzVche9ykXTirb3U8X9Fyp5OpJzCN2d0zw==</ds:SignatureValue><ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>B6PenDyGOg0P5vb5DfJ13DmjJi82KdPT58LjZlG6LYD27IFCh1yO+4ygJAxfIB00muiIuB8YyQ3T\n"
          + "JKgkJdEWcVTGL1aomN0PuHTHP67FfBPHgmCM1+wEtm6tn+uoxyvQhLkB1/4Ke0VA7wJx4LB5Nxoo\n"
          + "/4GCYZp+m/1DAqTvDy99hRuSTWt+VJacgPvfDMA2akFJAwUVSJwh/SyFZf2yqonzfnkHEK/hnC81\n"
          + "vACs6usAj4wR04yj5yElXW+pQ5Vk4RUwR6Q0E8nKWLfYFrXygeYUbTSQEj0f44DGVHOdMdT+BoGV\n"
          + "5SJ1ITs+peOCYjhVZvdngyCP9YNDtsLZftMLoQ==</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></ds:Signature>\n"
+ "    </SOAP-SEC:Signature>\n"
+"  </SOAP-ENV:Header>\n"
+ "  <SOAP-ENV:Body\n"
+"    xmlns:SOAP-SEC='http://schemas.xmlsoap.org/soap/security/2000-12'\n"
+"    SOAP-SEC:id='Body'>\n"
+ "    <m:GetLastTradePrice xmlns:m='some-URI'>\n"
+"      <m:symbol>IBM</m:symbol>\n"
+ "    </m:GetLastTradePrice>\n"
+"  </SOAP-ENV:Body>\n"
    + "</SOAP-ENV:Envelope>\n";

  @Test
  public void test_EmptySource() throws Exception {
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
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "EmptySource() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void test_MissingPublicKey() throws Exception {
    String expectedError = "public-key resolves to an empty string";

    msgCtxt.setVariable("message.content", signedXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNotNull(exception, "ValidResult() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "MissingKeybytes() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void test_RubbishPublicKey() throws Exception {
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
    Assert.assertNotNull(exception, "ValidResult() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "RubbishKeybytes() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void test_BadKey1() throws Exception {
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
    Assert.assertNull(exception, "BadKey1() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "BadKey1() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertFalse(isValid, "BadKey1() valid");
    System.out.println("=========================================================");
  }

  @Test
  public void disallowedTransform() throws Exception {
    msgCtxt.setVariable("message.content", signedXml2);

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
    Assert.assertNull(exception, "BadKey1() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "BadKey1() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertFalse(isValid, "disallowedTransform() valid");
    System.out.println("=========================================================");
  }

  @Test
  public void test_ValidResult() throws Exception {
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
    Assert.assertNull(exception, "ValidResult() exception");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "ValidResult() stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("xmldsig_valid");
    Assert.assertTrue(isValid, "ValidResult() valid");
    System.out.println("=========================================================");
  }
}
