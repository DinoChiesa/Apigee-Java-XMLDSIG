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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class TestXmlDsigSignCallout extends TestBase {

  private static final String privateKey1 =
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
          + "MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIe1dDIKI2EhwCAggA\n"
          + "MB0GCWCGSAFlAwQBAgQQijMNrkSU3jGJLHP90tc81ASCBNATKUMZxgfrCN67P3V6\n"
          + "/5iqKfoPcvmV+V1XJT9f/Y3YezMOvE9pAUtLv30N7HBcwadwbqsmfqYh7lVDOvpB\n"
          + "nyAayr5U0zZtfHS66XinZdtBc8UbMu2pb6DQ0pzrhG/tmo09QD7JDqs2Lq0Z88a4\n"
          + "2H5LbgAJMgpFwGVLPR/ZMmRe5zrsOjfmmVnt10hTarKVnjM/pc0S34TpnLlMKSjR\n"
          + "fIsqLFNAg9vZP2WHUChmGUNe9YaNZfe1r6S1TiPc5M0y62H996rYIR8FKxys6lxb\n"
          + "s0bFoYd0YWA50hDcXltmwyQPYBBRwUbRjLeQTUcR0W75bh34Ee/K9pqfYtQTf5Tw\n"
          + "+DiVv9FgDW9bIi30q1iovh7lboBUSWS2X4dfN1f/CDOFdeEm0Mi6yE/qqGDpjVrF\n"
          + "88xpmLnCy4WvKu97f4CLiL5fsVQu3yP9T6aldP+NOq4qXg96kpjwBjQDjCYRMpCi\n"
          + "Z8OHhoWa10EzRM8p5e4DiXco5YzVd5CpdxshKxT/sCvpHmWpVjzruANTXNQXXy6N\n"
          + "kWO+5PT9nSpb7+GOHruWrImkyytt6Yq53Rli6FCf22cgLxHaIN6mCbQuxb6InVxh\n"
          + "h1a7ccvbR2d7rk9FVbrfLSQ5vEWJnYFpoxWvrQGwKQHaYHbYfqH/oouaiN1vDrzu\n"
          + "NW0+y+lSYrMy+Rxv+vPD5EBt7aY1tj9sgrcWcHlSpkoyAttmWgmoF5TGF4A8M76r\n"
          + "+dzAdkkxqxGUP6prdkGvleWCwRnrmEXyKYILc2MtJxG45bD/XpSQKitkyRnXFF+J\n"
          + "MpdYCZES0NgFauPxVgnl4xkKjcpdV6e3HaJHatWY1/D6M1vIH0n/RT8uQhu/YpzF\n"
          + "hvsUsc+E6/jCN/P4mN6FlCugBzEouIseRhdXIL9qzQdSE1MmVzERlFNkNeqD+j+I\n"
          + "LvktK2s/VhBZxAf2yU9t4a92wQRaQyLPlsB/KFJ8tbGQGpgu1OqiJ4BcKlFBp2Jq\n"
          + "p4ivjcD+S4aKzMyQI9fMEyxOrHN0sfAHq2VBDS2QkcYWhe6qlckkDQJ7tWRhqzmi\n"
          + "k6LFGnjbA6RPnABJ9N2/JX4bEzlOeODiMXD81FLeHTlNUBgSNx8Itwm3DU6Jnv49\n"
          + "PqWICTMHWmXUkAwLbjydRBO6MVUQUNVpcM/dl5M/x0KPsghX7gXoXiPKIe9xrq6w\n"
          + "FcXZa2hED/9EJLLz6WvMtqX1BcrxA+wbueiTN8y+1GI6UkvTg42Iw//2t4qKwMv+\n"
          + "Q/jadrmxIgcyTe5GVxGUWmC336vW3bz2Vc7IEWDUcX0x+XLaw4ByKbKx2bti1mcN\n"
          + "zz/r2GZw1BtdWVCFQw2NfF4rLM5GCbrjF4XG5RB0Lbp1Q2XqXXRKJXR6kZuTgDgU\n"
          + "dFwGqhP1mwCGs9/Pg0AfGvqn+jcGipVevx/OFEiu+eK6VNYz4vAt5gU3sLyUwcpC\n"
          + "2vUN8Kh4TY4J4oJNeDibWU//qu35c+SoQQPC1L850ZCFsXoGg9TCGuhG97KlZxNw\n"
          + "i+CJHKTOWpPwLiPrVPtIp+Q6X8sRibLBdetXhq0P6Nh4mRew6iUg1DzClkK5/jFP\n"
          + "Tt5sUjnIV974hjP7F2e64scWXAIoEDYPdhhP/uLbxUmy0Cr9Jt8uUEGb+H7nWOUe\n"
          + "1MYSgvlF9eUm6e21FySl6H1kgw==\n"
          + "-----END ENCRYPTED PRIVATE KEY-----\n";

  private static final String privateKey2 =
      "-----BEGIN RSA PRIVATE KEY-----\n"
          + "Proc-Type: 4,ENCRYPTED\n"
          + "DEK-Info: DES-EDE3-CBC,63802B11A1FDFA29\n"
          + "\n"
          + "tGf3pCDVH00UpEmIB6YZxoJ7WcEwM1YIesjXMEpAmZUzwE9R6qu9J9c2idfMIy5z\n"
          + "0vlQnV3dU3DUuTXeaJZT/Gijs9jc8X1yTNDEKhNVX3NI/kDbC9xC+T20FS/LdSK7\n"
          + "kz18o3s9YutwSqc3RZeYb0ECR5uNv0ZQRv9GPQBVeJbfFS9GyXeE6UHgg4e9c0hW\n"
          + "3Ru9Z7XTtsPhhBdoV1rg8HvCsUADQMhOFTzlCaAD/bO6yhTeaeFIwXcAjK8Bdg72\n"
          + "mMUTgjZwfOyhrCB36Rfuv64MaZZfPqITM54Ha5exWbqjGbU+B5FkKppTV54eHen7\n"
          + "2mkCCUckGT9VLfMrXjZmBlmUSSgLNJguBwH5rIbEze2NcMJwX6oNoXVIC6j/Qt9D\n"
          + "VL7t1js5y4Xg/L2DbOfOrN4FAX1bOaaulS1wFmcyGTR5bYOTFRYqA8gfGP36wWdi\n"
          + "o4mEEgpdGuRsGvkI7svnQHFgKMvRgCG+aWg9PGeacpBHtjmv2A+KNiL0Am1x2bOM\n"
          + "B55kZCcHd/81/4lz/iKLG2dEpN2fqw5qxP0/UMqeehemUHBiX2sxPV1yIStAppno\n"
          + "dkZG9G0prnfCEHz47msj1gN4J4fyX2WxWyRKIUP+hNwuw5Sh9slc4HGyV/StfRsJ\n"
          + "4fjJaMmxDAc112JCbRCoxyxWVIcEEo35wBOTSEzlYF2zj179XnzD2519vc+QGpqc\n"
          + "q7/j/9dr0VLt78rrjCnH2DCA+K24zQluyKI2bkkNVeS+dqfHrK2b11guQiPAhLWd\n"
          + "4MAtt+zz0VxMyE3MExZwwFAs8Wxb5kG9Wam6FXdZiRNAFtNZ9Ab4fuDBLObHXlbU\n"
          + "rHXRHZmUbmCoW8B7cd6NlMrJQCsxSPyN9rhuyjEueB2UuMX4IXOZcghT8Ej0KMP+\n"
          + "OF4gYdL9loznsAmQspLG3NJESYQ6tZax6XayibWQGdVj2QwT3YZ7j2fRMVv8OQy6\n"
          + "TWMVMRXqVySAhB9KYNqfEYA+jw2aFWnwkKkcmHSadsVNs74GKwpvXwT48tmBjBAb\n"
          + "xbycgSV7ZBIzbXUMbBpZ/59h8eVLMmKVB9UmV6nQK2sYnhJ6wz0h3WjyQR0YJ9yJ\n"
          + "1OJTiAnvVAMJcs0Nju9Bf6qYOMvm8KWResVAmqfdENyiU9fuFR4FwbSVbPuebC/u\n"
          + "Y82c1hlNg/3gl5b7aUqNuoH1UeNuBf/C4HrLu7yhKuyVWAK7egRh+LhcYRYZWCWg\n"
          + "EPV89Rez36j6np4Lt4xNiyF92mHkld7+uG5Uw7+EGJWM9R/E7vY1w3A/i7BsIjNt\n"
          + "qBWFJP9Bq89kdl0wCKrKCbKHPkGb+8yy8ivu3Y9q+DtcnZXmOxxg4C43biyUeFVw\n"
          + "PWvdQwjEmliRzlsZEh65EDu9Od+VHPmKSU9bxTWYjHzpMjadEV/yQA312vdtdiSU\n"
          + "KA2BDCmNQFiTbcFsulxRhGxgHcexuYvuoLQNGfS6Qd85Leu0LJyn258eE0oRPxgi\n"
          + "77vm5V4RuEKiGr0+7cBcswZ4mDd+OJQYCYHGoDbpYFO4Rgy7WakCLI6I32E373BX\n"
          + "WoAnf4VfajzL/IDHUQV8TuM8YB0X2WdyxxobXb8BepqgDe3Aq83JZheE0HxoPEmR\n"
          + "-----END RSA PRIVATE KEY-----\n";

  private static final String privateKey3 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDS00tbNFPsFw/ZExSv3DFxBFoXwKhDeape8LYUK5m7katvlPf7lwzWrKU0w6gYnJZ8gwgnpY35mTCqOvCU4fRnZLsiecuQE+VuibkfzNFrK9NkW8CrsZkAeSlZEJEslLdMzYH+en/6zCzeaRUkJbdN3U128kxvVUjPX4Bd/ITPPNrjEt9spZsvqrIgq1bRcN48kHvNsCMRVXFmpXGTgUKH9mkokcuVPqbS23xXG5lS6cJ8RQXAAJU5UP511biHpduoyqMqT3juPb1LxAWDztq9FMqAjtU3QLYPaWarjLsT7CQ14w2tUZ1pWP/JeAFqhyp32x9/3J4oRJLwdGTbwUY9AgMBAAECggEAB6PenDyGOg0P5vb5DfJ13DmjJi82KdPT58LjZlG6LYD27IFCh1yO+4ygJAxfIB00muiIuB8YyQ3TJKgkJdEWcVTGL1aomN0PuHTHP67FfBPHgmCM1+wEtm6tn+uoxyvQhLkB1/4Ke0VA7wJx4LB5Nxoo/4GCYZp+m/1DAqTvDy99hRuSTWt+VJacgPvfDMA2akFJAwUVSJwh/SyFZf2yqonzfnkHEK/hnC81vACs6usAj4wR04yj5yElXW+pQ5Vk4RUwR6Q0E8nKWLfYFrXygeYUbTSQEj0f44DGVHOdMdT+BoGV5SJ1ITs+peOCYjhVZvdngyCP9YNDtsLZftMLoQKBgQD2cxpph+h+8FsPHN/IjoqUpZ9HuCSxgUo0DorGnW0hewZ5AtZVARqONfhVeNt9TEgXFAHFtbdBYWlEhqT3yNPMpcM9gemuqyUOL35tHUCNccgKev2qyqHFQnUkRr+jRcch1yCmEvPYhPGZRh4KUzm7fuBVIJqROaZ0xBz7a8iv2QKBgQDa/sggatnPK0S9d4VF+a6mdCiUF3mEkROwwO2obUiNPuKRkgElHt8vx86Son2qdanPWYkOtrMFLpAKSFRbEtNNXtu0CgC2wMsPoo6W8IXDVxfl7tMaYpNJHs15IFxiIcTgXNxyTefRpRdTa4NTthtaIwnUVtenK7XOny8twdUvBQKBgQCoAZ2+1XTMnIQnEFMKQQn9/c5QsRrqmy3/wO4gKg/MZDbsZd/BQSheTDKH6gUPLOJ0QSJYKuHLw2Fk4rkxZgnlGBe6JYctmOSBACWasvdftXJemqu1M8AGXqDG4ygfYSE4U5ShQohTUYX2LFOsTEIuLHc38SsN15Q/Q7ZSO48rOQKBgHjIoTRP+oWqxaUCML1hcpRX6LGVKO6W3ZdVMT7911Af6PKE5qDEoDBIMYTqngjQELJOHavB1Ib9IXCqZ+w7O9Omh+KKyc4CE30yGRbi3cPZW1L0H/aje7yOgqFV2d495cohLWzVzw/v0CewWqRnAjr6rEczBoorL4EghvLjv2LJAoGBAMaAkmyjSVIKIf4T4Vz5BR0KXIx/qgIfQFRVgIFr5hDRlIBm8m13tzwgnXFba9D2DFinLo4SO8BZVPDbPPDz2IZWduv2c7eOT3NmwQlWg8kNgMZDif3nyIC4xX7k2ioP6eGh8G8jWfnhCW56uVMNgDsHY2kzSxXbwLs64zRqYMn3\n"
          + "-----END PRIVATE KEY-----\n";

  private static final String simpleXml1 =
      "<purchaseOrder xmlns='http://tempuri.org/po.xsd' orderDate='2017-05-20'>\n"
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
          + "</purchaseOrder>\n";

  private static Document docFromStream(InputStream inputStream)
      throws IOException, ParserConfigurationException, SAXException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(inputStream);
    return doc;
  }

  @Test
  public void emptySource() throws Exception {
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", simpleXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "emptySource() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void missingPrivateKey() throws Exception {
    String expectedError = "private-key resolves to an empty string";

    msgCtxt.setVariable("message.content", simpleXml1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNotNull(exception, "missingPrivateKey() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "missingPrivateKey() stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void validResult1() throws Exception {
    msgCtxt.setVariable("message.content", simpleXml1);
    msgCtxt.setVariable("my-private-key", privateKey1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "validResult1() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "validResult1() stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, "validResult1() Signature element");
    System.out.println("=========================================================");
  }

  @Test
  public void keyIdentifier_Cert() throws Exception {
    String testName = "keyIdentifier_Cert";
    String privateKeyString =
        getResourceFileContents("keys-and-certs", "rsa-private-key-20220916.pem");
    String certString = getResourceFileContents("keys-and-certs", "x509-certificate-20220916.pem");

    msgCtxt.setVariable("message.content", simpleXml1);
    msgCtxt.setVariable("my-private-key", privateKeyString);
    msgCtxt.setVariable("my-cert", certString);
    msgCtxt.setVariable("debug", "true");

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("debug", "true");
    props.put("private-key", "{my-private-key}");
    props.put("key-identifier-type", "x509_cert_direct");
    props.put("certificate", "{my-cert}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, String.format("%s() exception", testName));
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, String.format("%s() stacktrace", testName));

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("%s\n", output);

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() Signature element", testName));
    System.out.println("=========================================================");
  }

  @Test
  public void withPrivateKeyPassword() throws Exception {
    msgCtxt.setVariable("message.content", simpleXml1);
    msgCtxt.setVariable("my-private-key", privateKey2);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "withPrivateKeyPassword() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "withPrivateKeyPassword() stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, "withPrivateKeyPassword() Signature element");
    System.out.println("=========================================================");
  }

  @Test
  public void withBlankPrivateKeyPassword() throws Exception {
    msgCtxt.setVariable("message.content", simpleXml1);
    msgCtxt.setVariable("my-private-key", privateKey3);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, "withBlankPrivateKeyPassword() exception");
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, "withBlankPrivateKeyPassword() stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, "withBlankPrivateKeyPassword() Signature element");
    System.out.println("=========================================================");
  }

  @DataProvider(name = "issuerNameStyles")
  protected Object[][] getGoodSignatures() {
    String[] issuerNameStyles = new String[] { "common_name", "dn", null, "invalid-value" };
    return toDataProvider(issuerNameStyles);
  };

  public static List<Element> getDirectChildElements(Element parent) {
    ArrayList<Element> list = new ArrayList<Element>();
    for(Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
      if(child instanceof Element) {
        list.add((Element)child);
      }
    }
    return list;
  }

  @Test(dataProvider = "issuerNameStyles")
  public void keyIdentifier_issuerSerial(int ix, String issuerNameStyle) throws Exception {
    final String testName = "keyIdentifier_issuerSerial";
    String privateKeyString =
        getResourceFileContents("keys-and-certs", "rsa-private-key-20220916.pem");
    String certString = getResourceFileContents("keys-and-certs", "x509-certificate-20220916.pem");

    msgCtxt.setVariable("message.content", simpleXml1);
    msgCtxt.setVariable("my-private-key", privateKeyString);
    msgCtxt.setVariable("my-cert", certString);
    msgCtxt.setVariable("debug", "true");

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("key-identifier-type", "x509_issuer_serial");
    props.put("certificate", "{my-cert}");
    if (issuerNameStyle!=null) {
      props.put("issuer-name-style", issuerNameStyle);
    }
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, String.format("%s() exception", testName));
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, String.format("%s() stacktrace", testName));

    String output = (String) msgCtxt.getVariable("output");

    // verify basic structure of the output document
    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() Signature element", testName));
    Element signature = (Element) nl.item(0);
    nl = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() X509Data element", testName));

    Element x509data = (Element) nl.item(0);
    List<Element> children = getDirectChildElements(x509data);
    Assert.assertEquals(children.size(), 1, String.format("%s() children of X509Data", testName));

    nl = x509data.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() X509IssuerSerial element", testName));
    Element issuerAndSerial = (Element) nl.item(0);
    nl = issuerAndSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() X509IssuerName element", testName));
    Element issuerName = (Element) nl.item(0);
    String[] parts = issuerName.getTextContent().split(",");
    if ("dn".equals(issuerNameStyle)) {
      Assert.assertEquals(parts.length, 7, "issuer name segments");
    }
    else {
      Assert.assertEquals(parts.length, 1, "issuer name segments");
      Assert.assertTrue(parts[0].startsWith("CN="), "issuer name");
    }
    nl = x509data.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() X509SerialNumber element", testName));
    System.out.println("=========================================================");
  }

  @Test
  public void keyIdentifier_certDirectAndIssuerSerial() throws Exception {
    final String testName = "keyIdentifier_certDirectAndIssuerSerial";
    String privateKeyString =
        getResourceFileContents("keys-and-certs", "rsa-private-key-20220916.pem");
    String certString = getResourceFileContents("keys-and-certs", "x509-certificate-20220916.pem");

    msgCtxt.setVariable("message.content", simpleXml1);
    msgCtxt.setVariable("my-private-key", privateKeyString);
    msgCtxt.setVariable("my-cert", certString);
    msgCtxt.setVariable("debug", "true");

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("key-identifier-type", "x509_cert_direct_and_issuer_serial");
    props.put("certificate", "{my-cert}");
    props.put("issuer-name-style", "common_name");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("xmldsig_exception");
    Assert.assertNull(exception, String.format("%s() exception", testName));
    Object errorOutput = msgCtxt.getVariable("xmldsig_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object stacktrace = msgCtxt.getVariable("xmldsig_stacktrace");
    Assert.assertNull(stacktrace, String.format("%s() stacktrace", testName));

    String output = (String) msgCtxt.getVariable("output");

    // verify basic structure of the output document
    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() Signature element", testName));
    Element signature = (Element) nl.item(0);
    nl = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() X509Data element", testName));

    Element x509data = (Element) nl.item(0);
    List<Element> children = getDirectChildElements(x509data);
    Assert.assertEquals(children.size(), 2, String.format("%s() children of X509Data", testName));

    nl = x509data.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() X509IssuerSerial element", testName));
    Element issuerAndSerial = (Element) nl.item(0);
    nl = issuerAndSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() X509IssuerName element", testName));
    Element issuerName = (Element) nl.item(0);
    String[] parts = issuerName.getTextContent().split(",");

      Assert.assertEquals(parts.length, 1, "issuer name segments");
      Assert.assertTrue(parts[0].startsWith("CN="), "issuer name");

    nl = x509data.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
    Assert.assertEquals(nl.getLength(), 1, String.format("%s() X509SerialNumber element", testName));
    System.out.println("=========================================================");
  }

}
