# Apigee Java callout for  XML Digital Signature

This directory contains the Java source code and pom.xml file required
to compile a simple Java callout for Apigee , that performs an
XML Digital Signature signing or validation, via [javax.xml.crypto.dsig.XMLSignature](https://docs.oracle.com/javase/9/docs/api/javax/xml/crypto/dsig/XMLSignature.html). When signing, this callout signs the entire document, and returns the resulting document.
When validating, it verifies that the signature is valid.

In all cases this callout uses RSA keys.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## License

This material is copyright 2018-2022, Google LLC.
and is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file.

This code is open source but you don't need to compile it in order to use it.

## Details

There are two callout classes,

* `com.google.apigee.callouts.xmldsig.Sign` - signs the input document.
  Always signs the root element, and always embeds the signature as a child of the root element.

* `com.google.apigee.callouts.xmldsig.Validate` - validates the signed document.
  It verifies that the signature is a child of the root element, and that the signed element is the root element.
  It can validate using either a public key, or via a certificate embedded in the Signature element of the document.
  In this latter case you must configure the callout with a set of one or more certificate thumbprints to trust.

The signature uses these settings:
* http://www.w3.org/2000/09/xmldsig
* enveloped mode
* signs the document root element
* canonicalization method of "http://www.w3.org/2001/10/xml-exc-c14n#"
* signature method of rsa-sha256 or rsa-sha1. The latter is dis-recommended.
* sha256 or SHA1 digest. SHA1 is dis-recommended.
* embeds the key identifier as an RSA public key directly, or with an X509 certificate.

These behaviors are hardcoded into the callout. If you need something else, you will
need to change the callout code. File a pull request if you think it's
useful!  Or you can ask on the [Apigee community
site](https://www.googlecloudcommunity.com/gc/Apigee/bd-p/cloud-apigee).


## Runtime Dependencies

* Bouncy Castle: bcprov-jdk15on-1.6x.jar, bcpkix-jdk15on-1.6x.jar

The BouncyCastle jar is available as part of the Apigee runtime, although it is
not a documented part of the Apigee platform and is therefore not guaranteed to
remain available in subsequent releases. In the highly unlikely future scenario in which Apigee removes
the BC jar from the Apigee runtime, you could simply upload the BouncyCastle jar
as a resource, either with the apiproxy or with the organization or environment,
to resolve the dependency.

## Usage

### Signing

Configure the policy this way:

```xml
<JavaCallout name='Java-XMLDSIG-Sign'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='output-variable'>output</Property>
    <Property name='private-key'>{my_private_key}</Property>
    <!-- optional -->
    <Property name='private-key-password'>{my_private_key_password}</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.xmldsig.Sign</ClassName>
  <ResourceURL>java://apigee-xmldsig-20220920.jar</ResourceURL>
</JavaCallout>
```

This policy will sign the entire document and embed a Signature element as a
child of the root element. The signature will embed a KeyInfo element containing
an RSAKeyValue.


To embed a certificate into the signed document, configure the policy this way:

```xml
<JavaCallout name='Java-XMLDSIG-Sign'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='output-variable'>output</Property>
    <Property name='private-key'>{my_private_key}</Property>
    <Property name='certificate'>{my_certificate}</Property>

    <Property name='key-identifier-type'>x509_cert_direct</Property>
    <!-- or x509_cert_direct_and_issuer_serial -->
  </Properties>
  <ClassName>com.google.apigee.callouts.xmldsig.Sign</ClassName>
  <ResourceURL>java://apigee-xmldsig-20220920.jar</ResourceURL>
</JavaCallout>
```

This policy will sign the entire document and embed a Signature element as a
child of the root element. The signature will embed a KeyInfo element containing
an X509Data element, embedding the X509Certificate (and optionally the
X509IssuerSerial element).


The available properties _for signing_ are:

| name                   | description |
| ---------------------- | ------------ |
| `source`               | optional. the variable name in which to obtain the source document to sign. Defaults to `message.content` |
| `output-variable`      | optional. the variable name in which to write the signed XML. Defaults to message.content |
| `signing-method`       | optional. Either `rsa-sha1` or `rsa-sha256`. Defaults to `rsa-sha256`. |
| `digest-method`        | optional. Either `sha1` or `sha256`. Defaults to `sha256`. |
| `private-key`          | required. the PEM-encoded RSA private key. You can use a variable reference here as shown above. Probably you want to configure your proxy to read this from encrypted KVM. |
| `private-key-password` | optional. The password for the key if any. |
| `key-identifier-type`  | optional. One of { `RSA_KEY_VALUE`, `X509_CERT_DIRECT`, `X509_CERT_DIRECT_AND_ISSUER_SERIAL` }. Defaults to `RSA_KEY_VALUE` |
| `issuer-name-style`    | optional. One of { `COMMON_NAME`, `DN` }. Defaults to `COMMON_NAME`. Used only when `key-identifier-type` is `X509_CERT_DIRECT_AND_ISSUER_SERIAL` .  |
| `certificate`          | optional. Specifies the PEM-encoded certificate to embed into the signed document. Useful only when `key-identifier-type` is `X509_CERT_DIRECT` or `X509_CERT_DIRECT_AND_ISSUER_SERIAL` . |

The `key-identifier-type` tells the signing callout how to format the KeyInfo element in the signed document.  Some examples are:
* `RSA_KEY_VALUE`
  ```
   <KeyInfo>
     <KeyValue>
       <RSAKeyValue>
         <Modulus>B6PenDyT58LjZlG6LYD27IFCh1yO+4...yCP9YNDtsLZftMLoQ==</Modulus>
         <Exponent>AQAB</Exponent>
       </RSAKeyValue>
     </KeyValue>
   </KeyInfo>
  ```

* `X509_CERT_DIRECT`
  ```
   <KeyInfo>
     <X509Data>
       <X509Certificate>MIICAjCCAWugAw....AQnI7IYAAKzz7BQnulQ=</X509Certificate>
     </X509Data>
   </KeyInfo>
  ```

* `X509_CERT_DIRECT_AND_ISSUER_SERIAL`
  ```
   <KeyInfo>
     <X509Data>
       <X509IssuerSerial>
         <X509IssuerName>CN=issuer-common-name</X509IssuerName>
         <X509SerialNumber>1323432320</X509SerialNumber>
       </X509IssuerSerial>
       <X509Certificate>MIICAjCCAWugAw....AQnI7IYAAKzz7BQnulQ=</X509Certificate>
     </X509Data>
   </KeyInfo>
  ```

### Validating

If you have a public key, configure the policy this way:

```xml
<JavaCallout name='Java-XMLDSIG-Validate'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='key-identifier-type'>RSA_KEY_VALUE</Property>
    <Property name='public-key'>{my_public_key}</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.xmldsig.Validate</ClassName>
  <ResourceURL>java://apigee-xmldsig-20220920.jar</ResourceURL>
</JavaCallout>
```

if you want to validate the signature using a certificate that is embedded within the signed document, configure the policy this way:

```xml
<JavaCallout name='Java-XMLDSIG-Validate'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='key-identifier-type'>X509_CERT_DIRECT</property>
    <Property name='certificate-thumbprint'>{sha1-thumbprint-of-acceptable-cert}</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.xmldsig.Validate</ClassName>
  <ResourceURL>java://apigee-xmldsig-20220920.jar</ResourceURL>
</JavaCallout>
```

The available properties _for validating_ are:

| name             | description |
| ---------------- | ------------ |
| `source`         | optional. the variable name in which to obtain the source signed document to validate. Defaults to `message.content` |
| `signing-method` | optional. Either `rsa-sha1` or `rsa-sha256`. If set, checks that the signature uses this signing method. |
| `digest-method`  | optional. Either `sha1` or `sha256`. If set, checks that the signature uses this digest method. |
| `public-key`     | optional. the PEM-encoded RSA public key. You can use a variable reference here as shown above. |
| `key-identifier-type` | optional. Either `RSA_KEY_VALUE` or `X509_CERT_DIRECT`. Defaults to `RSA_KEY_VALUE`. If you specify  `X509_CERT_DIRECT`, the policy will extract the certificate from the signed document, and extract the public key from that certificate. You must set `certificate-thumbprint` in this case, to the SHA-1 thumbprint of the trusted certificate. By default, this policy checks the validity of the certificate - that "right now" is before the certificate notAfter date, and  after the notBefore date. |
| `omit-certificate-validity-check` | optional. Specify `true` or `false`, defaults to `false`. If `true`, the policy will not perform a validity check on the certificate (a check of the notBefore and notAfter dates). This is not recommended! It means the policy might accept as valid, a certificate that is expired. |
| `certificate-thumbprints` | optional. a comma-separated list of acceptable SHA-1 thumbprints of the certificates that are trusted. Don't use this setting, if possible. Instead use the S256 version. This property is used only when `key-identifier-type` is `X509_CERT_DIRECT`. |
| `certificate-thumbprints-s256` | optional. a comma-separated list of acceptable SHA-256 thumbprints of the certificates that are trusted. This takes precedence over the deprecated `certificate-thumbprints`.  This property is used only when `key-identifier-type` is `X509_CERT_DIRECT`. |
| `reform-signedinfo`      | optional. Specify `true` to tell the validating callout to reform the `SignedInfo` element to remove spaces and newlines, before validating the signature. Omit this if you'd like to avoid unnecessary busy work. |

The result of the Validate callout is to set a single variable: xmldsig_valid.  It takes a true value if the signature was valid; false otherwise. You can use a Condition in your Proxy flow to examine that result.


See [the example API proxy included here](./bundle) for a working example of these policy configurations.


## Example API Proxy Bundle

Deploy the API Proxy to an organization and environment using a tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js/blob/master/examples/importAndDeploy.js)

There are some sample documents included in this repo that you can use for demonstrations.

There are two distinct private keys embedded in the API Proxy. Both are RSA keys. Key 1 was generated this way:

```
 openssl genpkey -aes-128-cbc -algorithm rsa \
     -pkeyopt rsa_keygen_bits:2048 \
     -out encrypted-genpkey-aes-128-cbc.pem
```

Key 2 generated with the "older" openssl syntax, this way:
```
openssl genrsa -des3 -out private-encrypted-DES-EDE3-CBC.pem 2048
```

Either form of PEM-encoded key works.

### Invoking the Example proxy:

* Signing with key 1

   ```
   # Apigee Edge
   ORG=myorgname
   ENV=myenv
   endpoint=https://${ORG}-${ENV}.apigee.net
   # Apigee X or hybrid
   endpoint=https://my-apigee-hostname.example.org

   curl -i $endpoint/xmldsig/sign1  -H content-type:application/xml \
       --data-binary @./sample-data/order.xml
   ```

* Signing with key 2

   ```
   curl -i $endpoint/xmldsig/sign2  -H content-type:application/xml \
       --data-binary @./sample-data/order.xml
   ```

* Signing with key 3 and embedding the cert into the signed document

   ```
   curl -i $endpoint/xmldsig/sign3  -H content-type:application/xml \
       --data-binary @./sample-data/order.xml
   ```

* Validating with key 1

   ```
   curl -i $endpoint/xmldsig/validate1  -H content-type:application/xml \
       --data-binary @./sample-data/order-signed1.xml
   ```
   The output of the above is "true", meaning "The signature on the document is valid."

* Validating with key 2

   ```
   curl -i $endpoint/xmldsig/validate2  -H content-type:application/xml \
       --data-binary @./sample-data/order-signed2.xml
   ```
   The output of the above is "true", meaning "The signature on the document is valid."

* Validation fails with incorrect key

   ```
   curl -i $endpoint/xmldsig/validate2  -H content-type:application/xml \
      --data-binary @./sample-data/order-signed1.xml
   ```
   Because order-signed1 was signed with private key 1, validating it against public key 2 (via /validate2) will return "false", meaning "The signature on the document is not valid."  This is expected.

* Validation fails with incorrect key, case 2

   ```
   curl -i $endpoint/xmldsig/validate1  -H content-type:application/xml \
       --data-binary @./sample-data/order-signed2.xml
   ```

   Because order-signed1 was signed with private key 2, validating it
   against public key 1 (via /validate1) will return "false", meaning
   "The signature on the document is not valid."  This is expected.


* Validating a signed document that has an embedded certificate:

   ```
   curl -i $endpoint/xmldsig/validate3  -H content-type:application/xml \
       --data-binary @./sample-data/order-signed3.xml
   ```
   The output of the above is "true", meaning "The signature on the document is valid."


### Example of Signed Output

Supposing the input XML looks like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<order>
  <customer customerNumber="0815A4711">
    <name>Michael Sonntag</name>
    <address>
      <street>Altenbergerstr. 69</street>
      <ZIP>4040</ZIP>
      <city>Linz</city>
    </address>
  </customer>
  <articles>
    <line>
      <quantity unit="piece">30</quantity>
      <product productNumber="9907">XML editing widget</product>
      <price currency="EUR">0.10</price>
    </line>
    <line>
      <quantity unit="litre">5</quantity>
      <product productNumber="007">Super juice</product>
      <price currency="HUF">500</price>
    </line>
  </articles>
  <delivery>
    <deliveryaddress>
      <name>Michael Sonntag</name>
      <address>
        <street>Auf der Wies 18</street>
      </address>
    </deliveryaddress>
  </delivery>
  <payment type="CC">
    <creditcard issuer="Mastercard">
      <nameOnCard>Mag. Dipl.-Ing. Dr. Michael Sonntag</nameOnCard>
      <number>5201 2345 6789 0123</number>
      <expiryDate>2006-04-30</expiryDate>
    </creditcard>
  </payment>
</order>
```

...the signed payload (with the default settings) looks like this:

```
<?xml version="1.0" encoding="UTF-8" standalone="no"?><order>
  <customer customerNumber="0815A4711">
    <name>Michael Sonntag</name>
    <address>
      <street>Altenbergerstr. 69</street>
      <ZIP>4040</ZIP>
      <city>Linz</city>
    </address>
  </customer>
  <articles>
    <line>
      <quantity unit="piece">30</quantity>
      <product productNumber="9907">XML editing widget</product>
      <price currency="EUR">0.10</price>
    </line>
    <line>
      <quantity unit="litre">5</quantity>
      <product productNumber="007">Super juice</product>
      <price currency="HUF">500</price>
    </line>
  </articles>
  <delivery>
    <deliveryaddress>
      <name>Michael Sonntag</name>
      <address>
        <street>Auf der Wies 18</street>
      </address>
    </deliveryaddress>
  </delivery>
  <payment type="CC">
    <creditcard issuer="Mastercard">
      <nameOnCard>Mag. Dipl.-Ing. Dr. Michael Sonntag</nameOnCard>
      <number>5201 2345 6789 0123</number>
      <expiryDate>2006-04-30</expiryDate>
    </creditcard>
  </payment>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>Rtv+iAkC0p7hJbs3741vK/V7eV92EuEk+hb6IUXVhME=</DigestValue></Reference></SignedInfo><SignatureValue>w9Fqn9Dx22xh++HgU4YeyZ0ndYcWj17IHrV2eZ17dj2U5o3de2IAmvg2jdLJxs99GLstOonhv/cK
b7mzpI6tGyUTfGwhS5l1Ok8DFooxDT7KvJ6RXBuWFuuNYa+iN+fLbxBOg5D8gAOVC1qsOCas7bs8
CSkzVWRZRxl6JJuaOpyJ6xM3nIdkSAqGYnChljQuGI6UXgru/KKc4mASCjkyzknzoJa4fv9C2enY
9E7LZ4z+KqdtyK5xjifLXxfIIDAF+9hQUzIe+Wm4otZ0p7pQX6LEYVifkLoJbaLdsw8KTHYcF+XS
8d6qUENo/WnHp0dCLxzFZISnumCAt6DHHah3/A==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>B6PenDyGOg0P5vb5DfJ13DmjJi82KdPT58LjZlG6LYD27IFCh1yO+4ygJAxfIB00muiIuB8YyQ3T
JKgkJdEWcVTGL1aomN0PuHTHP67FfBPHgmCM1+wEtm6tn+uoxyvQhLkB1/4Ke0VA7wJx4LB5Nxoo
/4GCYZp+m/1DAqTvDy99hRuSTWt+VJacgPvfDMA2akFJAwUVSJwh/SyFZf2yqonzfnkHEK/hnC81
vACs6usAj4wR04yj5yElXW+pQ5Vk4RUwR6Q0E8nKWLfYFrXygeYUbTSQEj0f44DGVHOdMdT+BoGV
5SJ1ITs+peOCYjhVZvdngyCP9YNDtsLZftMLoQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature></order>
```

## Important Note

XML Digital Signature is sensitive to whitespace!

The signature is computed over a sub-tree in an XML Document. Before signing,
the signer normalizes the sub-tree with a "canonicalization" (aka C14N)
algorithm. The standard C14N algorithm preserves line breaks and white spaces
(see http://www.w3.org/TR/xml-c14n#Example-WhitespaceInContent).

Signing a document results in inserting a Signature element with a SignedInfo
child element into the document. Most signers produce a SignedInfo element that
has no newlines or whitespace, as shown in the examples above. This can make it
difficult for humans to read or parse, which encourages humans to "pretty print"
the signedd XML. Be careful when doing so!

* If you sign a sub-tree within a document, then modify the whitespace of the
  sub-tree that has been signed, then validating the signature will fail.

* But, if you sign a sub-tree within a document, then modify the SignedInfo
  element that denotes the thing that has been signed, for example, by inserting
  newlines and indents to make it more legible, validating the signature will
  fail.

This is just how XML Signature works. It's not particular to this callout, or
its use within Apigee.

There is one partial mitigation for this - you can tell the callout to "reform"
the `SignedInfo` element before validating, to remove all spaces and
newlines. Do this by adding the `reform-signedinfo` property to the callout
configuration. This will not work to avoid whitespace problems with the signed
sub-tree! It works only on the `SignedInfo` element.

To avoid all of this, do not modify the signed document before validation.

## Support

This is open source software. It is officially unsupported. You may ask
questions or request assistance by posting to the [Apigee community
site](https://www.googlecloudcommunity.com/gc/Apigee/bd-p/cloud-apigee).


## Bugs

None reported.
