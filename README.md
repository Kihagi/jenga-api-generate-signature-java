# jenga-api-generate-signature-java
Generate header signature from private key in Java - https://developer.jengaapi.io/
## Creating private & public keys

Note:
This post is an attempt to document what worked for me. There are definitely other signing methods out there, but I finally got PKCS#8 with an RSA key in PEM format to work in Java.

The default private key generated using the command outlined in the jenga api documentation seems to be in PKCS#1 format and not in PKCS#8 format. It __will not work__ using this code! You can distinguish between the two formats by taking a look at the header, `BEGIN RSA PRIVATE KEY` vs. `BEGIN PRIVATE KEY`(This is the correct format)!

Here's how to do it:

First, generate a new RSA keypair using `openssl` as per jengaapi documentation:
```bash
openssl genrsa -out privatekey.pem 2048 -nodes
```
Once you are successful with the above command a file (pkcs8_privatekey.pem) will be created on your present directory, proceed to export the public key from the keypair generated. The command below shows how to do it:
```bash
openssl genrsa -out privatekey.pem 2048 -nodes
```
If the above command is successful, a new file (publickey.pem) will be created on your present directory. Copy the contents of this file and add it on our jengaHQ portal.

_Important:_ Now, __for Java__, you need to convert the RSA key into a PKCS#8 encoded key in PEM format:
```bash
openssl pkcs8 -topk8 -in privatekey.pem -nocrypt -outform PEM -out pkcs8_privatekey.pem
```

## Generate Signature
Now that you've got a PKCS#8 encoded key, you can easily use the PKCS8EncodedKeySpec class to parse the key for signing. Here's the code that signs a message (a String) using `SHA256withRSA`

Required library: `common-codec-1.6` _maven dependency can be found in the project._

```java
package com.mathenge.cryptography;

import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Signs a byte array (a message) using a PKCS#8 encoded
 * RSA private key.
 */
public class SignRSA
{
    public static void main( String[] args ) {

        //Replace with the data you want to sign e.g 0011547896523KE2018-08-09
        String dataStringToSign = "0011547896523KE2018-08-09";

        String base64Signature = "";

        // Replace with your private key!
        String privateKeyString = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCvcUCbs7unnr1m\n" +
                "LRE5w2tEkUdGiftEIe0g0QpWKHWu54RAiuO6opTrIMlvi19PEF+gWz9gXjgczP4k\n" +
                "jwkSUpk0EDtFMTavlojKD4iHsWm+Pj8DPRm/RvkFKeqB9j9ORQFu9BROP0IwFIc3\n" +
                "KZbm3ndPdi4d/qIeEOCuRmsvasi+1PHKKSiEKgYXnKwmbgg61xxiOZ0RQSNiRaVK\n" +
                "Hw8+dz+Da54P1K9ngsDoTh6qbqrLL2F5T+BeqT22GaqcVaev+7P0Ymoi2WFsuogS\n" +
                "iF/1wgLd7sAqdGeRgTh88zmhAEjZAS9T7xUoneSk4tXxjeV4m2LN375QQXBIA3Ay\n" +
                "D17hVq3tAgMBAAECggEAdTsoAOLIsejQhkX3DLIYK2koR2pMC+rfmN4WGhxPBuCM\n" +
                "7tPf+AZLnBH8iByJQzudqnlOkAZlWFliOOubFDM9TBzMfh+0ewALx3k5sfJKxmSx\n" +
                "lmhtm/LA00J/APiatKJHouxV5TM/9wDAmYug2gQtlVtS1ZggnBaLC+jiFn00Rs7I\n" +
                "kZQW+q2MFG1zuZWHJH0ZMEwXEZevEr/z6bmbJttwNyw7+LiIZ7WXbRhVDwdo4lYg\n" +
                "qL+DOzOFI+1UPETW34IL5+Qw2xh2Z05KDaNM4rBuUQSqn8vLQ3lJtsjr+gZXcogG\n" +
                "utGiOjjxc5wWbi5usLs3YdKK+aRw+HNo1tbQQ44jwQKBgQDcWjKRoNUPyuHxysLI\n" +
                "DE833ro5b8GuPbxmUbT6Iuu/L849UQWFBtntMftw5DJPRQRA7vqU8r9Iw4eC9aGd\n" +
                "9ZLZkZfn2qO5x3++jvVAKumrD6Zyx+pQ4C3po855SXB/qMVTakq6grULgT4bxeno\n" +
                "P7h87nyzzGe40OWbUWb6E6q/CwKBgQDL0yC5COfc8NL/t+6XG+SY9ESDigdDglsA\n" +
                "bwdgZiVSYvmVSC7X4Ud20XLvZDvX9apoeU8lGpgdB5n2xVQ95Oo8camIvXIRhrXe\n" +
                "ZUkT+OEJItGiYWEmaRdep6YvWTtRIjT6G3I81dOkODwxLZOLrY7DqCT0LtUSTdfE\n" +
                "ivvIotfB5wKBgQDGaQUtsdcHYFRwhnU68jKGiSu/ugx4myhALYQ60yTZQu9+sKy6\n" +
                "qn+iH6ZbcW6HiAqbeVPyuF1a5Izpc8lx1QTEmV9hqrJP/v3clRbqD3nVyMLEiZRH\n" +
                "/IP6479v4JvGpy3+vS/KnxTr5hUJpvzGXlH9VDS/JOekN5z3bKW/ueO+HwKBgQCv\n" +
                "XIFd0USzeVr/+f7DcZMW6an8xgeD1KZ41A2zqY5YuKDlCAqNX9w9ZOyO/FzkbA9l\n" +
                "/WDTmnLfHwgfIR1edxH0WRI0fFGktJLKubfLACiU1KkqHMAZ7PbXUEQRnqMDJfwQ\n" +
                "Zwa9QnbpZhybbwvvc65Ntd+9WoGlUuXdynnf4ALjZwKBgQCmO2hPTCqGkb2uayTr\n" +
                "SOTF5pUMN/mNmvWB5bAut5cPJ3MdQOtX6oQp3JfhSaxpRvb1RuMeXxGAAiqphq05\n" +
                "VQFDxCCn3EW5l8OPkqUAmjazG2vesvhwk3gmk34J+brHoqtS4TiOU41FnenHklxB\n" +
                "pkViMBI2XRsTDMUvF1AWK3EV5w==\n" +
                "-----END PRIVATE KEY-----";

        RSAPrivateKey rsaPrivateKey = null;
        try {
            rsaPrivateKey = getPrivateKeyFromString(privateKeyString);
            //Sign
            base64Signature = sign(rsaPrivateKey, dataStringToSign);

        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        System.out.println("Signature::::: " + base64Signature);
    }

    /**
     * Create RSAPrivateKey Object from the Private Key String using PKCS8EncodedKeySpec
     */
    private static RSAPrivateKey getPrivateKeyFromString(String privateKeyPEM) throws IOException, GeneralSecurityException {

        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.decodeBase64(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) kf.generatePrivate(keySpec);
    }

    /**
     * Create base64 encoded signature using SHA256/RSA.
     */
    private static String sign(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, UnsupportedEncodingException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(privateKey);
        sign.update(message.getBytes("UTF-8"));
        return new String(Base64.encodeBase64(sign.sign()), "UTF-8");
    }
}

```

