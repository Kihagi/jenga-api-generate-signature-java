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
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyF0f8VV8PPHuO\n" +
                "bQ5PaGANCxVueerlTEYrDOWPvVFUwjlbSsYLWRE3jGj2+9Eqqx6MiGGtwg3rN91F\n" +
                "niJqVJgxq8AbBAHZT6Q7RfIfr4oobhi9o98bVvDrA7y/rVVRXIyazfFfeRh7Nr7l\n" +
                "iHvtnrVPJF51jTFeeYtmibE4Ma7SWdn93AdAemLZae45u0rTRr7u8ehaKM4RH9Ev\n" +
                "hrG7Cux+dISfOTxbSM6lqJaNpd0HeJuWBvqEa4woidZEk+m/9vD7xZ+Vuc2EJi+S\n" +
                "FbYFXVSpths+tMy1m12iuWkZ3owEh0rk/Twr+4E+Rtl87ysnFeru6fIOJLPU1vM3\n" +
                "XFWAigP/AgMBAAECggEADqp2JiSNqH6NmkQG2qk4x7oy8J8fpfRrDt6IBRdNHFLG\n" +
                "UGtO9d5G2bE5b6V7Ky1eXapZiOqjJMy77yC/qsv+oJCJSHBDCrdRSgRPlSZqlTvD\n" +
                "09Ir7F9zhZcQMyS+Eu4xMgplpzwctQDkJZjgw8e/HJ5dHQccmrAdt7r9GiiVQgM6\n" +
                "9WG2vcoUuH8jvGjBCpqdidXqWg9Y3/67lkdt5yhExxWR1GNdXSfoJRGuL0GpimdX\n" +
                "0blgs3EjZtmKM/Rw1F/Ji6UNwN5gFneC5V+Oa9MKj16rSdxo+UdwjkwjaTPru09f\n" +
                "S/EJd03HweIHdsMA9j+2pD0JtMz721M2jUx520eJQQKBgQDnarp8WH4nUTHiK4Lx\n" +
                "b4EhFHdUlTXE/xfR6mVWoDhAy7laLe4cNrUD5UCBqDfOye8VZ66cKvxc+nKDzPD1\n" +
                "O3scoQreeFFyk7rRzSaR32iEPy9oKy3jburttys0tEmK+JKcjCmfzCB6sjy8Yj6t\n" +
                "tb3WcBEK34G5CWHAnNI0S2tn4QKBgQDFAmD0qNwANmb+18pUM9UrCtb4I+0P1lSr\n" +
                "gF/RSClV04nvApLnk7/L1/1L09bYrz3PLav5XxYollpwO3XC0NKjGQFdRT7yl6R1\n" +
                "liSb2l9VBXs8m+nRhszPdtXkE0TL9RZ4+BflaACjPJkcKl4oehZXkbGVRY/VKkZK\n" +
                "oNjQoQ9n3wKBgGT+Hf6QPBX6iFOU+6NULz15ig5ew8WCMioJKkqgx4v3nJ9vdf/Y\n" +
                "HC1kCj/LYvebBv0Hb5t14wbMwdclRG8xkyvOWEj4p0rij+BpsJBuuFUmohDK707X\n" +
                "JC20B2YL3CCLFKi/PpcfZXlGed0Y3xO+QefopndhTWKsZn3BsrbhxzDhAoGBAIg4\n" +
                "a9ffxjbzZuYBSWpNaLDZTujG1ozj0ym+mwI3VjV9DlvQOMmdFLoa/45lzKGJEkDl\n" +
                "wIquH8EyrRf7VSK+h1a03IekcLEG/3U6utd0+APuxVaUK+lvvsAY2C5a0HACaGZ+\n" +
                "jO9XqVE1flzGQtLUEAy+tb6UGa74CyBg9WnUY7WbAoGBAJ+LvUVtiTccZspRj6qi\n" +
                "vkQZJFel+FemzWKAzgfO52WZSQUGBHBDInEVnAZXfH8nZECN8u7GdOP5FSFm+EH+\n" +
                "vbFwJGUdyEahxHibYm8cCNG9ZPbUwBb2JwBmlrYx7oD315+sr1CsTo9b68Ty/1on\n" +
                "1LorLDA89Y+y2iprmMFHUFO7\n" +
                "-----END PRIVATE KEY-----\n";

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
