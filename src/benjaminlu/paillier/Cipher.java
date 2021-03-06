package benjaminlu.paillier;

import benjaminlu.paillier.exceptions.PublicKeysNotEqualException;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Created by BenjaminLu on 2015/5/22.
 */
public class Cipher implements Serializable
{
    private Random rng;
    private PublicKey publicKey;
    private BigInteger cipher;

    public Cipher(PublicKey publicKey)
    {
        this(BigInteger.ZERO, publicKey);
    }

    public Cipher(PublicKey publicKey, BigInteger cipher)
    {
        this.rng = new SecureRandom();
        this.publicKey = publicKey;
        this.cipher = cipher;
    }

    public Cipher(BigInteger plaintext, PublicKey publicKey)
    {
        this.rng = new SecureRandom();
        this.publicKey = publicKey;
        this.cipher = encrypt(plaintext);
    }

    private BigInteger encrypt(BigInteger plaintext)
    {
        BigInteger r;
        BigInteger n = publicKey.getN();
        BigInteger nSquared = publicKey.getNSquared();
        do {
            r = new BigInteger(publicKey.getBitLength(), rng);
        } while (r.compareTo(n) >= 0);

        BigInteger g = publicKey.getG();
        return g.modPow(plaintext, nSquared).multiply(r.modPow(n, nSquared)).mod(nSquared);
    }

    public BigInteger decrypt(PrivateKey privateKey)
    {
        BigInteger plaintext;
        BigInteger inputOfLFunction = cipher.modPow(privateKey.getLambda(), publicKey.getNSquared());
        BigInteger outputOfLFunction = inputOfLFunction.subtract(BigInteger.ONE).divide(publicKey.getN());
        plaintext = outputOfLFunction.multiply(privateKey.getMu()).mod(publicKey.getN());
        return plaintext;
    }

    public Cipher add(Cipher other) throws PublicKeysNotEqualException
    {
        if (!publicKey.equals(other.getPublicKey())) {
            throw new PublicKeysNotEqualException("Cannot perform add operation with different public keys");
        }

        BigInteger resultCipher = cipher.multiply(other.getCipher()).mod(publicKey.getNSquared());
        return new Cipher(publicKey, resultCipher);
    }

    public Cipher add(BigInteger plaintext)
    {
        BigInteger g = publicKey.getG();
        BigInteger resultCipher = cipher.multiply(g.modPow(plaintext, publicKey.getNSquared())).mod(publicKey.getNSquared());
        return new Cipher(publicKey, resultCipher);
    }

    public Cipher multiply(BigInteger plaintext)
    {
        BigInteger resultCipher = cipher.modPow(plaintext, publicKey.getNSquared());
        return new Cipher(publicKey, resultCipher);
    }

    public void randomize()
    {
        BigInteger r;
        BigInteger n = publicKey.getN();
        BigInteger nSquared = publicKey.getNSquared();
        do {
            r = new BigInteger(publicKey.getBitLength(), rng);
        } while (r.compareTo(n) >= 0);

        BigInteger randomZeroCipher = r.modPow(n, nSquared);
        cipher = cipher.multiply(randomZeroCipher).mod(publicKey.getNSquared());
    }

    public static Cipher encryptWithR(BigInteger plaintext, PublicKey publicKey, BigInteger r)
    {
        BigInteger n = publicKey.getN();
        BigInteger nSquared = publicKey.getNSquared();
        BigInteger g = publicKey.getG();
        BigInteger cipher = g.modPow(plaintext, nSquared).multiply(r.modPow(n, nSquared)).mod(nSquared);
        return new Cipher(publicKey, cipher);
    }

    public BigInteger getTrapdoorR(PrivateKey privateKey)
    {
        BigInteger m = decrypt(privateKey);
        BigInteger intermediateC = cipher.modPow(BigInteger.ONE, publicKey.getN()).multiply(publicKey.getG().modPow(m.negate(), publicKey.getN())).mod(publicKey.getN());
        BigInteger r = intermediateC.modPow(publicKey.getN().modPow(BigInteger.ONE.negate(), privateKey.getLambda()), publicKey.getN());
        return r;
    }

    public BigInteger getCipher()
    {
        return cipher;
    }

    public byte[] getCipherBytes()
    {
        return cipher.toByteArray();
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }
}
