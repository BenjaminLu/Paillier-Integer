package benjaminlu.paillier.test;

import benjaminlu.paillier.Cipher;
import benjaminlu.paillier.PrivateKey;
import benjaminlu.paillier.PublicKey;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import benjaminlu.paillier.exceptions.PublicKeysNotEqualException;
import org.junit.*;

import static org.junit.Assert.*;

public class CipherTest
{
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Random rng;
    private int N_BIT_LENGTH = 1024;
    private int NUMBER_BIT_LENGTH = N_BIT_LENGTH / 2;

    @Before
    public void setUp()
    {
        privateKey = new PrivateKey(N_BIT_LENGTH);
        publicKey = privateKey.getPublicKey();
        rng = new SecureRandom();
    }

    @Test
    public void testCreation()
    {
        BigInteger message = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(message, publicKey);
        assertNotNull(cipher);
    }

    @Test
    public void testEncryption()
    {
        BigInteger message = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(message, publicKey);
        assertNotEquals(message, cipher.getCipher());
    }

    @Test
    public void testDecryption()
    {
        BigInteger message = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(message, publicKey);
        assertEquals(message, cipher.decrypt(privateKey));
    }

    @Test
    public void testAdditionOfPositiveConstant()
    {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        BigInteger b = new BigInteger(NUMBER_BIT_LENGTH, rng);
        BigInteger expected = a.add(b);
        expected = expected.mod(publicKey.getN());
        Cipher cipher = new Cipher(a, publicKey);
        cipher = cipher.add(b);
        assertEquals(expected, cipher.decrypt(privateKey));
    }

    @Test
    public void testAdditionOfZeroResult()
    {
        BigInteger a = BigInteger.TEN;
        BigInteger b = BigInteger.TEN.negate();
        BigInteger expected = a.add(b);
        Cipher cipher = new Cipher(a, publicKey);
        cipher = cipher.add(b);
        assertEquals(expected, cipher.decrypt(privateKey));
    }

    @Test
    public void testSubtractionToNegativeResult()
    {
        BigInteger a = BigInteger.ONE;
        BigInteger b = BigInteger.TEN.negate();
        BigInteger expected = a.add(b).mod(publicKey.getN());
        Cipher cipher = new Cipher(a, publicKey);
        cipher = cipher.add(b);
        assertEquals(expected, cipher.decrypt(privateKey));
    }

    @Test
    public void testAdditionOfEncryptedInteger()
    {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        BigInteger b = new BigInteger(NUMBER_BIT_LENGTH, rng);
        BigInteger expected = a.add(b);
        expected = expected.mod(publicKey.getN());
        Cipher cipherA = new Cipher(a, publicKey);
        Cipher cipherB = new Cipher(b, publicKey);
        try {
            cipherA = cipherA.add(cipherB);
        } catch (PublicKeysNotEqualException e) {
            fail();
        }
        assertEquals(expected, cipherA.decrypt(privateKey));
    }

    @Test
    public void testBadAdditionOfEncryptedInteger()
    {
        PrivateKey privateKey2 = new PrivateKey(N_BIT_LENGTH);
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        BigInteger b = new BigInteger(NUMBER_BIT_LENGTH, rng);

        Cipher cipherA = new Cipher(a, publicKey);
        Cipher cipherB = new Cipher(b, privateKey2.getPublicKey());
        try {
            cipherA = cipherA.add(cipherB);
            fail();
        } catch (PublicKeysNotEqualException e) {
        }
    }

    @Test
    public void testMultiplicationOfConstant()
    {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        BigInteger b = new BigInteger(NUMBER_BIT_LENGTH, rng);
        BigInteger expected = a.multiply(b);
        expected = expected.mod(publicKey.getN());
        Cipher cipher = new Cipher(a, publicKey);
        cipher = cipher.multiply(b);
        assertEquals(expected, cipher.decrypt(privateKey));
    }

    @Test
    public void testRandomize()
    {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        a = a.mod(publicKey.getN());
        Cipher cipherA = new Cipher(a, publicKey);
        BigInteger cipherValueA = cipherA.getCipher();
        BigInteger plainValueA = cipherA.decrypt(privateKey);
        cipherA.randomize();
        BigInteger cipherValueA2 = cipherA.getCipher();
        BigInteger plainValueA2 = cipherA.decrypt(privateKey);
        assertNotSame(cipherValueA, cipherValueA2);
        assertEquals(plainValueA, plainValueA2);
    }

    @Test
    public void testSerializableWithCipherValue()
    {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(a, publicKey);
        BigInteger cipherValue = cipher.getCipher();
        //send cipherValue to receiver
        Cipher cipher2 = new Cipher(publicKey, cipherValue);
        assertEquals(cipher.decrypt(privateKey), cipher2.decrypt(privateKey));
    }

    @Test
    public void testSerializableWithCipherBytes()
    {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(a, publicKey);
        byte[] cipherBytes = cipher.getCipherBytes();
        //encode cipherBytes to  base64 or hexadecimal string and send it to receiver or store into disk
        BigInteger cipherValue = new BigInteger(cipherBytes);
        Cipher cipher2 = new Cipher(publicKey, cipherValue);
        assertEquals(cipher.decrypt(privateKey), cipher2.decrypt(privateKey));
    }

    @Test
    public void testSerializableWithInterface() throws IOException, ClassNotFoundException
    {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(a, publicKey);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(cipher);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        Cipher cipherReadFromDiskOrInternet = (Cipher) ois.readObject();
        assertEquals(a, cipherReadFromDiskOrInternet.decrypt(privateKey));
    }

    @Test
    public void testSubtractToNegative()
    {
        BigInteger a = new BigInteger("2000");
        BigInteger b = new BigInteger("3000");
        BigInteger expected = a.subtract(b);
        Cipher cipherA = new Cipher(a, publicKey);
        Cipher cipherB = new Cipher(b, publicKey);

        cipherB = cipherB.multiply(new BigInteger("-1"));
        try {
            cipherA = cipherA.add(cipherB);
        } catch (PublicKeysNotEqualException e) {
            fail();
        }

        BigInteger ans = cipherA.decrypt(privateKey);
        ans = ans.subtract(publicKey.getN());
        assertEquals(expected, ans);
    }
}