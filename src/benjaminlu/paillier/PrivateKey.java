package benjaminlu.paillier;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Created by BenjaminLu on 2015/5/22.
 */
public class PrivateKey implements Serializable
{
    private PublicKey publicKey;
    private BigInteger lambda;
    private BigInteger mu;

    public PrivateKey(int bitLength)
    {
        Random rng = new SecureRandom();
        BigInteger p;
        BigInteger q;
        p = new BigInteger(bitLength / 2, 20, rng);
        q = new BigInteger(bitLength / 2, 20, rng);

        BigInteger n = p.multiply(q);
        p = p.subtract(BigInteger.ONE);
        q = q.subtract(BigInteger.ONE);
        this.lambda = p.multiply(q);

        this.publicKey = new PublicKey(bitLength, n);
        this.mu = this.lambda.modInverse(this.publicKey.getN());
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public BigInteger getLambda()
    {
        return lambda;
    }

    public BigInteger getMu()
    {
        return mu;
    }
}
