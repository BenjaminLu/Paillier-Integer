package benjaminlu.paillier;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Created by BenjaminLu on 2015/5/22.
 */
public class PublicKey implements Serializable
{
    private int bitLength;
    private BigInteger n;
    private BigInteger nSquared;
    private BigInteger g;

    public PublicKey(int bitLength, BigInteger n)
    {
        this.bitLength = bitLength;
        this.n = n;
        this.nSquared = n.multiply(n);
        this.g = n.add(BigInteger.ONE);
    }

    public int getBitLength()
    {
        return bitLength;
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getNSquared()
    {
        return nSquared;
    }

    public BigInteger getG()
    {
        return g;
    }

    public boolean equals(PublicKey otherPublicKey)
    {
        return this.n.equals(otherPublicKey.getN());
    }
}
