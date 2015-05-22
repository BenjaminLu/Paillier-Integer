#Paillier Integer
Paillier Integer is a well-tested, pure java implementation of [Paillier cryptosystem](http://en.wikipedia.org/wiki/Paillier_cryptosystem).

##Install
You can find the jar file that built with the jdk 1.8 (version 1.8.0_25) under the bin folder.

##Usage

###Generate key pair of Paillier cryptosystem

```java
PrivateKey privateKey = new PrivateKey(2048);
PublicKey publicKey = privateKey.getPublicKey();
```

###Encrypt a number

```java
BigInteger message = new BigInteger("5");
Cipher cipher = new Cipher(message, publicKey);
//ciphertext of five
System.out.println(cipher.getCipher());
```

###Decrypt a number from ciphertext

```java
BigInteger message = new BigInteger("5");
Cipher cipher = new Cipher(message, publicKey);
//print 5
System.out.println(cipher.decrypt(privateKey));
```

###Addition of positive constant

```java
BigInteger a = new BigInteger("5");
BigInteger b = new BigInteger("6");
Cipher cipher = new Cipher(a, publicKey);
cipher = cipher.add(b);
//print 11
System.out.println(cipher.decrypt(privateKey));
```

###Addition of encrypted integers

```java
BigInteger a = new BigInteger("5");
BigInteger b = new BigInteger("6");
Cipher cipherA = new Cipher(a, publicKey);
Cipher cipherB = new Cipher(b, publicKey);
try {
    cipherA = cipherA.add(cipherB);
} catch (PublicKeysNotEqualException e) {
    e.printStackTrace();
}
//print 11
System.out.println(cipherA.decrypt(privateKey));
```

###Subtract to negative
```java
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
//subtract N if you are pretty sure that the answer is negative
ans = ans.subtract(publicKey.getN());
assertEquals(expected, ans);
```


### Bad addition of encrypted integers

```java
PrivateKey privateKey1 = new PrivateKey(2048);
PublicKey publicKey1 = privateKey1.getPublicKey();
PrivateKey privateKey2 = new PrivateKey(2048);
PublicKey publicKey2 = privateKey2.getPublicKey();

BigInteger a = new BigInteger("5");
BigInteger b = new BigInteger("6");

Cipher cipherA = new Cipher(a, publicKey1);
Cipher cipherB = new Cipher(b, publicKey2);

try {
    //it will fail to execute add operation
    cipherA = cipherA.add(cipherB);
} catch (PublicKeysNotEqualException e) {
    e.printStackTrace();
}
```

###Multiplication of constant

```java
BigInteger a = new BigInteger("5");
BigInteger b = new BigInteger("6");
Cipher cipher = new Cipher(a, publicKey);
cipher = cipher.multiply(b);
//print 30
System.out.println(cipher.decrypt(privateKey));
```

###Randomize

Randomization is useful so a server does not know that you are resubmitting a value they have already processed. Randomizing the encrypted integer without needing the private key is based on the homomorphic properties to add a randomly encrypted zero.

```java
BigInteger a = new BigInteger("5");
Cipher cipher = new Cipher(a, publicKey);
BigInteger cipherValue1 = cipher.getCipher();
BigInteger plainValue1 = cipher.decrypt(privateKey);
cipher.randomize();
BigInteger cipherValue2 = cipher.getCipher();
BigInteger plainValue2 = cipher.decrypt(privateKey);
System.out.println(cipherValue1 + " is not equal to " + cipherValue2);
System.out.println(plainValue1 + " is equal to " + plainValue2);
```

###Serialization of cipher

####By cipher

```java
BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
Cipher cipher = new Cipher(a, publicKey);
BigInteger cipherValue = cipher.getCipher();
//send cipherValue to receiver
Cipher cipher = new Cipher(publicKey, cipherValue);
```

####By Serializable interface

```java
BigInteger a = new BigInteger(512, rng);
Cipher cipher = new Cipher(a, publicKey);

ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeObject(cipher);
byte[] serializedCipher = baos.toByteArray();

//load cipher from disk or internet
ByteArrayInputStream bais = new ByteArrayInputStream(serializedCipher);
ObjectInputStream ois = new ObjectInputStream(bais);
Cipher cipherReadFromDiskOrInternet = (Cipher) ois.readObject();
assertEquals(a, cipherReadFromDiskOrInternet.decrypt(privateKey));
```
###Serialization of key pair

Private key

```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeObject(privateKey);
byte[] serializedPrivateKey = baos.toByteArray();

//load private key from disk or internet
ByteArrayInputStream bais = new ByteArrayInputStream(serializedPrivateKey);
ObjectInputStream ois = new ObjectInputStream(bais);
PrivateKey privateKeyReadFromDiskOrInternet = (PrivateKey) ois.readObject();
BigInteger result = cipher.decrypt(privateKeyReadFromDiskOrInternet);
```
Public key

```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeObject(publicKey);
byte[] serializedPublicKey = baos.toByteArray();

//load public key from disk or internet
ByteArrayInputStream bais = new ByteArrayInputStream(serializedPublicKey);
ObjectInputStream ois = new ObjectInputStream(bais);
PublicKey publicKeyReadFromDiskOrInternet = (PublicKey) ois.readObject();

Cipher cipher = new Cipher(message, publicKeyReadFromDiskOrInternet);
BigInteger result = cipher.decrypt(privateKey);
```

##License
Code and documentation copyright 2015 Benjamin Lu. Code released under the MIT license.