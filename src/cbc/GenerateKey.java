package cbc;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

// generate a salted 256 bit key utilizing the PBKDF2 algorithm for secure key hashing.
// uses a set hashing algorithm and number of iterations
// for use with the AES-256 block cipher

public class GenerateKey
{
	private static final String ALGORITHM = "PBKDF2WithHmacSHA1";
	private static final int ITERATIONS = 100000;

	// generate the 256 bit SecretKey using a PBE (Password Based Encryption)
	// specification
	// the SecretKeyFactory instance of the PBKDF2 hashing algorithm
	// returns a type SecretKey which can be encoded to a byte array

	public static SecretKey genKey(String passPhrase, byte[] salt)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		// define a PBE key specification for generating a SecretKey from a passphrase
		// and salt
		KeySpec spec = new PBEKeySpec(passPhrase.toCharArray(), salt,
			ITERATIONS, 256);
		
		// generate the PBE key from the specification using a SecretKeyFactory instance
		SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
		SecretKey PBEKey = factory.generateSecret(spec);
		
		// convert to AES key and return
		return new SecretKeySpec(PBEKey.getEncoded(), "AES");
		
	}

	// generate a random 128 bit salt, which is more than secure considering a
	// collision within 2^64 generations with same password occurrences.
	// uses java's SecureRandom class from java.security to get random bytes for
	// the salt, seeded when nextBytes() is called (from SecureRandom docs).
	// returns the resultant salt byte array

	public static byte[] getRandomSalt()
	{
		SecureRandom sr = new SecureRandom();
		byte[] salt = new byte[16];
		sr.nextBytes(salt);

		return salt;
	}
}
