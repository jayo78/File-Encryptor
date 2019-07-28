package testing;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.Test;

import cbc.CBCMode;
import cbc.CBCPassphraseDecrypt;
import cbc.CBCPassphraseEncrypt;

class StringEncryptionTesting
{

	@Test
	public void stringEncryption()
	{
		try
		{
			// encrypt / decrypt with same passphrase
			CBCMode encrypt = new CBCPassphraseEncrypt("waffles");
			CBCMode decrypt = new CBCPassphraseDecrypt("waffles");

			String toEncrypt = "Encrypt me!";
			byte[] encrypted = encrypt.doMode(toEncrypt.getBytes());
			
			// print the encrypted bytes in string form to console
			String encryptedString = new String(encrypted);
			System.out.println("ENCRYPTED STRING: " + encryptedString);

			String decrypted = new String(decrypt.doMode(encrypted));

			assertEquals(decrypted, "Encrypt me!");

		} catch (NoSuchAlgorithmException | InvalidKeySpecException
			| NoSuchPaddingException | InvalidKeyException
			| IllegalBlockSizeException | BadPaddingException
			| InvalidAlgorithmParameterException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Test
	public void samePassphraseDifferentSalt()
	{
		try
		{
			CBCPassphraseEncrypt encrypt = new CBCPassphraseEncrypt("waffles");
			CBCPassphraseEncrypt encrypt1 = new CBCPassphraseEncrypt("waffles");

			assertFalse(encrypt.getSalt() == encrypt1.getSalt());
			assertFalse(encrypt.getKey() == encrypt1.getKey());
			assertFalse(encrypt.doMode("string".getBytes()) == encrypt1
				.doMode("string".getBytes()));

		} catch (NoSuchAlgorithmException | InvalidKeySpecException
			| NoSuchPaddingException | InvalidKeyException
			| IllegalBlockSizeException | BadPaddingException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Test    
	// keys hashed with same passphrase and salt should be equal.
	// encrypting with the same key, however, should produce unequal cipher text outputs.
	// keys should be 256 bits in length
	
	public void samePassphraseSameSalt()
	{
		try
		{
			CBCPassphraseEncrypt encrypt = new CBCPassphraseEncrypt();
			CBCPassphraseEncrypt encrypt1 = new CBCPassphraseEncrypt();

			// create 16 byte salt
			byte[] salt = new byte[16];

			encrypt.setKey("waffles", salt);
			encrypt1.setKey("waffles", salt);

			// hashes to same 256 bit (32 bytes) AES key
			assertEquals(encrypt.getKey(), encrypt1.getKey());
			assertEquals(encrypt.getKey().getEncoded().length, 32);

			// still encryptes to different cipher texts due to the random IV
			assertFalse(encrypt.doMode("string".getBytes()) == encrypt1
				.doMode("string".getBytes()));

		} catch (NoSuchAlgorithmException | NoSuchPaddingException
			| InvalidKeySpecException | InvalidKeyException
			| IllegalBlockSizeException | BadPaddingException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
