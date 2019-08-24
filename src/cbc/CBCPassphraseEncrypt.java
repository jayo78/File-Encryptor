package cbc;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

// Creates an object to handle encryption in CBC mode with a passPhrase and salt
// extends the abstract CBCMode class to implement CBC encryption in the doMode() method
// using a SecretKey, generated securely from a passphrase and salt, with input from a byte array 

public class CBCPassphraseEncrypt extends CBCMode
{

	private byte[] salt;

	// default constructor, must set key later**
	
	public CBCPassphraseEncrypt() throws NoSuchAlgorithmException,
					     NoSuchPaddingException, 
					     InvalidKeySpecException
	{
		this("password");
	}

	// generates the key from a pass phrase and random salt through the PBKDF2
	// secure PBE hashing algorithm, implemented in the GenerateKey class

	public CBCPassphraseEncrypt(String passPhrase) throws NoSuchAlgorithmException,
							      InvalidKeySpecException,
							      NoSuchPaddingException
	{
		this.salt = GenerateKey.getRandomSalt();
		this.key = GenerateKey.genKey(passPhrase, this.salt);
		cipher = Cipher.getInstance(TRANSFORMATION);
	}

	// encrypt the input using a Cipher instance
	// pack the IV and salt into the resultant header (32 bits)
	// the output will be of the format: SALT + IV + ENCRYPTEDBYTES
	
	public byte[] doMode(byte[] toEncrypt) throws NoSuchAlgorithmException,
						      NoSuchPaddingException,
						      InvalidKeyException,
						      IllegalBlockSizeException,
						      BadPaddingException
	{		
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] result;
		byte[] IV = cipher.getIV(); // 16 byte SecureRandom iv from cipher
									// instance
		
		// the initial resultant Length will include the IV and salt
		int resultLength = IV.length + salt.length;

		// encrypt ---
		// the resulting encrypted bytes will most likely contain
		// more bytes than the input, due to the padding
		// so we add the encryptedBytes length instead of
		// the input length
		byte[] encryptedBytes = cipher.doFinal(toEncrypt);
		resultLength += encryptedBytes.length;

		result = new byte[resultLength];

		// pack the IV along with the salt 
		// to the beginning (header) of the result
		// - neither the IV or salt are considered secrets
		// so we can include them before the encrypted bytes
		// The result: SALT + IV + ENCRYPTEDBYTES
		int pos = 0;
		
		packBytes(salt, result, pos);
		pos += salt.length;
		
		packBytes(IV, result, pos);
		pos += IV.length;

		packBytes(encryptedBytes, result, pos);

		return result;
	}

	// pack a byte array to another at a given position

	private void packBytes(byte[] toPack, byte[] b, int pos)
	{
		if (toPack.length <= (b.length - pos))
		{
			for (int i = 0; i < toPack.length; i++)
			{
				b[pos] = toPack[i];
				pos++;
			}
		}
	}

	// return the salt

	public byte[] getSalt()
	{
		return salt;
	}
	
	// set the key with random salt and passphrase arg
	
	public void setKey(String passPhrase, byte[] salt) throws NoSuchAlgorithmException, 
								  InvalidKeySpecException
	{
		if(salt.length != 16)
			throw new IllegalArgumentException();
		
		this.salt = salt;
		this.key = GenerateKey.genKey(passPhrase, salt);
	}
	


}
