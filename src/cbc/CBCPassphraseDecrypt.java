package cbc;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

// Creates an object to handle decryption in CBC mode with a passPhrase and salt
// requires that the IV and salt be included in the input header for extraction.
// extends the abstract CBCMode class to implement CBC decryption in the doMode() method
// using the SecretKey and cipher instance with input from a byte array

public class CBCPassphraseDecrypt extends CBCMode
{
	private String passPhrase;
	
	// default constructor, must set passphrase later**

	public CBCPassphraseDecrypt() throws NoSuchAlgorithmException,
					     NoSuchPaddingException
	{
		this("");
	}

	// constructor to accept a passphrase.
	// a salt will be extracted from cipher texts and used with this passphrase
	// to construct the decryption key

	public CBCPassphraseDecrypt(String passPhrase) throws NoSuchAlgorithmException,
							      InvalidKeySpecException,
							      NoSuchPaddingException
	{	
		this.passPhrase = passPhrase;
		cipher = Cipher.getInstance(TRANSFORMATION);
	}

	// unpack the IV and salt from the 32 bit header 
	// construct the key from the salt and passphrase
	// attempt to decrypt the input with the key and IV
	// -- will fail if the 32 bit header is invalid
	// -- must follow: SALT + IV + ENCRYPTEDBYTES

	public byte[] doMode(byte[] toDecrypt) throws InvalidKeyException,
						      InvalidAlgorithmParameterException,
						      IllegalBlockSizeException,
						      BadPaddingException, 
					              NoSuchAlgorithmException, 
						      InvalidKeySpecException
	{
		// get the salt, update input, and generate the key
		byte[] salt = unpackBytes(toDecrypt, 16, 0);
		toDecrypt = deleteBytes(toDecrypt, 16);
		this.key = GenerateKey.genKey(passPhrase, salt);

		// get the IV and update input
		byte[] IV = unpackBytes(toDecrypt, 16, 0);
		toDecrypt = deleteBytes(toDecrypt, 16);

		// wrap IV with an IV specification for use in the cipher instance
		IvParameterSpec IVspec = new IvParameterSpec(IV);

		cipher.init(Cipher.DECRYPT_MODE, key, IVspec);

		// decrypt ---
		// attempts to decrypt the input after the IV and
		// salt have been unpacked
		// return the decrypted input
		return cipher.doFinal(toDecrypt);
	}

	// unpack a number of bytes from a byte array and return them in new byte
	// array

	private byte[] unpackBytes(byte[] toUnpack, int numBytes, int pos)
	{
		byte[] result = new byte[numBytes];

		if ((toUnpack.length - pos) >= numBytes)
		{
			for (int i = 0; i < result.length; i++)
			{
				result[i] = toUnpack[pos];
				pos++;
			}
		}

		return result;
	}

	// deletes bytes starting from index 0 from a byte array by
	// returning a new array without the specified number of bytes

	private byte[] deleteBytes(byte[] b, int numBytes)
	{
		byte[] result = new byte[b.length - numBytes];
		int pos = numBytes;

		for (int i = 0; i < result.length; i++)
		{
			result[i] = b[pos];
			pos++;
		}

		return result;
	}
	
	// set the passPhrase for use in decryption
	
	public void setPassphrase(String passPhrase)
	{
		this.passPhrase = passPhrase;
	}
}
