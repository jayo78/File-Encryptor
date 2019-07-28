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

// AES in CBC (cipher block chaining) mode takes a secret key to encrypt or decrypt an input 
// of arbitrary length by padding the input to reach a multiple of an AES block size. Then 
// encrypting or decrypting each block and xoring to the next plaintext block for encryption
// starting with an initial block, the initialization vector. The encrypted blocks are then 
// appended for a full cipher text output

// the Cipher object in the given transformation implements CBC mode with
// padding and a secure random IV (initialization vector), which is required for
// CBC.

// this class provides the fields necessary for encryption and decryption in CBC mode.
// allows subclasses to implement the actual encryption or decryption through
// the abstract doMode method, which returns a byte array output.

public abstract class CBCMode
{
	public final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

	protected SecretKey key;
	protected Cipher cipher;

	public abstract byte[] doMode(byte[] input) throws NoSuchAlgorithmException,
										   			   NoSuchPaddingException,
										   			   InvalidKeyException,
										   			   IllegalBlockSizeException,
										   			   BadPaddingException,
										   			   InvalidAlgorithmParameterException, 
										   			   InvalidKeySpecException;
	// returns the key
	
	public SecretKey getKey()
	{
		return key;
	}
}
