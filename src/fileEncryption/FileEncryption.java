package fileEncryption;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import cbc.CBCMode;
import cbc.CBCPassphraseDecrypt;
import cbc.CBCPassphraseEncrypt;

// contains methods to enable file encryption and decryption
// using the AES block cipher in CBC mode.
// the 256 bit AES key is hashed from a passphrase
// and salt, utilizing the PBKDF2 secure hashing algorithm.

public class FileEncryption
{

	//*********TODO************
	// secure file wipe method
	
	
	// return the bytes from a file in a byte array
	
	public static byte[] loadDataFromFile(String filePath) throws IOException
	{
		File file = new File(filePath);
		byte[] output = new byte[(int) file.length()];

		try (FileInputStream in = new FileInputStream(file))
		{
			in.read(output);
		}
		
		return output;
	}
	
	// write data to a file
	
	public static void writeDataToFile(String filePath, byte[] data) throws FileNotFoundException, 
																			IOException
	{
		try (FileOutputStream out = new FileOutputStream(new File(filePath)))
		{
			out.write(data);
		}
	}

	// checks whether a file exists at the specified path
	// returns a boolean indicating the file's existence
	
	public static boolean fileExists(String filePath)
	{
		File file = new File(filePath);
		
		return file.exists();
	}
	
	// encrypts a file using a passPhrase argument
	// encryption is implemented through a CBCPassphraseEncrypt object
	// after the plaintext bytes are loaded.
	// the encrypted bytes are then written to a new .enc file, retaining the original 
	// file input name
	
	public static void encrypt(String passPhrase, String fileIn) throws NoSuchAlgorithmException, 
																 		InvalidKeySpecException, 
																 		NoSuchPaddingException, 
																 		InvalidKeyException, 
																 		IllegalBlockSizeException, 
																 		BadPaddingException, 
																 		InvalidAlgorithmParameterException, 
																 		IOException
	{
		CBCMode enc = new CBCPassphraseEncrypt(passPhrase);
		
		byte[] encBytes = enc.doMode(loadDataFromFile(fileIn));
		
		writeDataToFile(fileIn + ".enc", encBytes);
	}
	
	// decrypts a .enc file to plain text, using a passPhrase argument
	// decryption is implemented through a CBCPassphraseDecrypt object
	// after the encryped bytes are loaded.
	// the plaintext bytes are then written to a new file
	
	public static void decrypt(String passPhrase, String fileIn) throws IOException, 
																		NoSuchAlgorithmException, 
																		InvalidKeySpecException, 
																		NoSuchPaddingException, 
																		InvalidKeyException, 
																		IllegalBlockSizeException, 
																		BadPaddingException, 
																		InvalidAlgorithmParameterException 
	{
		if(fileExists(fileIn.substring(0, fileIn.lastIndexOf("."))))
		{
			throw new IOException("A file with that name already exists, move or rename it");
		}
		
		CBCMode dec = new CBCPassphraseDecrypt(passPhrase);
		
		byte[] plain = dec.doMode(loadDataFromFile(fileIn));
		
		writeDataToFile(fileIn.substring(0, fileIn.lastIndexOf(".")), plain);
	}
}
