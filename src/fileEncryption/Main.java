package fileEncryption;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
	
		// usage as executable jar:
		// java -jar FileEncryptor -encrypt/decrypt <file path> <passphrase>
		
		if(args.length != 3)
		{
			System.out.println("Usage: java -jar fileEncryption <encrypt/decrypt> <filePath> <passphrase>");
		}
		
		String mode = args[0];
		String filePath = args[1];
		String passPhrase = args[2];
		
		if(mode.toLowerCase().contains("-enc"))
		{
			FileEncryption.encrypt(passPhrase, filePath);
		}
		
		else if(mode.toLowerCase().contains("-dec"))
		{
			FileEncryption.decrypt(passPhrase, filePath);
		}
	}

}
