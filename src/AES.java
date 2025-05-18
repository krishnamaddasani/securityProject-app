import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * @author krishna - 2/23/2024
 *
 */
public class AES {

	private static SecretKeySpec secretKey;

	public static void setKey(final String myKey) {
		MessageDigest sha = null;
		try {
			byte[] key = myKey.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	public static String encrypt(final String strToEncrypt, final String secret) {
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			byte[] iv = new byte[12];
			SecureRandom secureRandom = new SecureRandom();
			secureRandom.nextBytes(iv);
			GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
			byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes("UTF-8"));
			byte[] encryptedData = new byte[iv.length + cipherText.length];
			System.arraycopy(iv, 0, encryptedData, 0, iv.length);
			System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);
			return Base64.getEncoder().encodeToString(encryptedData);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}

	public static String decrypt(final String strToDecrypt, final String secret) {
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			byte[] encryptedData = Base64.getDecoder().decode(strToDecrypt);
			byte[] iv = Arrays.copyOfRange(encryptedData, 0, 12);
			byte[] cipherText = Arrays.copyOfRange(encryptedData, 12, encryptedData.length);
			GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
			return new String(cipher.doFinal(cipherText), "UTF-8");
		} catch (Exception e) {
			System.out.println("Error while decrypting: " + e.toString());
		}
		return null;
	}
	
	public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
	    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	    keyGenerator.init(n);
	    SecretKey key = keyGenerator.generateKey();
	    return key;
	}

}
