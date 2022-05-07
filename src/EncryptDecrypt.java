/**
 * 
 */

/**
 * @author krishna
 *
 */
public class EncryptDecrypt {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		final String secretKey = "test";

		String originalString = "Krishna";
		String encryptedString = AES.encrypt(originalString, secretKey) ;
		String decryptedString = AES.decrypt(encryptedString, secretKey) ;

		System.out.println(originalString);
		System.out.println(encryptedString);
		System.out.println(decryptedString);	

	}

}
