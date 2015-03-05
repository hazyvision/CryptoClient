import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;


public final class Jce {

    public static void main(String[] args) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        Key key = KeyGenerator.getInstance("AES").generateKey();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] plainText = "Hello World!".getBytes("UTF-8");
        byte[] cipherText = cipher.doFinal(plainText);
        System.out.println(new String(cipherText));
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decipheredText = cipher.doFinal(cipherText);
        System.out.println(new String(decipheredText));
    }
}