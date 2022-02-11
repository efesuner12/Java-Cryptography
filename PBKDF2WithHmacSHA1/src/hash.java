import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class hash
{
    private static final int iterations = 1000;
    private static final int keyLength = 512;

    public static String hash(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] salt = getSalt().getBytes();

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();

        return iterations + ":" + toHex(salt) + ":" + toHex(hash);
    }

    private static String getSalt() throws NoSuchAlgorithmException
    {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        return salt.toString();
    }

    private static boolean validatePassword(String original, String stored) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        String[] parts = stored.split(":");
        int iterations = Integer.parseInt(parts[0]);
        byte[] salt = fromHex(parts[1]);
        byte[] hash = fromHex(parts[2]);

        PBEKeySpec spec = new PBEKeySpec(original.toCharArray(), salt, iterations, hash.length * 8);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] testHash = skf.generateSecret(spec).getEncoded();

        int diff = hash.length ^ testHash.length;

        for(int i = 0; i < hash.length && i < testHash.length; i++)
        {
            diff |= hash[i] ^ testHash[i];
        }

        return diff == 0;
    }

    private static String toHex(byte[] array)
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();

        if(paddingLength > 0)
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        else
            return hex;
    }

    private static byte[] fromHex(String hex) throws NoSuchAlgorithmException
    {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length; i++)
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);

        return bytes;
    }

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        String originalPassword = "Password00!";
        String generatedSecuredPasswordHash = hash(originalPassword.toCharArray());
        System.out.println(generatedSecuredPasswordHash);

        boolean matched = validatePassword(originalPassword, generatedSecuredPasswordHash);
        System.out.println(matched);

        matched = validatePassword("Password00", generatedSecuredPasswordHash);
        System.out.println(matched);

        System.out.println("\nPART 2");

        int code1 = 15154578;
        String s = Integer.toString(code1);
        String hash1 = hash(s.toCharArray());

        boolean matchedHashofInt = validatePassword("15154578", hash1);
        System.out.println(matchedHashofInt);

        matchedHashofInt = validatePassword("15154579", hash1);
        System.out.println(matchedHashofInt);
    }
}
