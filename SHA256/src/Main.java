import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main
{
    private static byte[] getSalt() throws NoSuchAlgorithmException
    {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        return salt;
    }

    private static String hash(String passwordToHash, byte[] salt)
    {
        String generatedPassword = null;

        try
        {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte[] bytes = md.digest(passwordToHash.getBytes());
            StringBuilder sb = new StringBuilder();

            for(int i=0; i< bytes.length ;i++)
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));

            generatedPassword = sb.toString();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }

        return generatedPassword;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException
    {
        String password1 = "Password!";
        String password2 = "Password";

        byte[] salt1 = getSalt();
        byte[] salt2 = getSalt();

        String securePass1 = hash(password1, salt1);
        String securePass2 = hash(password2, salt2);

        System.out.println(securePass1);
        System.out.println(securePass2);
    }
}
