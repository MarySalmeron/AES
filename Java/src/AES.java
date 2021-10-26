import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class AES {
    public static IvParameterSpec generateIv() {    //no sé... tengo duda con este
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public void generateKey(int size){   //generates an AES key of size n
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(size);
            SecretKey key = keyGenerator.generateKey();

            System.out.print("Choose a file name to save the key: ");
            Scanner reader = new Scanner(System.in);
            File f = new File("");
            FileOutputStream stream = new FileOutputStream(Paths.get(f.getAbsolutePath(), reader.next()+".txt").toString());
            stream.write( Base64.getEncoder().encode(key.getEncoded()) );
            System.out.println("Key saved successfully!");
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public void encryptAES(String keyName, String fileName, int mode){
        System.out.println("keyName = " + keyName);
        System.out.println("fileName = " + fileName);
        System.out.println("mode = " + mode);
    }

    public static void main(String[] args) {
        AES aes = new AES();
        //aes.generateKey(128);

        System.out.println("1. Generate Key\n2. Encrypt/Decrypt with AES");
        Scanner reader = new Scanner(System.in);
        int choice = reader.nextInt();
        reader.nextLine();

        if(choice==1) {
            System.out.print("Key size (128, 192 or 256): ");   //¿así o con un menú?
            aes.generateKey(reader.nextInt());
        }
        else  {
            System.out.print("Key file: ");
            String keyFile = reader.nextLine();
            System.out.print("File to encrypt/decrypt (include extension): ");
            String file = reader.nextLine();
            System.out.println("(1) Encrypt\n(2) Decrypt");   //ENCRYPT_MODE=1, DECRYPT_MODE=2
            aes.encryptAES(keyFile,file, reader.nextInt());
        }
    }
}
