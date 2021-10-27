import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class AES {

    public IvParameterSpec generateIv() {    //no sé... tengo duda con este
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public void generateKey(Integer size){   //generates an AES key of size n
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(size);
            SecretKey key = keyGenerator.generateKey();
            saveFile(Base64.getEncoder().encode(key.getEncoded()), "");
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Regresa un array de strings con la informacion del archivo considerando lo siguiente:
     * retorna solo una string si el archivo es la llave
     * retorna solo una string si el archivo es el plaintext
     * retorna dos strings si rl archivo es el encriptado, una string para el iv y otra para el cipher text
     * @param name
     * @param base64
     * @return
     * @throws IOException
     */
    public ArrayList<String> readFile(String name, boolean base64) throws IOException {
        ArrayList<String> res = new ArrayList<>();
        File f = new File(name+".txt");
        byte[] content;
        if(!base64){
            content = Files.readAllBytes(Paths.get(f.getAbsolutePath()));
            res.add(new String(content));
        }else{
            List<String> tmp = Files.readAllLines(Paths.get(f.getAbsolutePath()));
            res = new ArrayList<>(tmp);
        }
        return res;
    }

    public void saveFile(byte[] content, String name) throws IOException {
        if(name.isEmpty()){
            System.out.print("Choose a file name to save the key (Without extension): ");
            Scanner reader = new Scanner(System.in);
            name = reader.next();
        }
        File f = new File(name+".txt");
        FileOutputStream stream = new FileOutputStream(f.getAbsolutePath());
        stream.write(content);
        System.out.println("Data saved successfully in file "+ f.getName());
    }

    public void encryptAES(String keyName, String fileName, Integer mode, Integer variation) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String instance = "AES/CBC/PKCS5Padding"; //Default
        SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(readFile(keyName, true).get(0)), "AES");
        ArrayList<String> data = readFile(fileName, mode==2);
        byte[] text;
        IvParameterSpec iv;
        if(mode==1){
            text = data.get(0).getBytes(StandardCharsets.UTF_8);
            iv = generateIv();
        }else{
            iv = new IvParameterSpec(Base64.getDecoder().decode(data.get(0)));
            text = Base64.getDecoder().decode(data.get(1));
        }

        switch (variation){
            case 1: instance = "AES/CBC/PKCS5Padding";  break;
            case 2: instance = "AES/CTR/PKCS5Padding";  break;
            case 3: instance = "AES/CFB/PKCS5Padding";  break;
        }

        Cipher cipher = Cipher.getInstance(instance);
        cipher.init(mode, key, iv);
        byte[] resultt = cipher.doFinal(text);
        String fileContent;
        if(mode==1){
            //DOs lineas, la primera con el iv y la otra con la encriptacion, ambas en base64
            fileContent = new String(Base64.getEncoder().encode(iv.getIV())) + "\n"  + new String(Base64.getEncoder().encode(resultt));
        }else{
            fileContent = new String(resultt); //Sin base64 porque es plaintext
        }
        saveFile(fileContent.getBytes(StandardCharsets.UTF_8), fileName+ (mode==1 ? "enc": "dec")); //Al nombre del archivo se le agrega enc/dec dependiendo que sea
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        AES aes = new AES();
        //aes.generateKey(128);

        System.out.println("1. Generate Key\n2. Encrypt/Decrypt with AES");
        Scanner reader = new Scanner(System.in);
        Integer choice = reader.nextInt();
        reader.nextLine();

        if(choice==1) {
            System.out.print("Key size (128, 192 or 256): ");
            aes.generateKey(reader.nextInt());
        }
        else  {
            System.out.print("Key file (Without extension): ");
            String keyFile = reader.nextLine();
            System.out.print("File to encrypt/decrypt (Without extension): ");
            String file = reader.nextLine();
            System.out.println("(1) Encrypt\n(2) Decrypt");   //ENCRYPT_MODE=1, DECRYPT_MODE=2
            Integer mode = reader.nextInt();
            System.out.println(("(1) CBC\n(2) CTR\n(3) CFB"));
            Integer variation = reader.nextInt();
            aes.encryptAES(keyFile,file, mode, variation);
        }
    }
}
