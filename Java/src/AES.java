import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class AES {
    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    public void testVectors(){
        System.out.println("\nProve of AES correctness using the Known Answer Test (KAT) vectors");
        //Create zero keys
        byte[] key128 = new byte[16];
        byte[] key192 = new byte[24];
        byte[] key256 = new byte[32];

        byte[] plaintext128 = hexStringToByteArray("f34481ec3cc627bacd5dc3fb08f273e6");
        byte[] plaintext192 = hexStringToByteArray("1b077a6af4b7f98229de786d7516b639");
        byte[] plaintext256 = hexStringToByteArray("014730f80ac625fe84f026c60bfd547d");

        try {
            System.out.println("\nTest of CBC mode");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key128, "AES"), new IvParameterSpec(key128));
            System.out.println("result128 = " + byteArrayToHex(cipher.doFinal(plaintext128)));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key192, "AES"), new IvParameterSpec(key128));
            System.out.println("result192 = " + byteArrayToHex(cipher.doFinal(plaintext192)));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key256, "AES"), new IvParameterSpec(key128));
            System.out.println("result256 = " + byteArrayToHex(cipher.doFinal(plaintext256)));

            System.out.println("\nTest of CTR mode");
            //According to NIST document, counter mode is tested by selecting the ECB mode
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key128, "AES")/*, new IvParameterSpec(key128)*/);
            System.out.println("result128 = " + byteArrayToHex(cipher.doFinal(plaintext128)));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key192, "AES")/*, new IvParameterSpec(key128)*/);
            System.out.println("result192 = " + byteArrayToHex(cipher.doFinal(plaintext192)));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key256, "AES")/*, new IvParameterSpec(key128)*/);
            System.out.println("result192 = " + byteArrayToHex(cipher.doFinal(plaintext256)));

            System.out.println("\nTest of CFB mode");
            cipher = Cipher.getInstance("AES/CFB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key128, "AES"), new IvParameterSpec(plaintext128));
            System.out.println("result128 = " + byteArrayToHex(cipher.doFinal(new byte[1])));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key192, "AES"), new IvParameterSpec(plaintext192));
            System.out.println("result192 = " + byteArrayToHex(cipher.doFinal(new byte[1])));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key256, "AES"), new IvParameterSpec(plaintext256));
            System.out.println("result256 = " + byteArrayToHex(cipher.doFinal(new byte[1]))+"\n");

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public IvParameterSpec generateIv() {    
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public void generateKey(Integer size){   //generates an AES key of size n
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(size);
            SecretKey key = keyGenerator.generateKey();
            System.out.println("key = " + Arrays.toString(key.getEncoded()));
            saveFile(Base64.getEncoder().encode(key.getEncoded()), "");
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Regresa un array de strings con la informacion del archivo considerando lo siguiente:
     * retorna solo una string si el archivo es la llave
     * retorna solo una string si el archivo es el plaintext
     * retorna dos strings si el archivo es el encriptado, una string para el iv y otra para el cipher text
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
        byte[] result = cipher.doFinal(text);
        String fileContent;
        if(mode==1){
            //DOs lineas, la primera con el iv y la otra con la encriptacion, ambas en base64
            fileContent = new String(Base64.getEncoder().encode(iv.getIV())) + "\n"  + new String(Base64.getEncoder().encode(result));
        }else{
            fileContent = new String(result); //Sin base64 porque es plaintext
        }
        saveFile(fileContent.getBytes(StandardCharsets.UTF_8), fileName+ (mode==1 ? "enc": "dec")); //Al nombre del archivo se le agrega enc/dec dependiendo que sea
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        AES aes = new AES();
        aes.testVectors();
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
