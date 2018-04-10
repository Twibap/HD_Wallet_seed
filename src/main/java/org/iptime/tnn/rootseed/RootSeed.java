package org.iptime.tnn.rootseed;

import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * 결정적 종자 지갑을 생성하기 위한 클래스이다.
 *
 * CSPRNG(보안화된 유사난수 생성기)를 사용해 무작위열(엔트로피)를 생성한다.
 * 무작위열을 복원하기 위한 연상 기호를 생성한다.
 * 무작위열로부터 마스터 개인키를 생성할 수 있는 종자키를 생성한다.
 */
public class RootSeed {

    private byte[]              entropy;
    private ArrayList<String>   words;
    private byte[]              seed;

    public RootSeed(){
        entropy = getEntropy(128 );	// 128 bits = 16 * 8 bits
        seed 	= pbkdf2(bytesToHex(entropy));
        words	= toMnemonicCode();
    }

    public static void main(String[] args) {
        RootSeed seed = new RootSeed();

        System.out.println("Entropy : "+seed.getEntropyStr());
        System.out.println("Words	: "+seed.getWords());
        System.out.println("Seed	: "+seed.getSeedStr());
        System.out.println();

        String reEntropyStr = bytesToHex(seed.toEntropy());
        System.out.println("Words to Entropy : ");
        System.out.println(reEntropyStr);
        System.out.println(bytesToHex(seed.pbkdf2(reEntropyStr)));
    }

    /**
     * 무작위 숫자열을 생성한다.
     * @param bits
     * @return
     */
    private byte[] getEntropy(int bits){
        byte[] result = new byte[ bits/8 ];

        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        assert random != null;
        random.nextBytes(result);

        return result;
    }


    /**
     * Byte 배열을 Hex 표현으로 전환한다.
     * @param bytes
     * @return hex string
     */
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * key-stretching 함수
     * 엔트로피로부터 마스터키와 체인 코드를 생성할 수 있는 Hash를 생성한다.
     *
     * @param password
     * @return
     */
    private byte[] pbkdf2(String password) {
        String salt = "소금";
        int iterations = 100;
        int keyLength = 512;
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, keyLength);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
//            return new String(Base64.getEncoder().encode(hash));
//            return new String(bytesToHex(hash));
            return hash;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("error on pbkdf2", e);
        }
    }

    /**
     * 엔트로피로부터 연상 기호를 얻는다.
     *
     * 1. 엔트로피의 SHA256 Hash에서 검사합을 구한다.
     *    검사합은 엔트로피 비트 자리수 / 32 이다.
     * 2. 검사합을 엔트로피의 끝에 합친다.
     * 3. 겁사합을 합친 엔트로피를 11비트씩 나눈 후 2048개로 구성된 사전의 색인으로 사용한다.
     *
     * 엔트로피(비트) | 검사합(비트)    | 엔트로피+검사합  | 단어 갯수
     * 128            | 4 (엔트로피/32) | 132              | 12 ((엔트로피+검사합) / 11)
     * 160            | 5               | 165              | 15
     * 192            | 6               | 198              | 18
     * 224            | 7               | 231              | 21
     * 256            | 8               | 264              | 24
     *
     * @return
     */
    private ArrayList<String> toMnemonicCode(){
        MnemonicCode mnemonicHelper = MnemonicCode.INSTANCE;
        ArrayList<String> result = null;
        try {
            result = (ArrayList<String>) mnemonicHelper.toMnemonic(entropy);
        } catch (MnemonicException.MnemonicLengthException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * 연상 단어열로부터 엔트로피를 복원한다.
     * @return
     */
    private byte[] toEntropy(){
        MnemonicCode mnemonicHelper = MnemonicCode.INSTANCE;
        byte[] result = null;
        try {
            return mnemonicHelper.toEntropy(words);
        } catch ( MnemonicException.MnemonicLengthException
                | MnemonicException.MnemonicWordException
                | MnemonicException.MnemonicChecksumException e) {
            e.printStackTrace();
        }
        return result;
    }

    // Getter and no Setter
    byte[] getEntropy(){
        return entropy;
    }
    String getEntropyStr(){
        return bytesToHex(entropy);
    }
    ArrayList<String> getWords(){
        return words;
    }
    byte[] getSeed(){
        return seed;
    }
    String getSeedStr() {
        return bytesToHex(seed);
    }
}
