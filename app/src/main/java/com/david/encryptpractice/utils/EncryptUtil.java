package com.david.encryptpractice.utils;

import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * 常用加密工具类,包含:<br/>
 * <ol>
 * <li>Hex 编码</li>
 * </ol>
 */
public final class EncryptUtil {

    private EncryptUtil() {

    }

    // --------------------------------------------------

    /**
     * 存储公钥和私钥到本地
     * @param privateKey
     * @param publicKey
     */
    public static List<String> outputRSAKey(PrivateKey privateKey,PublicKey publicKey){
        List<String>list=null;
        if(privateKey!=null&&publicKey!=null) {
            list=new ArrayList<>();
            byte[] privateKeyEncoded = privateKey.getEncoded();
            String privateStr = Base64.encodeToString(privateKeyEncoded, Base64.NO_WRAP);
            byte[] publicKeyEncoded = publicKey.getEncoded();
            String publicStr = Base64.encodeToString(publicKeyEncoded, Base64.NO_WRAP);
            list.add(privateStr);
            list.add(publicStr);
        }
        return list;
    }
    public static PrivateKey importPriKey(String privateKey){
       PrivateKey priKey=null;
      if(privateKey!=null){
          try {
              KeyFactory keyFactory=KeyFactory.getInstance("RSA");
              Log.d("keyFactory",""+(keyFactory==null));
              PKCS8EncodedKeySpec keySpec=new PKCS8EncodedKeySpec(Base64.decode(privateKey.getBytes(), Base64.NO_WRAP));
              Log.d("keyFactory",""+(keySpec==null));
              priKey= keyFactory.generatePrivate(keySpec);
              Log.d("priKey",""+(priKey==null));
          } catch (NoSuchAlgorithmException e) {
              e.printStackTrace();
          } catch (InvalidKeySpecException e) {
              e.printStackTrace();
          }

      }
        return priKey;
    }
    public static PublicKey importPubKey(String publicKey){
        PublicKey pubKey=null;
        if(publicKey!=null){
            try {
                KeyFactory keyFactory=KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpec=new X509EncodedKeySpec(Base64.decode(publicKey.getBytes(),Base64.NO_WRAP));
                Log.d("keySpec",""+(keySpec==null));
                pubKey= keyFactory.generatePublic(keySpec);
                Log.d("pubKey",""+(pubKey==null));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }

        }
        return pubKey;
    }

    /**
     * RSA 加密
     *
     * @param data
     * @param key  可以是 PublicKey,也可以是 PrivateKey
     * @return
     */
    public static byte[] rsaEncrypt(byte[] data, Key key) {
        byte[] ret = null;
        if (data != null && data.length > 0 && key != null) {
            // 1. 创建 Cipher 使用 RSA
            try {

                Cipher cipher = Cipher.getInstance("RSA");
                // 设置 Key
                cipher.init(Cipher.ENCRYPT_MODE, key);

                ret = cipher.doFinal(data);

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
        return ret;
    }

    /**
     * RSA 解密
     *
     * @param data
     * @param key  可以是 PublicKey,也可以是 PrivateKey
     * @return
     */
    public static byte[] rsaDecrypt(byte[] data, Key key) {
        byte[] ret = null;
        if (data != null && data.length > 0 && key != null) {
            // 1. 创建 Cipher 使用 RSA
            try {

                Cipher cipher = Cipher.getInstance("RSA");
                // 设置 Key
                cipher.init(Cipher.DECRYPT_MODE, key);

                ret = cipher.doFinal(data);

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
        return ret;
    }

    // RSA 密钥生成

    /**
     * 通过指定的密钥长度,生成非对称的密钥对
     *
     * @param keySize 推荐使用 1024, 2048 不允许低于 1024
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keySize) {
        KeyPair ret = null;

        try {
            // 1. 准备 生成
            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("RSA");

            // 2. 初始化,设置密钥长度
            generator.initialize(keySize);

            // 3. 生成,并且返回
            ret = generator.generateKeyPair();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return ret;
    }


    // --------------------------------------------------

    // AES 带有加密模式的 方法, 形成的加密强度更高, 需要 Iv参数


    public static byte[] aesEncrypt(byte[] data, byte[] keyData, byte[] ivData) {
        return aesWithIv(Cipher.ENCRYPT_MODE, data, keyData, ivData);
    }

    public static byte[] aesDecrypt(byte[] data, byte[] keyData, byte[] ivData) {
        return aesWithIv(Cipher.DECRYPT_MODE, data, keyData, ivData);
    }


    /**
     * @param mode
     * @param data
     * @param keyData
     * @param ivData  用于 AES/CBC/PKCS5Padding 这个带有加密模式的算法
     * @return
     */
    private static byte[] aesWithIv(
            int mode,
            byte[] data,
            byte[] keyData,
            byte[] ivData) {

        byte[] ret = null;

        if (data != null
                && data.length > 0
                && keyData != null
                && keyData.length == 16
                && ivData != null
                && ivData.length == 16
                ) {

            // 支持的 加密模式:
            // AES/CBC/PKCS5Padding
            // AES/ECB/PKCS5Padding
            try {

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                // 密码部分还是设置成 "AES" 即可
                SecretKeySpec keySpec = new SecretKeySpec(keyData, "AES");

                // 准备 Iv 参数,用于 支持 CBC 或者 ECB 模式
                IvParameterSpec iv = new IvParameterSpec(ivData);

                // 设置 密码以及 Iv 参数
                cipher.init(mode, keySpec, iv);

                ret = cipher.doFinal(data);

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }


        }

        return ret;
    }


    // --------------------------------------------------
    // AES 加密与解密 (其中一种设置的方式,采用单一密码的情况) !!!

    public static byte[] aesEncrypt(byte[] data, byte[] keyData) {
        return aesSingle(Cipher.ENCRYPT_MODE, data, keyData);
    }

    public static byte[] aesDecrypt(byte[] data, byte[] keyData) {
        return aesSingle(Cipher.DECRYPT_MODE, data, keyData);
    }

    public static byte[] aesSingle(int mode, byte[] data, byte[] keyData) {
        byte[] ret = null;

        if (data != null
                && data.length > 0
                && keyData != null
                && keyData.length == 16) { // 128bit AES

            try {

                Cipher cipher = Cipher.getInstance("AES");

                // AES 方式1 ,单一密码的情况 不同于 DES
                SecretKeySpec keySpec =
                        new SecretKeySpec(keyData, "AES");

                cipher.init(mode, keySpec);

                ret = cipher.doFinal(data);

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }

        return ret;
    }


    // --------------------------------------------------

    // DES 加密与解密

    private static byte[] des(int mode, byte[] data, byte[] keyData) {
        byte[] ret = null;

        if (data != null
                && data.length > 0
                && keyData != null
                && keyData.length == 8) {

            try {
                Cipher cipher = Cipher.getInstance("DES");

                // 3. 准备 Key 对象
                // 3.1 DES 使用 DESKeySpec, 构造的时候,指定 8个字节的密码即可;
                DESKeySpec keySpec = new DESKeySpec(keyData);

                // 3.2 DESKeySpec 需要转换成 Key对象,才可以继续使用
                //     需要使用 SecretKeyFactory 来处理
                SecretKeyFactory keyFactory
                        = SecretKeyFactory.getInstance("DES");

                // 3.3 生成 Key 对象
                SecretKey key = keyFactory.generateSecret(keySpec);

                // 2. 设置Cipher 是加密还是解密 就是模式
                //    同时对于对称加密,还需要设置密码 Key 对象
                // 参数2 使用 Key 对象
                cipher.init(mode, key);

                // 4. 加密
                // doFinal 方法,可以设置字节数组,作为待加密的内容;
                // 返回值就是最终的加密结果;
                ret = cipher.doFinal(data);

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        }

        return ret;
    }

    public static byte[] desEncrypt(byte[] data, byte[] keyData) {
        return des(Cipher.ENCRYPT_MODE, data, keyData);
    }

    public static byte[] desDecrypt(byte[] data, byte[] keyData) {
        return des(Cipher.DECRYPT_MODE, data, keyData);
    }


    // --------------------------------------------------

    /**
     * 将 字节数组转换为字符串
     * 一个字节会形成两个字符, 最终长度,是原始数据的 2 倍
     *
     * @param data
     * @return
     */
    public static String toHex(byte[] data) {
        String ret = null;

        // TODO 将 字节数组转换为字符串

        if (data != null && data.length > 0) {

            StringBuilder sb = new StringBuilder();

            for (byte b : data) {

                // 分别获取高四位,第四位的内容,将两个数值,专为成字符
                int h = (b >> 4) & 0x0f;
                int l = b & 0x0f;

                char ch, cl;
                if (h > 9) {  // 0x0a ~ 0x0f
                    ch = (char) ('A' + (h - 10));
                } else {  // 0 ~ 9
                    ch = (char) ('0' + h);
                }
                if (l > 9) {
                    cl = (char) ('A' + (l - 10));
                } else {
                    cl = (char) ('0' + l);
                }
                sb.append(ch).append(cl);
            }
            ret = sb.toString();
        }

        return ret;
    }

    public static byte[] fromHex(String str) {
        byte[] ret = null;

        // TODO 将Hex编码的字符串,还原为 原始的字节数组

        if (str != null) {

            int len = str.length();
            // 检查长度是否合法
            if (len > 0 && len % 2 == 0) {

                char[] chs = str.toCharArray();

                ret = new byte[len / 2];

                for (int i = 0, j = 0; i < len - 1; i += 2, j++) {
                    char ch = chs[i];
                    char cl = chs[i + 1];

                    int ih = 0, il = 0, v;

                    if (ch >= 'A' && ch <= 'F') {
                        ih = 10 + (ch - 'A');
                    } else if (ch >= 'a' && ch <= 'f') {
                        ih = 10 + (ch - 'a');
                    } else if (ch >= '0' && ch <= '9') {
                        ih = ch - '0';
                    }

                    if (cl >= 'A' && cl <= 'F') {
                        il = 10 + (cl - 'A');
                    } else if (cl >= 'a' && cl <= 'f') {
                        il = 10 + (cl - 'a');
                    } else if (cl >= '0' && cl <= '9') {
                        il = cl - '0';
                    }

                    v = ((ih & 0x0f) << 4) | (il & 0x0f);
                    // 赋值
                    ret[j] = (byte) v;
                }

            }
        }

        return ret;
    }

}
