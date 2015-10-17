package com.david.encryptpractice;


import android.content.SharedPreferences;
import android.os.Bundle;

import android.support.v7.app.AppCompatActivity;

import android.util.Base64;
import android.util.Log;
import android.view.View;

import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.david.encryptpractice.utils.EncryptUtil;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private EditText etContent;
    private TextView tvEncryptData;
    private TextView tvDecryptData;
    private KeyPair keyPair;
    private PrivateKey privateKey=null;
    private PublicKey publicKey=null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        etContent= (EditText) findViewById(R.id.et_content);
        tvEncryptData= (TextView) findViewById(R.id.tv_encrypt);
        tvDecryptData= (TextView) findViewById(R.id.tv_decrypt);


        SharedPreferences sharedPreferences=getSharedPreferences("key", MODE_PRIVATE);

        int oldNum=sharedPreferences.getInt("logNum", 0);

        if(oldNum==0){
            keyPair = EncryptUtil.generateRSAKeyPair(1024);
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            SharedPreferences.Editor editor=sharedPreferences.edit();
            List<String>list=EncryptUtil.outputRSAKey(privateKey, publicKey);
            oldNum=1;
            if(list!=null){
                editor.putInt("logNum",oldNum);
                editor.putString("privateKey",list.get(0));
                editor.putString("publicKey",list.get(1));
                editor.commit();
            }
        }else{

            String priKey=sharedPreferences.getString("privateKey","noKey");
            String pubKey=sharedPreferences.getString("publicKey","noKey");
            Log.i("priKey",priKey);
            Log.i("pubKey",pubKey);
            if(!priKey.equals("noKey")) {
                privateKey = EncryptUtil.importPriKey(priKey);
            }
            if(!pubKey.equals("noKey")){
                publicKey=EncryptUtil.importPubKey(pubKey);
            }
        }


    }

    public void rasEncryptTest(View view) {
        String content=etContent.getText().toString();


//        PublicKey publicKey = keyPair.getPublic();
        if(publicKey!=null) {
            byte[] encryptData = EncryptUtil.rsaEncrypt(content.getBytes(), publicKey);
            String encryptStr = Base64.encodeToString(encryptData, Base64.NO_WRAP);
            try {
                FileOutputStream fos = new FileOutputStream("content.txt");
                fos.write(encryptStr.getBytes());
                fos.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            tvEncryptData.setText(encryptStr);
        }

    }

    public void rasDecryptTest(View view) {
//        PrivateKey privateKey = keyPair.getPrivate();
        if(privateKey!=null) {
            String oldStr = tvEncryptData.getText().toString();
            byte[] decode = Base64.decode(oldStr, Base64.NO_WRAP);
            byte[] bytes = EncryptUtil.rsaDecrypt(decode, privateKey);
            String str = new String(bytes);
            tvDecryptData.setText(str);
        }

    }
}
