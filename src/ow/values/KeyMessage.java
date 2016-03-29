package ow.values;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class KeyMessage implements Serializable {
	/**
	 * The session key.
	 */
	private byte[] ktmp;
	/**
	 * The message.
	 */
	private byte[] msg;
	
	public KeyMessage (PublicKey pubKey, String msg) {
		// Generate the key session.
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256); // for example
			SecretKey secretKey = keyGen.generateKey();
			
			// Cipher the message with the key session then save it.
			System.out.print ("Encrypting the message with the session key…  ");
			this.msg = cipher (msg.getBytes("UTF-8"), secretKey);
			System.out.println ("  [OK]");
			// Cipher the key session with the public key then save it.
			System.out.print ("Encrypting the key, with the public key…  ");
			ktmp =  cipher (secretKey.getEncoded(), pubKey);
			System.out.println ("  [OK]");
			
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
		}
		
	}
	
	/**
	 * Cipher an array of bytes, thanks to a RSA public key.
	 * @param plain
	 * @param pubKey
	 * @return
	 */
	private byte[] cipher (byte[] plain, PublicKey pubKey) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA");

			//System.out.println (pubKey);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			//System.out.println ("Init : OK !");
			return cipher.doFinal(plain);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException|
				IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();

			return null;
			
		}
		
	}
	
	/**
	 * Cipher an array of bytes, thanks to a AES key.
	 * @param plain
	 * @param pubKey
	 * @return
	 */
	private byte[] cipher (byte[] plain, SecretKey pubKey) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES");

			//System.out.println (pubKey);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			//System.out.println ("Init : OK !");
			return cipher.doFinal(plain);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException|
				IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();

			return null;
			
		}
		
	}
	
	/**
	 * Decrypt an array of byte, with a RSA private key.
	 * @param data
	 * @param privKey
	 * @return
	 */
	public byte[] decrypt (byte[] data, PrivateKey privKey) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			
			cipher.init(Cipher.DECRYPT_MODE, privKey); //privKey stored earlier
			
			return cipher.doFinal(data);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return data;
			
		}
		
	}
	
	/**
	 * Decrypt an array of byte, with an AES key.
	 * @param data
	 * @param privKey
	 * @return
	 */
	public byte[] decrypt (byte[] data, SecretKey privKey) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES");
			
			cipher.init(Cipher.DECRYPT_MODE, privKey); //privKey stored earlier
			
			return cipher.doFinal(data);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return data;
			
		}
		
	}
	
	public byte[] getMsg (PrivateKey privKey) {
		SecretKeySpec sks;
		
		// Decrypt the key session with the publick key.
		System.out.print ("Decrypting the key with the public key…  ");
		sks = new SecretKeySpec(decrypt (ktmp, privKey), "AES");
		System.out.println ("  [OK]");
		
		// Decrypt the message with the key session.
		// Return the message in plaintext, as an array of byte.
		System.out.println ("Decrypting the message with the session key…  ");
		return decrypt (this.msg, sks);
			
	}
	
	/**
	 * @return This instance as an array of bytes.
	 */
	public byte[] inByte () {
		ByteArrayOutputStream bos = new ByteArrayOutputStream ();   //
		ObjectOutput out = null;
		
		try {
			out = new ObjectOutputStream (bos);   // Write to bos.
			out.writeObject(this);   // Serialize this object.
			return bos.toByteArray ();   // Return this object as an array of bytes.
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			try {
				if (out != null)
					out.close ();
				
			}catch (IOException ex) {}
			try {
				bos.close ();
				
			}catch (IOException ex) {}
			
		}
		return null;
	    
	}
	/**
	 * @param  pnvBytes  A PrivaNetValue object as an array of bytes.
	 * @return  An instance of PrivaNetValue unserialized from the parameter, if possible. Else null.
	 */
	public static KeyMessage getFromByte (byte[] kmInByte) {
		ObjectInput in = null;
		// Set pvnBytes as the source.
		
		if (kmInByte == null)
			return null;
		
		ByteArrayInputStream bis = new ByteArrayInputStream (kmInByte);  
		
		try {
			in = new ObjectInputStream (bis);   // Set bis as the source.
			return (KeyMessage)in.readObject ();   // Return the instance. 
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			try {
				bis.close ();
			} catch (IOException ex) {}
			try {
				if (in != null)
					in.close ();
				
			} catch (IOException ex) {}
			
		}
		return null;
		
	}
	/**
	 * @return  This instance in base64 format.
	 */
	public String inBase64 () {
		return Base64.encode (this.inByte ());
		
	}
	/**
	 * @param  bs64   A base64 String encoding a PrivaNetValue object.
	 * @return  An instance of PrivaNetValue decoded from bs64.
	 */
	public static KeyMessage getFromBase64 (String bs64) {
		return getFromByte (Base64.decode (bs64));
		
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
