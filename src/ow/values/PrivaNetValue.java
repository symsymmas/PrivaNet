package ow.values;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class PrivaNetValue implements Serializable {
	/////////// Fields  ///////////
	/**
	 * Message to save.
	 */
	private String value;
	/**
	 * Certificate to authenticate the user.
	 */
	private X509Certificate certificatRacine;
	
	//////////////// Contructors  ////////////////
	/**
	 * À finir.
	 * Create a certificate and save the value.
	 * @param value   The message to store in the DHT.
	 */
	public PrivaNetValue (String value) {
		certificatRacine = GenerateCertificate (generateKeyPair());
		
		this.value = value;
		
	}
	/**
	 * Only save parameters.
	 * @param Value  The message to store in the DHT.
	 * @param certificatRacine   Certificate used for the authentification, when a user want to access to a PrivaNetValue object.
	 */
	public PrivaNetValue (String value, X509Certificate certificatRacine) {
		this.value = value;
		this.certificatRacine = certificatRacine;
		
	}
	
	/////////////// Getters  ///////////////
	/**
	 * @return The root certificat.
	 */
	public X509Certificate getCertificatRacine () { return certificatRacine; }
	/**
	 * @return The value.
	 */
	public String getValue () { return value; }
	
	////////////  Other methods  ////////////
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
	public static PrivaNetValue getFromByte (byte[] pnvBytes) {
		ObjectInput in = null;
		// Set pvnBytes as the source.
		
		if (pnvBytes == null)
			return null;
		
		ByteArrayInputStream bis = new ByteArrayInputStream (pnvBytes);  
		
		try {
			in = new ObjectInputStream (bis);   // Set bis as the source.
			return (PrivaNetValue)in.readObject ();   // Return the instance. 
			
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
	public static PrivaNetValue getFromBase64 (String bs64) {
		return getFromByte (Base64.decode (bs64));
		
	}
	/**
	 * @param  pvn
	 * @return  True if both fields of the parameter and this instance are equal.
	 */
	public boolean equals (PrivaNetValue pvn) {
		return value.equals(pvn.value) & certificatRacine.equals(pvn.certificatRacine);
		
	}
	/**
	 * @param cert  The certificate used to verify if the user is certified.
	 * @return
	 * True if the certificate of this instance verifies the certificate in parameter or 
	 * if certificatRacine is null (doesn't exist).
	 */
	public boolean Certified (X509Certificate cert) {
		try {
			if (certificatRacine == null)
				return true;
			if (cert == null) {
				//System.out.println ("The certificate is null");
				// System.out.println ("cert is null");
				return false;
				
			}
			cert.verify(certificatRacine.getPublicKey());  // Verify "certificatRacine.getPublicKey()" enable to find the key stored in "cert".
			
			return true;
			
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			// TODO Auto-generated catch block
			
		}
		
		return false;
	}
	/**
	 * @param cert  The certificate used to verify if the user is certified.
	 * @return   True if the certificate of this instance verifies the certificate in parameter.
	 */
	public boolean isCertified (X509Certificate cert) { return Certified (cert); }
	public static KeyPair generateKeyPair () {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");  // RSA key pairs instance.
	        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");   // Instanciate a random system secure.
	
	        keyGen.initialize(2048, sr);
	        
	        return keyGen.generateKeyPair();

		} catch (NoSuchAlgorithmException e) {}
		
		return null;
		
	}
	/**
	 * Generate a key pair and set a self-signed certificate.
	 * @return  The self-signed certificate.
	 */
	public static X509Certificate GenerateCertificate (KeyPair kp) {
		try {
	        PrivateKey privKey;  // To store private key.
	        PublicKey pubKey;  // To store public key.
	        X509V3CertificateGenerator serverCertGen;  // To store metadata useful to generate the certificate.
	        X500Principal serverSubjectName;  // To store the DN.

	        privKey = kp.getPrivate();  // To self-certify.
	        pubKey = kp.getPublic();  // Key to certify.
	        
	        serverCertGen = new X509V3CertificateGenerator();  // Generate a X509 certificate.
	        serverSubjectName = new X500Principal("CN=Chris SYM");  // Generate a DN.
	        serverCertGen.setSerialNumber(new BigInteger ("123458789"));  // ??
	     // X509Certificate caCert=null;
	        serverCertGen.setIssuerDN(serverSubjectName);  // Set the entity who sign the certificate.
	        serverCertGen.setNotBefore(new Date());  // Begining of the validity.
	        serverCertGen.setNotAfter(new Date());  // Set the date after which this certificate will no longer be valid. 
	        serverCertGen.setSubjectDN(serverSubjectName);  // Set the DN.
	        serverCertGen.setPublicKey(pubKey);  // Set the key to certify.
	        serverCertGen.setSignatureAlgorithm("MD5WithRSA");  // Set the signature algorithm.
	        
	        serverCertGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
	        	    new SubjectKeyIdentifierStructure(pubKey));
	        
	         return serverCertGen.generate(privKey);  // Generate and save the X509 certificate.
	         

		} catch (NoSuchAlgorithmException | CertificateParsingException | CertificateEncodingException | InvalidKeyException | IllegalStateException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	/**
	 * To test this class.
	 * @param args
	 */
	public static void main(String[] args) {
		PrivaNetValue pnv = new PrivaNetValue ("bar"),  // PrivaNetValue, with a certificate generated.
				pnvBis = null;  // Used to save pnv unserialized.
		String a = null;  // Used to save pnv in base64.
		
		System.out.println ("The value: " + pnv.getValue());
		System.out.println ("The cert: " + pnv.getCertificatRacine().getClass().toString());
		
		a = pnv.inBase64();
		System.out.println (a);
		pnvBis = PrivaNetValue.getFromBase64(a);
		System.out.println ("The value: " + pnvBis.getValue());
		System.out.println ("The cert: " + pnvBis.getCertificatRacine());

		if (pnv.Certified(pnvBis.getCertificatRacine()))
			System.out.println ("pnv certified pnvBis certificate");
		else
			System.out.println ("pnv never certified pnvBis certificate");
		
		if (pnvBis.Certified(pnv.getCertificatRacine()))
			System.out.println ("pnvBis certified pnv certificate");
		else
			System.out.println ("pnvBis never certified pnv certificate");
	}

}
