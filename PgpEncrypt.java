import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.File;
import java.security.NoSuchProviderException;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import java.io.FileOutputStream;

public class PgpEncrypt {

        private static final BouncyCastleProvider provider = new BouncyCastleProvider();
        static
        {
            Security.addProvider( provider );
        }
	public static void main(String[] args) {
               String publicKeyFilePath = "publickey.txt";
try{
        FileInputStream	in = new FileInputStream(publicKeyFilePath);

        PGPPublicKey publicKey = readPublicKey(in);

        String str = "Hii anshuman";
        byte[] byteArr = str.getBytes();
        // print the byte[] elements
        String s = new String(byteArr);
System.out.println("-----------------------------------\noriginal message: "+s);
byte[] byteArr1 = encrypt( byteArr,  publicKey, true );
String s1 = new String(byteArr1);
System.out.println("-----------------------------\nencrypted message\n"+s1);

FileInputStream secKey = new FileInputStream("privatekey.txt");
FileOutputStream dfis = new FileOutputStream("msg.txt");
        dfis.write(byteArr1);
        dfis.close();
 
        byte[] encFromFile = getBytesFromFile(new File("msg.txt"));
byte[] decrypted = decrypt(encFromFile, secKey, "passphrase".toCharArray());

System.out.println("---------------------------\ndecrypted data = '" + new String(decrypted) + "'");

} catch (PGPException e) {
        System.out.println(e.toString());
        System.out.println(e.getUnderlyingException().toString());
        
} catch (Exception e) {
        System.out.println(e.toString());
}		
	}	
        public static byte[] encrypt( final byte[] message, final PGPPublicKey publicKey, boolean armored )
        throws PGPException
{
    try
    {
        final ByteArrayInputStream in = new ByteArrayInputStream( message );
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        final PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
        final PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator( CompressionAlgorithmTags.ZIP );
        final OutputStream pOut =
                literal.open( comData.open( bOut ), PGPLiteralData.BINARY, "filename", in.available(), new Date() );
        Streams.pipeAll( in, pOut );
        comData.close();
        final byte[] bytes = bOut.toByteArray();
        final PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder( SymmetricKeyAlgorithmTags.AES_256 ).setWithIntegrityPacket( true )
                                                                                   .setSecureRandom(
                                                                                           new SecureRandom() )

                                                                                   .setProvider( provider ) );
        generator.addMethod( new JcePublicKeyKeyEncryptionMethodGenerator( publicKey ).setProvider( provider ) );
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OutputStream theOut = armored ? new ArmoredOutputStream( out ) : out;
        OutputStream cOut = generator.open( theOut, bytes.length );
        cOut.write( bytes );
        cOut.close();
        theOut.close();
        return out.toByteArray();
    }
    catch ( Exception e )
    {
        throw new PGPException( "Error in encrypt", e );
    }
}

static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException
{
    InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
    PGPPublicKey pubKey = readPublicKey(keyIn);
    keyIn.close();
    return pubKey;
}
    
	
  static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                if (key.isEncryptionKey())
                {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }	
    public static String decrypt(String passphrase, String keyFile, String encryptedStr)
    throws Exception {

byte[] decrypted = decryptByte(passphrase, keyFile, encryptedStr.getBytes());

return new String(decrypted);
}

public static String decryptFile(String passphrase, String keyFile, String inputFile)
    throws Exception {

byte[] encFromFile = getBytesFromFile(new File(inputFile));
byte[] decrypted = decryptByte(passphrase, keyFile, encFromFile);

return new String(decrypted);

}

private static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase)
    throws PGPException {
PGPPrivateKey privateKey = null;
BcPGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();
BcPBESecretKeyDecryptorBuilder secretKeyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(
        calculatorProvider);
PBESecretKeyDecryptor pBESecretKeyDecryptor = secretKeyDecryptorBuilder.build(passPhrase);

try {
    privateKey = pgpSecKey.extractPrivateKey(pBESecretKeyDecryptor);
} catch (PGPException e) {
    throw new PGPException("invalid privateKey passPhrase: " + String.valueOf(passPhrase),
            e);
}

return privateKey;
}

@SuppressWarnings("unchecked")
protected static byte[] decrypt(byte[] encrypted, InputStream keyIn, char[] password)
    throws IOException, PGPException, NoSuchProviderException {

InputStream decodeIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(encrypted));
BcPGPObjectFactory pgpF = new BcPGPObjectFactory(decodeIn);
decodeIn.close();

PGPEncryptedDataList enc = null;
Object o = pgpF.nextObject();

//
// the first object might be a PGP marker packet.
//
if (o instanceof PGPEncryptedDataList) {
    enc = (PGPEncryptedDataList) o;
} else {
    enc = (PGPEncryptedDataList) pgpF.nextObject();
}

// find the secret key

PGPPrivateKey sKey = null;









//Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
PGPPublicKeyEncryptedData pbe = null;
PGPSecretKeyRingCollection pgpSec = new BcPGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(keyIn));

// while (sKey == null && it.hasNext()) {
//     pbe = it.next();
//     sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);

// }

for (int i = 0; i < enc.size() && sKey == null; i++) {
        Object encryptedData = enc.get(i);
      
        pbe = (PGPPublicKeyEncryptedData) encryptedData;
        sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
       
      }



// ////
// PGPSecretKey secretKey = readSecretKey(keyIn);
// sKey = getPGPSecretKey(secretKey, password);
// ///

// if (pbe == null) {
//     throw new IllegalArgumentException("PGPPublicKeyEncryptedData not found.");
// }

if (sKey == null) {
    throw new IllegalArgumentException("secret key for message not found.");
}

BcPublicKeyDataDecryptorFactory pkdf = new BcPublicKeyDataDecryptorFactory(sKey);

InputStream clear = pbe.getDataStream(pkdf);
PGPObjectFactory pgpFact = new BcPGPObjectFactory(clear);

PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

pgpFact = new BcPGPObjectFactory(cData.getDataStream());

PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

InputStream unc = ld.getInputStream();

ByteArrayOutputStream out = new ByteArrayOutputStream();
int ch;

while ((ch = unc.read()) >= 0) {
    out.write(ch);

}

byte[] returnBytes = out.toByteArray();
clear.close();
out.close();
unc.close();

return returnBytes;

}

protected static byte[] decryptByte(String passphrase, String keyFile, byte[] encryptedBytes)
    throws Exception {
Security.addProvider(new BouncyCastleProvider());

FileInputStream secKey = new FileInputStream(keyFile);
byte[] decrypted = decrypt(encryptedBytes, secKey, passphrase.toCharArray());

return decrypted;
}

protected static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID,
    char[] pass) throws PGPException, NoSuchProviderException {
PGPPrivateKey privateKey = null;
PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

if (pgpSecKey == null) {
    return null;
}
privateKey = extractPrivateKey(pgpSecKey, pass);

return privateKey;
}




public static byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);
 
        // Get the size of the file
        long length = file.length();
 
        if (length > Integer.MAX_VALUE) {
            // File is too large
        }
 
        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];
 
        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
               && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
            offset += numRead;
        }
 
        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }
 
        // Close the input stream and return bytes
        is.close();
        return bytes;
    }














    

    

}
