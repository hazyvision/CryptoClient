//Adriene Cuenco
//CS380.01 (W15)
//Project 8 (Crypto Client)
//Due: 3.13.2015
//

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.xml.bind.DatatypeConverter;

public class CryptoClient {
    //Initialize Global Variables
    static byte version = 4;
    static byte hlen = 5;
    static byte tos = 0;
    static short tLen = 0;
    static short iden = 0;
    static int flags =0x4000;
    static byte ttl = 50;
    static byte protocol = 17; //udp = 17
    static short checksum = 0;
    static int srcAddress = 0xC0A811A; //192.168.1.26
    static int destAddress = 0x4C5B7B61; //76.91.123.97
    static long totalTime = 0;
   static short fillerPort = 0x420;
   static short destPort = (short)38008;
	public static void main(String[] args) throws Exception {
		Socket socket = new Socket("45.50.5.238", 38008);
		System.out.println("server> Ip: "+socket.getInetAddress().getHostAddress() +"; Port#: "+socket.getPort());
		System.out.println("\nAuthenticating session key...\n");
		InputStream fromServer = socket.getInputStream();
		OutputStream toServer = socket.getOutputStream();
		
		
		String filePath = "public.bin";
		ObjectInputStream rsaPuKey = new ObjectInputStream(new FileInputStream(filePath));
		
		//read from the file in to an instance of RSAPublicKey.
		RSAPublicKey rsaPublicKey =  (RSAPublicKey) rsaPuKey.readObject();
		
		//Use an instance of Cipher with the public key
		Cipher cipher = Cipher.getInstance("RSA");
		
		//close public.bin file
		rsaPuKey.close();
		
		//Generate AES session key
		Key aes_sesh_key = KeyGenerator.getInstance("AES").generateKey();
	
		//Serialize the session key
		ByteArrayOutputStream serializeKey = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(serializeKey);
		oos.writeObject(aes_sesh_key);
		byte[] sesh_key = serializeKey.toByteArray();
	
		//Encrypt serialized session key with given public key
		cipher.init(Cipher.ENCRYPT_MODE,rsaPublicKey);
		byte[] cipherText = cipher.doFinal(sesh_key);
			
		//Send resulting cipher text as data in UDP
		byte[] initialPacket = generateIpv4(generateUdp(cipherText)); 
		
		toServer.write(initialPacket);
		byte[] response1 = new byte[4];
		fromServer.read(response1);
		System.out.println("server> "+DatatypeConverter.printHexBinary(response1));
		System.out.println("\nServer has authenticated session key.");
		System.out.println("Sending 10 encrypted udp packets...\n");
		
		//Change cipher instance to AES because the Session key is using AES
		cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE,aes_sesh_key);
		
		int dataSize = 2;
		//Begin sending encrypted packets with dummy data
		double totalTime = 0;
		for(int i = 1; i <=10;i++){
			double start = System.currentTimeMillis();
			byte[] packet = generateIpv4(generateUdp(generateRandomData(dataSize)));
			byte[] enPacket = cipher.doFinal(packet);	
			toServer.write(enPacket);
			byte[] serResponse = new byte[4];
			fromServer.read(serResponse);
			double stop = System.currentTimeMillis();
			double time = stop-start;
			System.out.println("Packet # " + i );
			System.out.println("server> "+DatatypeConverter.printHexBinary(serResponse));
			System.out.println("RTT: " + time + "ms\n" );
			totalTime+=time;
			dataSize = dataSize*2;	
		}	
		System.out.println("All packets sent successfully.");
		System.out.println("AvgRTT: " + totalTime/10.0 + "ms\n");
		System.out.println("Socket is now closing...");
		socket.close();
	}// end main
	
    public static byte[] generateIpv4(byte[] data) {
        checksum = 0;
        int dataLength = data.length;
        byte[] header = new byte[20 + dataLength];
        
        //Wrap header in Bytebuffer
        ByteBuffer bb = ByteBuffer.wrap(header);
        bb.put((byte) ((version & 0xf) << 4 | hlen & 0xf));
        bb.put(tos);
        tLen = (short)(20 + dataLength);
        bb.putShort(tLen);
        bb.putShort(iden);
        bb.putShort((short) flags);
        bb.put(ttl);
        bb.put(protocol);
        bb.putShort(checksum);
        bb.putInt(srcAddress);
        bb.putInt(destAddress);
        checksum = (byte) checksum_Funct(bb,hlen);
        bb.put(data);
        return header;
    }// End generateIpv4
    public static byte[] generateUdp(byte[] data){
           int dataSize = data.length;
           short udpLength= (short) (8 + dataSize);
           int udpDataSize = data.length;
           //Wrap udpHeader and data and return
           byte[] udpHeader = new byte[8 + udpDataSize]; 
           ByteBuffer udpHeaderWrap = ByteBuffer.wrap(udpHeader);
           udpHeaderWrap.putShort((short)fillerPort);
           udpHeaderWrap.putShort((short)destPort);
           udpHeaderWrap.putShort((short)udpLength); 
           udpHeaderWrap.putShort((short)checksum_Funct2(destPort, udpLength, checksum, data)); 
           udpHeaderWrap.put(data);
           return udpHeader;
    } //end generateUdp
    
    public static short checksum_Funct(ByteBuffer bb, byte hlen){
        short checksum;
        int num = 0;
        bb.rewind();
        for(int i = 0; i < hlen*2; ++i){
          num += 0xFFFF & bb.getShort();
        }
        num = ((num >> 16) & 0xFFFF) + (num & 0xFFFF);
        checksum = (short) (~num & 0xFFFF);
        bb.putShort(10,checksum);
        return checksum;
    }//end checksum_Funct
    
    public static short checksum_Funct2(int port,int length, short checksum, byte[] data){
     ByteBuffer header = ByteBuffer.allocate(length);
     header.putShort((short) fillerPort);
     header.putShort((short) port);
     header.putShort((short) length);
     header.putShort((short) 0);
     header.put(data);
     header.rewind();
     
     int sum = 0;
     sum += ((srcAddress >> 16) & 0xFFFF) + (srcAddress & 0xFFFF);
     sum += ((destAddress >> 16) & 0xFFFF) + (destAddress & 0xFFFF);
     sum += (byte) 17 & 0xFFFF;
     sum += length & 0xFFFF;
     
     //Sum header
     for (int i = 0; i < length * 0.5 ; i++){
       sum += 0xFFFF & header.getShort();
     }     
     // if length is odd
     if(length % 2 > 0){
       sum += (header.get() & 0xFF) << 8;
     }
     sum = ((sum >> 16) & 0xFFFF) + (sum & 0xFFFF);
     short result = (short) (~sum & 0xFFFF);
     return result;
  }//end checksum_funct2
    
  public static byte[] generateRandomData(int size){
     Random r = new Random();
	 byte[] randomArr = new byte[size];
	 for (int i = 0; i < size; i++){
	    randomArr[i] = (byte)r.nextInt();
	 }
	 return randomArr;
  } // end Function generateRandomData
  
}//end class CryptoClient
