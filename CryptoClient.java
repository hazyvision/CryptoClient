//Adriene Cuenco
//CS380.01 (W15)
//Project 8 (Crypto Client)
//Due: 3.13.2015
//

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Random;

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
    //System.currentTimeMillis();
	public static void main(String[] args) throws Exception {
		Socket socket = new Socket("45.50.5.238", 38008);
		//file path for local machine
		String filePath = "/home/adriene/Dropbox/CS380/Projects/Proj8/src/public.bin";
		
		//filepath for submission
		//String filePath = "public.bin";
		
		ObjectInputStream rsaPuKey = new ObjectInputStream(new FileInputStream(filePath));
		System.out.println(rsaPuKey.read());
		
		ObjectInputStream toServer = new ObjectInputStream(socket.getInputStream());
		ObjectOutputStream fromServer = new ObjectOutputStream(socket.getOutputStream());
		
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
    public static byte[] generateUdp(byte[] data, int udpDestAddress){
        //Start PseudoHeader-------------------------------------------
           int pseudoSrcAddress = srcAddress;
           int pseudoDestAddress = destAddress;
           byte zeros = 0;
           byte pseudoProtocol = 17;
           int dataSize = data.length;
           short pseudoUdpLength= (short) (8 + dataSize);
           short pseudoChecksum = 0;
           
           byte[] psuedoHeader = new byte[20 + dataSize]; 
           ByteBuffer pseudoBuf = ByteBuffer.wrap(psuedoHeader);
           pseudoBuf.putInt(pseudoSrcAddress);
           pseudoBuf.putInt(pseudoDestAddress);
           pseudoBuf.put(zeros);
           pseudoBuf.put(pseudoProtocol);               
           pseudoBuf.putShort(pseudoUdpLength);

           pseudoBuf.putShort((short)udpDestAddress);
           pseudoBuf.putShort((short)udpDestAddress);

           short udpLength= (short) (8 + dataSize);
           pseudoBuf.putShort(udpLength); 
           pseudoBuf.put(data);          
           
           //Calculate Checksum on PseudoHeader
           pseudoChecksum = checksum_Funct2(udpDestAddress, udpLength, checksum, data);
           //End PseudoHeader----------------------------------------------------------
           
           short udpSrcAddress = (short)udpDestAddress;
           //From handshake
           int udpDataSize = data.length;
           //Wrap udpHeader and data and return
           byte[] udpHeader = new byte[8 + udpDataSize]; 
           ByteBuffer udpHeaderWrap = ByteBuffer.wrap(udpHeader);
           udpHeaderWrap.putShort((short)udpSrcAddress);
           udpHeaderWrap.putShort((short)udpDestAddress);
           udpHeaderWrap.putShort((short)udpLength); 
           udpHeaderWrap.putShort((short)pseudoChecksum); 
           udpHeaderWrap.put(data);
           return udpHeader;
       } //End generateUdp
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
     header.putShort((short) port);
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
