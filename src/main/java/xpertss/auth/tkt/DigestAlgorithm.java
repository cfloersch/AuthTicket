/**
 * Copyright 2015 XpertSoftware
 * <p/>
 * Created By: cfloersch
 * Date: 8/14/2015
 */
package xpertss.auth.tkt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.lang.String.format;
import static xpertss.lang.Bytes.fromHexString;

public enum DigestAlgorithm {

   MD5(16, "MD5"), SHA256(32, "SHA-256"), SHA512(64, "SHA-512");

   private ThreadLocal<MessageDigest> digesters = new ThreadLocal<MessageDigest>() {
      protected MessageDigest initialValue() {
         try {
            return MessageDigest.getInstance(algName);
         } catch(NoSuchAlgorithmException e) { throw new Error(format("No %s Algorithm???", name())); }
      }
   };

   private int checksumSize;
   private String algName;

   private DigestAlgorithm(int len, String algName)
   {
      this.checksumSize = len * 2;
      this.algName = algName;
   }

   public MessageDigest digest()
   {
      return digesters.get();
   }

   public AuthTicket parse(String ticket)
   {
      if(ticket.length() <= checksumSize + 8) throw new MalformedTicketException("invalid ticket length");
      try {
         byte[] checksum = fromHexString(ticket.substring(0, checksumSize));
         long ts = Long.valueOf(ticket.substring(checksumSize, checksumSize + 8), 16);

         String[] parts = ticket.substring(checksumSize + 8).split("!", -3);
         if(parts.length == 3) {
            return AuthTicket.create(checksum, ts, parts[0], parts[1], parts[2]);
         } else if(parts.length == 2) {
            return AuthTicket.create(checksum, ts, parts[0], null, parts[1]);
         } else {
            throw new MalformedTicketException("ticket missing user data");
         }
      } catch(NumberFormatException nfe) {
         throw new MalformedTicketException(nfe);
      }
   }

}
