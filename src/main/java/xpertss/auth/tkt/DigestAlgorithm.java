/*
 * Copyright 2015 XpertSoftware
 * <p>
 * Created By: cfloersch
 * Date: 8/14/2015
 */
package xpertss.auth.tkt;

import xpertss.lang.Strings;
import xpertss.net.NetUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static xpertss.lang.Bytes.fromHexString;

/**
 * An enumeration of the digest algorithm's supported by the auth ticket specification.
 */
public enum DigestAlgorithm {


   MD5(16, "MD5"), SHA256(32, "SHA-256"), SHA512(64, "SHA-512");

   private static final Pattern BASE64 = Pattern.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");

   private ThreadLocal<MessageDigest> digesters = new ThreadLocal<MessageDigest>() {
      protected MessageDigest initialValue() {
         try {
            return MessageDigest.getInstance(algName);
         } catch(NoSuchAlgorithmException e) { throw new Error(format("No %s Algorithm???", name())); }
      }
   };

   private int checksumSize;
   private String algName;

   DigestAlgorithm(int len, String algName)
   {
      this.checksumSize = len * 2;
      this.algName = algName;
   }

   /**
    * Return a {@link MessageDigest} instance that can be used to encode the Message
    * Authentication Code (MAC) that is dedicated to the calling thread.
    * <p>
    * MessageDigest instances are expensive to create. As a result this enumeration
    * will cache them in a thread local way to ensure that only a single thread is
    * operating on a particular MessageDigest instance at a time.
    *
    * @return a thread safe message digest instance
    */
   public MessageDigest digest()
   {
      return digesters.get();
   }

   /**
    * This will decode the ticket and parse it into an immutable AuthTicket instance
    * based on the digest algorithm's output size.
    * <p>
    * Each digest produces a slightly different encoded result. This will throw an
    * exception if the supplied encoded ticket was not encoded using the current
    * digest algorithm.
    *
    * @param ticket - the raw ticket value
    * @return a parsed immutable AuthTicket instance
    * @throws MalformedTicketException if the supplied ticket is improperly encoded
    */
   public AuthTicket parse(String ticket)
   {
      ticket = decode(ticket);
      if(ticket.length() <= checksumSize + 8) throw new MalformedTicketException("invalid ticket length");
      try {
         byte[] checksum = fromHexString(ticket.substring(0, checksumSize));
         long ts = Long.valueOf(ticket.substring(checksumSize, checksumSize + 8), 16);

         String[] parts = ticket.substring(checksumSize + 8).split("!", -3);
         if(parts.length == 3) {
            return EncodedAuthTicket.create(checksum, ts, parts[0], parts[1], parts[2]);
         } else if(parts.length == 2) {
            return EncodedAuthTicket.create(checksum, ts, parts[0], null, parts[1]);
         } else {
            throw new MalformedTicketException("ticket missing user data");
         }
      } catch(NumberFormatException nfe) {
         throw new MalformedTicketException(nfe);
      }
   }

   private static String decode(String cookie)
   {
      String str = Strings.unquote(cookie);
      while(!str.contains("!")) {
         if(str.contains("%21") || str.contains("%3D")) {
            str = NetUtils.urlDecode(str);
         } else {
            str = base64Decode(str);
            if(Strings.isEmpty(str)) throw new MalformedTicketException("unknown encoding");
         }
      }
      return str;
   }


   private static String base64Decode(String str)
   {
      try {
         return new String(Base64.getDecoder().decode(str));
      } catch(Exception e) {
         return null;
      }
   }

}
