/*
 * Copyright 2018 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 10/4/2018
 */
package xpertss.auth.tkt;

import xpertss.lang.Objects;
import xpertss.lang.Strings;
import xpertss.net.NetUtils;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.security.MessageDigest;

import static java.nio.charset.StandardCharsets.UTF_8;
import static xpertss.lang.Bytes.toHexString;

public final class AuthTicketEncoder {

   private final AuthTicketConfig config;
   private final DigestAlgorithm digestAlg;

   public AuthTicketEncoder(AuthTicketConfig config)
   {
      this.config = Objects.notNull(config);
      this.digestAlg = config.getDigestAlgorithm();
   }


   public AuthTicket encode(String remoteIp, AuthTicket ticket)
   {
      MessageDigest digester = digestAlg.digest();
      digester.reset();

      // This stuff makes sense other than they don't specify a character
      // encoding which means this will likely break when dealing with
      // characters outside the ASCII set.
      digester.update(computeIPStamp(remoteIp, ticket.getTimestamp()));
      digester.update(toBytes(config.getSecret()));
      digester.update(toBytes(ticket.getUsername()));
      digester.update(new byte[1]);
      digester.update(toBytes(Strings.join(",", ticket.getTokens())));
      digester.update(new byte[1]);
      digester.update(toBytes(ticket.getUserData()));

      // These retards actually created a spec where they treat the digest bytes
      // as a STRING (hex encoded no less where case matters!!!)
      // I think string programmers should be run out of the industry on a rail..
      digester.update(toBytes(toHexString(digester.digest()).toLowerCase()));
      return EncodedAuthTicket.create(ticket, digester.digest(toBytes(config.getSecret())));
   }

   private byte[] computeIPStamp(String remoteIp, long timestamp)
   {
      byte[] ipStamp = new byte[8];
      if(!config.ignoreIP() && remoteIp != null) {
         InetAddress remoteAddr = NetUtils.getInetAddress(remoteIp.split("\\s*,\\s*")[0]);
         if(remoteAddr == null) {
            throw new IllegalArgumentException("invalid remote ip: " + remoteIp);
         } else if(remoteAddr instanceof Inet4Address) {
            System.arraycopy(remoteAddr.getAddress(), 0, ipStamp, 0, 4);
         }
         // TODO What to do with IPv6 addresses???
         // I guess those must not have existed when this spec was created??
      }
      ipStamp[4] = (byte) ((timestamp >>> 24) & 0xFF);
      ipStamp[5] = (byte) ((timestamp >>> 16) & 0xFF);
      ipStamp[6] = (byte) ((timestamp >>>  8) & 0xFF);
      ipStamp[7] = (byte) ((timestamp) & 0xFF);

      return ipStamp;
   }





   private static byte[] toBytes(String str)
   {
      // TODO What charset do they use to convert string data into byte data
      // The C api uses unsigned characters.. Not sure what the digest algorithm does to them
      // My guess is that the C code uses ASCII (aka 8 lower bits of each char) without any real encoding
      // It doesn't make a difference here in the states where english basically translates the same
      // God help anyone that uses a more sophisticated character set.
      return (str != null) ? str.getBytes(UTF_8) : new byte[0];
   }


}
