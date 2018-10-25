/*
 * Copyright 2018 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 10/25/2018
 */
package xpertss.auth.tkt;

import xpertss.lang.Bytes;
import xpertss.lang.Strings;
import xpertss.util.Sets;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public final class MutableTicket implements AuthTicket {

   private final long timestamp = System.currentTimeMillis() / 1000;
   private final Set<String> tokens = new LinkedHashSet<>();
   private final String uid;

   private String userData;

   public MutableTicket(String uid)
   {
      this.uid = uid;
   }


   @Override
   public String getUsername()
   {
      return uid;
   }




   @Override
   public Set<String> getTokens()
   {
      return Collections.unmodifiableSet(tokens);
   }

   public void addToken(String token)
   {
      tokens.add(token);
   }

   @Override
   public boolean contains(String token)
   {
      return tokens.contains(token);
   }

   @Override
   public boolean containsAny(Set<String> tokens)
   {
      return this.tokens.size() > 0 && !Sets.intersection(this.tokens, tokens).isEmpty();
   }



   @Override
   public long getTimestamp()
   {
      return timestamp;
   }

   @Override
   public boolean isExpired(long timeout)
   {
      if(timeout <= 0) return false;
      long currentTime = System.currentTimeMillis() / 1000;
      return timestamp + timeout <= currentTime;
   }



   @Override
   public String getUserData()
   {
      return userData;
   }

   public void setUserData(String userData)
   {
      this.userData = userData;
   }



   @Override
   public byte[] getChecksum()
   {
      return new byte[0];
   }



   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder();
      builder.append(Strings.toLower(Bytes.toHexString(new byte[4])));

      byte[] ts = new byte[4];
      ts[0] = (byte) ((timestamp >>> 24) & 0xFF);
      ts[1] = (byte) ((timestamp >>> 16) & 0xFF);
      ts[2] = (byte) ((timestamp >>>  8) & 0xFF);
      ts[3] = (byte) ((timestamp) & 0xFF);
      builder.append(Strings.toLower(Bytes.toHexString(ts)));

      builder.append(uid);
      if(!tokens.isEmpty()) {
         builder.append("!").append(Strings.join(",", tokens));
      }
      builder.append("!").append(Strings.emptyIfNull(userData));
      return builder.toString();
   }


}
