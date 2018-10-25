/*
 * Copyright 2018 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 10/25/2018
 */
package xpertss.auth.tkt;

import java.util.Set;

public interface AuthTicket {

   public String getUsername();


   public long getTimestamp();

   public boolean isExpired(long timeout);


   public Set<String> getTokens();

   public boolean contains(String token);

   public boolean containsAny(Set<String> tokens);



   public String getUserData();

   
   public byte[] getChecksum();
   
}
