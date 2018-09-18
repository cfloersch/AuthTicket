/*
 * Copyright 2018 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 9/18/2018
 */
package xpertss.auth.tkt;

import javax.servlet.http.Cookie;

public class Cookies {


   public static Cookie getCookie(Cookie[] cookies , String cookieName)
   {
      if(cookies != null && cookieName != null) {
         for (Cookie cookie : cookies) {
            if(cookieName.equals(cookie.getName())) return cookie;
         }
      }
      throw new TicketNotFoundException();
   }

}
