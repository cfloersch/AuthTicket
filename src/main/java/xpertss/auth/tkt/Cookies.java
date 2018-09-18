/*
 * Copyright 2018 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 9/18/2018
 */
package xpertss.auth.tkt;

import javax.servlet.http.Cookie;

public class Cookies {

   /**
    * This will return the named cookie or null if the cookie is not found.
    *
    * @param cookies The list of cookies to iterate
    * @param cookieName The name of the cookie to locate
    * @return The named cookie or null
    */
   public static Cookie getCookie(Cookie[] cookies , String cookieName)
   {
      if(cookies != null && cookieName != null) {
         for (Cookie cookie : cookies) {
            if(cookieName.equals(cookie.getName())) return cookie;
         }
      }
      return null;
   }

}
