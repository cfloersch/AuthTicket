package xpertss.auth.util;

import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 */
public class Time {

   private static final Pattern pattern = Pattern.compile("(\\d+)([smhd]{0,1})");


   public static long parse(String str, TimeUnit unit)
   {
      if(str == null) return 0L;
      Matcher matcher = pattern.matcher(str);
      if(matcher.matches()) {
         long value = Long.parseLong(matcher.group(1));
         switch(matcher.group(2)) {
            case "s":
               return unit.convert(value, TimeUnit.SECONDS);
            case "m":
               return unit.convert(value, TimeUnit.MINUTES);
            case "h":
               return unit.convert(value, TimeUnit.HOURS);
            case "d":
               return unit.convert(value, TimeUnit.DAYS);
            default:
               return unit.convert(value, TimeUnit.SECONDS);
         }
      }
      throw new IllegalArgumentException("invalid time expression: " + str);
   }

}
