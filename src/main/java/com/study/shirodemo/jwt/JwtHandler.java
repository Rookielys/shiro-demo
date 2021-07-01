package com.study.shirodemo.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtHandler {
    public static final String SECRET_KEY = "BS2ajwDy+SYuO9JNwBn1535G8akZHwstSbd03jxtCtE=";

    public static String sign(String subject, Date exp, SecretKey key) {
        return Jwts.builder().setSubject(subject).setExpiration(exp).signWith(key).compact();
    }

    public static Claims verify(String jws, SecretKey key) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jws).getBody();
    }

    public static boolean isExpired(Date date) {
        Date now = new Date();
        return now.after(date);
    }

    public static boolean isLegalSubjec(String subject) {
        return subject != null && !subject.isEmpty();
    }

    public static SecretKey createKey(String ks) {
        byte[] decode = Decoders.BASE64.decode(ks);
        return Keys.hmacShaKeyFor(decode);
    }

    public static String getSubject(Claims body) {
        return body.getSubject();
    }

    public static Date getExp(Claims body) {
        return body.getExpiration();
    }

    public static void main2(String[] args) {
        System.out.println(Encoders.BASE64.encode(Keys.secretKeyFor(SignatureAlgorithm.HS256).getEncoded()));
    }
}
