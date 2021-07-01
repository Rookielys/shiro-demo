package com.study.shirodemo.realm;

import com.study.shirodemo.jwt.JwtHandler;
import com.study.shirodemo.jwt.JwtToken;
import io.jsonwebtoken.Claims;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class JwtRealm extends AuthorizingRealm {

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String principal = (String) principals.getPrimaryPrincipal();
        Set<String> permissions = getPermissionsByUsername(principal);
        if (permissions == null) {
            permissions = new HashSet<>();
        }
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addStringPermissions(permissions);
        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        JwtToken jwtToken = (JwtToken) token;
        String jws = (String) jwtToken.getPrincipal();
        try {
            Claims claims = JwtHandler.verify(jws, JwtHandler.createKey(JwtHandler.SECRET_KEY));
            String subject = claims.getSubject();
            Date expiration = claims.getExpiration();
            // 这里应该还要判断用户账户的状态
            if (JwtHandler.isLegalSubjec(subject) && !JwtHandler.isExpired(expiration)) {
                return new SimpleAuthenticationInfo(subject, subject, getName());
            } else {
                throw new AuthenticationException("token非法或过期.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new AuthenticationException("校验token失败.", e);
        }
    }

    protected Set<String> getPermissionsByUsername(String username) {
        return new HashSet<>();
    }
}
