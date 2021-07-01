package com.study.shirodemo.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

/**
 * 认证和授权的realm
 * AuthorizingRealm继承了AuthenticatingRealm
 */
public class UserRealm extends AuthorizingRealm {
    /**
     * 授权逻辑
     * AuthorizationInfo对象会以密码为key放到缓存里
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        Object principal = principalCollection.getPrimaryPrincipal();
//        System.out.println(principal);
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        if ("admin".equals(principal)) {
            authorizationInfo.addStringPermission("user:add");
        }
        return authorizationInfo;
    }

    /**
     * 认证逻辑
     * AuthenticationInfo对象会以密码为key放到缓存里
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
//        System.out.println("开始认证。。。");
//        // 根据authenticationToken中获取的用户信息，从db中查询
//        String name = "admin";
//        String password = "038bdaf98f2037b31f1e75b5b4c9b26e";
//        UsernamePasswordToken user = (UsernamePasswordToken) authenticationToken;
//        if (!user.getUsername().equals(name)) {
//            return null; // 会抛UnknownAccountException
//        }
        if ("admin".equals(authenticationToken.getPrincipal())) {
            return new SimpleAuthenticationInfo("admin", "admin", getName());
        } else {
            throw new AuthenticationException("haha");
        }
    }
}
