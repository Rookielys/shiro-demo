package com.study.shirodemo.filter;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class MyFilter extends AccessControlFilter {
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        HttpServletRequest rep = (HttpServletRequest) request;
        String authentication = rep.getHeader("Authentication");
        UsernamePasswordToken token = new UsernamePasswordToken(authentication, "admin");
        Subject subject = getSubject(request, response);
        try {
            System.out.println(SecurityUtils.getSubject().getPrincipals());
            subject.login(token);
            System.out.println(SecurityUtils.getSubject().getPrincipals());
            System.out.println(SecurityUtils.getSubject() == subject);
            return true;
        } catch (AuthenticationException e){
            e.printStackTrace();
            return false;
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return false;
    }
}
