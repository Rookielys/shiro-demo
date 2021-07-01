package com.study.shirodemo.filter;

import com.study.shirodemo.jwt.JwtToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class JwtFilter extends AuthenticatingFilter {
    public static final String AUTH_HEADER = "Authorization";

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        String auth = getAuthHeader(request);
        if (auth == null) {
            auth = "";
        }
        return new JwtToken(auth);
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        boolean flag;
        try {
            flag = executeLogin(request, response);
        } catch (Exception e) {
            e.printStackTrace();
            flag = false;
        }
        return flag;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return false;
    }

    protected String getAuthHeader(ServletRequest request) {
        HttpServletRequest servletRequest = WebUtils.toHttp(request);
        return servletRequest.getHeader(AUTH_HEADER);
    }
}
