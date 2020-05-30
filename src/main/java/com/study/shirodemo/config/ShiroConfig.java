package com.study.shirodemo.config;

import com.study.shirodemo.realm.UserRealm;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.pam.AllSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.eis.*;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * shiro spring-boot 整合的配置类
 */
@Configuration
public class ShiroConfig {
    /**
     * ShiroFilterFactoryBean
     * 配置shiro的拦截器
     */
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        // 为资源添加内置拦截器
        Map<String, String> filters = new LinkedHashMap<>();
        filters.put("/add", "anon");
        filters.put("/login", "anon");
        filters.put("/update", "perms[user:add]");
        filters.put("/**", "authc");
        // 设置一些默认的url，不会被上面的拦截器拦截
        shiroFilterFactoryBean.setLoginUrl("/toLogin");
        shiroFilterFactoryBean.setSuccessUrl("/success");
        shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filters);
        return shiroFilterFactoryBean;
    }

    /**
     * DefaultWebSecurityManager
     */
    @Bean
    public DefaultWebSecurityManager getDefaultWebSecurityManager(UserRealm realm, RememberMeManager rememberMeManager,
                                                                  DefaultSessionManager sessionManager) {
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealm(realm);
        defaultWebSecurityManager.setRememberMeManager(rememberMeManager);
        // 这里的SessionManager有问题
//        defaultWebSecurityManager.setSessionManager(sessionManager);
        //这里的CacheManager会覆盖SessionManager的
//        defaultWebSecurityManager.setCacheManager(new MemoryConstrainedCacheManager());
        return defaultWebSecurityManager;
    }

    /**
     * Realm
     */
    @Bean
    public UserRealm getRealm(CredentialsMatcher matcher) {
        UserRealm userRealm = new UserRealm();
        userRealm.setCredentialsMatcher(matcher);
        return userRealm;
    }

    /**
     * 认证时的密码比对器
     * @return
     */
    @Bean
    public CredentialsMatcher getCredentialsMatcher() {
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("MD5");
        matcher.setHashIterations(1024);
        return matcher;
    }

    /**
     * 记住我功能使用的RememberMeManager
     * 主要设置一些cookie信息，比如自定义cookie时长
     * @return
     */
    @Bean
    public RememberMeManager getRememberMeManager() {
        RememberMeManager rememberMeManager = new CookieRememberMeManager();
        Cookie cookie = new SimpleCookie("rememberMe");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(3600);
        return rememberMeManager;
    }

    /**
     * 如果是多realm就需要自定义认证器
     * 在认证器里指定认证策略
     * 默认只要一个realm认证成功即可认为登录成功
     * 需要注入到SecurityManager中
     * @return
     */
    @Bean
    public Authenticator getAuthenticator() {
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        // 策略改为需要全部认证成功
        authenticator.setAuthenticationStrategy(new AllSuccessfulStrategy());
        return authenticator;
    }

    /**
     * 授权器不需要自定义
     * 多realm默认只要一个授权成功即可认为授权成功
     * 需要注入到SecurityManager中
     */
    @Bean
    public Authorizer getAuthorizer() {
        return new ModularRealmAuthorizer();
    }

    /**
     * 开启shiro注解需要的bean
     * @return
     */
    @Bean
    public LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    /**
     * 开启shiro注解需要的bean
     * @return
     */
    @Bean
    @DependsOn({"getLifecycleBeanPostProcessor"})
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    /**
     * 开启shiro注解需要的bean
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    /**
     * sessionid生成器
     * 当然也可以自己实现一个
     * @return
     */
    @Bean
    public SessionIdGenerator getSessionIdGenerator() {
        return new JavaUuidSessionIdGenerator();
    }

    /**
     * 用于对session的操作，创建、更新、删除等
     * 这里的bean需要继承EnterpriseCacheSessionDAO（或继承它的父类）自己实现一个
     * 重写里面的方法
     * 可以完全重写里面的方法，将session存入redis，不用shiro的缓存？
     * 默认用的缓存是一个map
     * @param sessionIdGenerator
     * @return
     */
    @Bean
    public SessionDAO getEnterpriseCacheSessionDAO(SessionIdGenerator sessionIdGenerator) {
//        EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
//        sessionDAO.setSessionIdGenerator(sessionIdGenerator);
        //设置缓存管理器
        //sessionDAO.setCacheManager();
        //设置缓存，如果设置了就不用缓存管理器了
        //sessionDAO.setActiveSessionsCache();
        //sessionDAO.setActiveSessionsCacheName();
        MemorySessionDAO sessionDAO = new MemorySessionDAO();
        return sessionDAO;
    }

    /**
     * session管理器
     * 对session的操作委托给了sessionDAO
     * 需要注入到SecuriManager
     * @param sessionDAO
     * @return
     */
    @Bean
    public DefaultSessionManager getDefaultSessionManager(SessionDAO sessionDAO) {
        DefaultSessionManager sessionManager = new DefaultSessionManager();
        sessionManager.setSessionDAO(sessionDAO);
        sessionManager.setGlobalSessionTimeout(1000000);
        //这里的缓存管理器会覆盖sessionDAO的
        //sessionManager.setCacheManager();
        // 设置这些属性，就需要一个定时任务去定时清理过期的session
        //sessionManager.setDeleteInvalidSessions();
        //sessionManager.setSessionValidationSchedulerEnabled(true);
        return sessionManager;
    }
}
