package com.study.shirodemo.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class ShiroController {

    @GetMapping("/toLogin")
    public String toLogin() {
        return "toLogin";
    }

    @GetMapping("/success")
    public String success() {
        return "success";
    }

    @GetMapping("/unauthorized")
    public String unauthorized() {
        return "unauthorized";
    }

    @GetMapping("/add")
    public String add() {
        return "add";
    }

    @GetMapping("/update")
    public String update() {
        return "update";
    }

    @GetMapping("/login")
    public String login(String name, String password, HttpSession session) {
        session.setAttribute("hello", "hello");
        Subject subject = SecurityUtils.getSubject();
        System.out.println(subject.getSession().getAttribute("hello"));
        UsernamePasswordToken token = new UsernamePasswordToken(name, password);
        // 开启记住我功能
        // token.setRememberMe(true);
        try {
            subject.login(token);
            return "login success";
        } catch (Exception e) {
            e.printStackTrace();
            return "login fail";
        }
    }

    public static void main(String[] args) {
        String name = "admin";
        String pass = "123456";
        SimpleHash md5 = new SimpleHash("MD5", pass, ByteSource.Util.bytes(name), 1024);
        System.out.println(md5.toString());
    }
}
