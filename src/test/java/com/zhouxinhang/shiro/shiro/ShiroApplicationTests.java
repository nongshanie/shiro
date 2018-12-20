package com.zhouxinhang.shiro.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ShiroApplicationTests {

    @Autowired
    private SecurityManager securityManager;

    @Test
    public void testLogin() {
        //1.创建object
        SecurityUtils.setSecurityManager(securityManager);
        // 设置realm.
        Subject subject = SecurityUtils.getSubject();
        //2.创建帐号密码token
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("zxh", "123456");
        try {
            //3.登录
            subject.login(usernamePasswordToken);
        } catch (AuthenticationException e) {
            //e.printStackTrace();
        }
        //4.判断登录
        boolean authenticated = subject.isAuthenticated();
        System.out.println("验证是否登录 = " + authenticated);
        //5.注销
        subject.logout();
        authenticated = subject.isAuthenticated();
        System.out.println("验证登录状态 = " + authenticated);
    }
}

