package com.zhouxinhang.shiro.shiro;

import com.zhouxinhang.shiro.shiro.realm.PermissionRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;

import java.util.Arrays;

/**
 * @author: zhouxinhang
 * @date: 2018/12/20
 * @Description:
 */
public class ShiroTests {

    @Test
    public void testMD5() {

        Md5Hash md5Hash = new Md5Hash("123456","zxh",3);
        System.out.println("md5Hash = " + md5Hash);
        //5c3662cb04b3c66f1e74818826218007
    }

    @Test
    public void testRoleByRealm() throws Exception {
        //1、创建创建SecurityManager
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        //2.设置realm.
        securityManager.setRealm(new PermissionRealm());
        //3、将securityManager设置到运行环境中
        SecurityUtils.setSecurityManager(securityManager);
        //4、在运行环境下创建Subject
        Subject subject =  SecurityUtils.getSubject();
        //5、创建token令牌，记录用户认证的身份和凭证即账号和密码
        UsernamePasswordToken token = new UsernamePasswordToken("zhangsan", "666");
        try {
            //6、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            //7、身份验证失败
            e.printStackTrace();
        }
        //8、用户认证状态
        Boolean isAuthenticated = subject.isAuthenticated();
        System.out.println("用户认证状态：" + isAuthenticated);
        //是否有某一个角色
        System.out.println("用户是否拥有一个角色：" + subject.hasRole("role2"));
        //是否有多个角色
        System.out.println("用户是否拥有多个角色：" + subject.hasAllRoles(Arrays.asList("role1", "role2")));

        //角色检查，如果没有就跑出异常
        //subject.checkRole("role1");
        //subject.checkRoles(Arrays.asList("role1", "role2"));
    }

    @Test
    public void testRole() throws Exception {
        //1、创建SecurityManager工厂,IniSecurityManagerFactory可以从ini文件中初始化SecurityManager环境
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-permission.ini");
        //2、创建SecurityManager
        SecurityManager securityManager = factory.getInstance();
        //3、将securityManager设置到运行环境中
        SecurityUtils.setSecurityManager(securityManager);
        //4、在运行环境下创建Subject
        Subject subject =  SecurityUtils.getSubject();
        //5、创建token令牌，记录用户认证的身份和凭证即账号和密码
        UsernamePasswordToken token = new UsernamePasswordToken("zhangsan", "666");
        try {
            //6、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            //7、身份验证失败
            e.printStackTrace();
        }
        //8、用户认证状态
        Boolean isAuthenticated = subject.isAuthenticated();
        System.out.println("用户认证状态：" + isAuthenticated);
        //是否有某一个角色
        System.out.println("用户是否拥有一个角色：" + subject.hasRole("role2"));
        //是否有多个角色
        System.out.println("用户是否拥有多个角色：" + subject.hasAllRoles(Arrays.asList("role1", "role2")));

        //角色检查，如果没有就跑出异常
        subject.checkRole("role1");
        subject.checkRoles(Arrays.asList("role1", "role2","role3"));
    }


}
