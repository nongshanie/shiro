package com.zhouxinhang.shiro.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

/**
 * @author: zhouxinhang
 * @date: 2018/12/20
 * @Description:
 */
public class MyShiroRealm extends AuthorizingRealm {

    @Override
    public String getName() {
        return "myShiroRealm";
    }

    /**
     * 认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String principal = (String) token.getPrincipal();
        System.out.println("principal = " + principal);
        if(!"zxh".equals(principal)){
            return null;
        }
        String password = "9552370e1e99963578c2eea94a47a8e0";
        String salt = "zxh";
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo("username", password,getName());
        //设置加盐
        authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes(salt));
        return authenticationInfo;
    }

    /**
     * 授权
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }
}
