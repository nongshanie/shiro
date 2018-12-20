package com.zhouxinhang.shiro.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author: zhouxinhang
 * @date: 2018/12/20
 * @Description:
 */
public class PermissionRealm extends AuthorizingRealm {
    //Realm的名称
    @Override
    public String getName() {
        return "PermissionRealm";
    }
    //认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String principal = (String) token.getPrincipal();
        if(!"zhangsan".equals(principal)){
            return null;
        }
        //静态数据,模拟数据库中获取到的.
        String password = "666";
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(principal, password,getName());
        return simpleAuthenticationInfo;
    }
    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //获取身份信息,此处获取到的用户名是用户放入到SimpleAuthenticationInfo的principal
        //具体转成什么类型是根据放入到SimpleAuthenticationInfo的principal来定的
        String principal = (String) principals.getPrimaryPrincipal();

        //根据身份信息从数据库中查询权限数据
        //此处我们就模拟从数据库中查询到用户对应的角色数据
        List roles = new ArrayList<String>();
        roles.addAll(Arrays.asList("role1","role2"));
        //此处我们就模拟从数据库中查询到用户的权限数据。通过用户--->角色---->权限
        List permissions = new ArrayList<String>();
        permissions.addAll(Arrays.asList("user:create","user:update",",user:delete"));

        //创建授权对象
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        //将角色信息封闭为AuthorizationInfo
        simpleAuthorizationInfo.addRoles(roles);
        //将权限信息封闭为AuthorizationInfo
        simpleAuthorizationInfo.addStringPermissions(permissions);

        //返回授权信息
        return simpleAuthorizationInfo;
    }
}

