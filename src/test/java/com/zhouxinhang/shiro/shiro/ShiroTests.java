package com.zhouxinhang.shiro.shiro;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.junit.Test;

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


}
