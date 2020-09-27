package com.heli.annotation;

import org.springframework.stereotype.Component;

import java.lang.annotation.*;

/**
 * @author konglingpeng
 * @description
 * @date 2020/7/27 下午4:56
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Component
public @interface RadiusServer {
}
