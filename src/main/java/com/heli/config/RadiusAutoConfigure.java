package com.heli.config;

import com.heli.annotation.RadiusServer;
import com.heli.endpoints.AbstractRadiusServer;
import com.heli.packet.RadiusPacket;
import com.heli.properties.RadiusClientAutoConfigureProperties;
import com.heli.properties.RadiusServerAutoConfigureProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;
import java.lang.annotation.Annotation;
import java.net.*;
import java.util.concurrent.Executors;

/**
 * @author konglingpeng
 * @description
 * @date 2020/7/25 下午2:26
 */
@Configuration
@ConditionalOnClass
@EnableConfigurationProperties(value = {RadiusServerAutoConfigureProperties.class, RadiusClientAutoConfigureProperties.class})
@Slf4j
public class RadiusAutoConfigure {
    @Autowired
    private RadiusServerAutoConfigureProperties radiusServerAutoConfigureProperties;
    @Autowired
    private AbstractRadiusServer abstractRadiusServer;

    @PostConstruct
    public void startServer(){
        try {
            Class<? extends AbstractRadiusServer> radiusServerClass = abstractRadiusServer.getClass();
            RadiusServer radiusServerClassAnnotation = radiusServerClass.getAnnotation(RadiusServer.class);
            Class<?> tempServerAnnotation = checkAnnotation(radiusServerClass);

            if (radiusServerClassAnnotation == null){
                if (tempServerAnnotation == null){
                    throw new RuntimeException("Please add @RadiusServer on " + radiusServerClass.getName());
                }else {
                    throw new RuntimeException("Please use @RadiusServer on " + radiusServerClass.getName() + " instead of @" + tempServerAnnotation.getSimpleName());
                }
            }
            abstractRadiusServer.setSocketTimeout(radiusServerAutoConfigureProperties.getSocketTimeoutMillis());
            abstractRadiusServer.setDuplicateInterval(radiusServerAutoConfigureProperties.getDuplicateIntervalMillis());
            abstractRadiusServer.setListenAddress(InetAddress.getByName(radiusServerAutoConfigureProperties.getHost()));
            abstractRadiusServer.setAuthPort(radiusServerAutoConfigureProperties.getAuthPort());
            abstractRadiusServer.setAcctPort(radiusServerAutoConfigureProperties.getAccountPort());
            if (radiusServerAutoConfigureProperties.getEnableMultiThread()){
                if (radiusServerAutoConfigureProperties.getThreadPoolSize() < 1){
                    log.info("pool-size less than 1, using singleThread mode");
                }else {
                    abstractRadiusServer.setExecutor(Executors.newFixedThreadPool(radiusServerAutoConfigureProperties.getThreadPoolSize()));
                }
            }
            abstractRadiusServer.setEnableAuth(radiusServerAutoConfigureProperties.getEnableAuth());
            abstractRadiusServer.setEnableAccount(radiusServerAutoConfigureProperties.getEnableAccount());
            abstractRadiusServer.start();
        } catch (SocketException | UnknownHostException e) {
            e.printStackTrace();
        }
    }

    private <T> Class<?> checkAnnotation(Class<? extends T> clazz){
        Class<?> tempAnnotation = null;
        Annotation[] serverAnnotations = clazz.getAnnotations();
        for (Annotation serverAnnotation : serverAnnotations) {
            Class<? extends Annotation> aClass = serverAnnotation.annotationType();
            String name = serverAnnotation.getClass().getName();
            if (aClass.equals(Component.class)){
                tempAnnotation = Component.class;
            }
            if (aClass.equals(Service.class)){
                tempAnnotation = Service.class;
            }
            if (aClass.equals(Controller.class)){
                tempAnnotation = Controller.class;
            }
        }
        return tempAnnotation;
    }
    
    @Bean(name = "radiusPacketObjectFactory")
    public ObjectFactory<RadiusPacket> initObjectFactory(){
        return RadiusPacket::new;
    }
}
