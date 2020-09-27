package com.heli.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author konglingpeng
 * @description
 * @date 2020/7/27 下午4:51
 */
@Data
@ConfigurationProperties(prefix = "radius.client")
public class RadiusClientAutoConfigureProperties {

}
