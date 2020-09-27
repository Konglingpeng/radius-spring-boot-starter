package com.heli.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author konglingpeng
 * @description
 * @date 2020/7/27 下午4:51
 */
@Data
@ConfigurationProperties(prefix = "radius.server")
public class RadiusServerAutoConfigureProperties {
    private String host = "localhost";
    private Integer socketTimeoutMillis = 3000;
    private Long duplicateIntervalMillis = 300000L;
    private Boolean enableAuth = true;
    private Integer authPort = 1812;
    private Boolean enableAccount = true;
    private Integer accountPort = 1813;
    private Boolean enableMultiThread = false;
    private Integer threadPoolSize = 5;
}
