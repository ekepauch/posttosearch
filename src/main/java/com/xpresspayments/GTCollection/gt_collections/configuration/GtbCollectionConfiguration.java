package com.xpresspayments.GTCollection.gt_collections.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "gt")
@Data
public class GtbCollectionConfiguration {
    private String username;
    private String password;
    private String hash_value;

}
