package com.patternknife.securityhelper.oauth2.domain.common.dto;

import lombok.Data;

@Data
public class SorterValueFilter {
    private String column;
    private Boolean asc;
}
