package com.xpresspayments.GTCollection.gt_collections.exceptions;

public class BadRequestException extends AbstractException {

    public BadRequestException(String code, String message) {
        super(code, message);
    }
}