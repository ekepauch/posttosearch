package com.xpresspayments.GTCollection.gt_collections.utility;


public class CustomResponseCode {

    public static final String DEFAULT = "0";
    public static final String FAILED = "101";

    public static final String INVALID_REQUEST = "01";
    public static final String SUCCESS_200 = "200";
   
    public static final String SUCCESS_00 = "00";
    public static final String SUCCESS_90000 = "90000";


    public static final String CONFLICT_EXCEPTION = "07";
    public static final String LOCKED_EXCEPTION = "423";

    public static final String NOT_FOUND_EXCEPTION = "04";
    public static final String SUCCESS = "00";

    public static final int ACTIVE_USER = 1;
    public static final int INACTIVE_USER = 0;
    public static final int DEACTIVE_USER = 2;

    public static final String CHANGE_P_REQUIRED = "15";

    public static final String UNAUTHORIZED = "02";
    public static final String OTHERS = "05";

    public static final int ENABLE = 1;
    public static final int DISABLE = 0;

    public static final int DB_SUCCESS = 1;




    public static final String USER_CATEGORY_COORPORATE = "C";
    public static final String USER_CATEGORY_XPPRESS_USER = "S";

    public static final String FORGET_PASSWORD = "F";
    public static final String LOGIN = "L";
    public static final String CREATE_USER = "C";



    public static final String EMAIL_URL = "EMAIL_URL";
    public static final String SMS_URL = "SMS_URL";

    /*.............................*/

    public static final String CHARGE_FEE = "CHARGE_FEE";
    public static final String LOGIN_ATTEMPTS_CONFIG = "LOGIN_ATTEMPTS_CONFIG";

    public static final String TRANSACTION_INITIATED = "I";
    public static final String TRANSACTION_UPLOADED = "U";
    public static final String TRANSACTION_UPLOAD_VALIDATION = "V";
    public static final String TRANSACTION_PROCESSING = "P";
    public static final String TRANSACTION_COMPLETED = "C";
    public static final String TRANSACTION_REJECTED = "R";
    public static final String TRANSACTION_APPROVAL_IN_PROGRESS = "A";
    public static final String TRANSACTION_UPLOAD_FAILED = "F";


    public static final String XPRESS_TOKEN="T";
    public static final String SMS_TOKEN="S";
    public static final String MAIL_TOKEN="M";
    public static final String SMS_MAIL_TOKEN="B";

    public static final String GLOBAL_CHARGE="global";
    public static final String CORPORATE_CHARGE="corporate";


    public static final String BENE_TRAN_IN_PROGRESS="06";
    public static final String BENE_TRAN_ACCEPTED="16";
    public static final String BENE_TRAN_FAILED="99";
    public static final String BENE_TRAN_DISAAPPROVED="09";
    public static final String BENE_TRAN_SUCCESSFUL="00";



}
