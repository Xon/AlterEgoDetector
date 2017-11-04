<?php

// This class is used to encapsulate global state between layers without using $GLOBAL[] or
// relying on the consumer being loaded correctly by the dynamic class autoloader
class LiamW_AlterEgoDetector_Globals
{
    const DETECT_METHOD_COOKIE = "aed_detection_method_cookie";
    const DETECT_METHOD_IP     = "aed_detection_method_ip";

    private function __construct() { }
}
