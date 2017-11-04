<?php

class LiamW_AlterEgoDetector_Listener
{
    public static function load_class($class, array &$extend)
    {
        $extend[] = 'LiamW_AlterEgoDetector_' . $class;
    }
}
