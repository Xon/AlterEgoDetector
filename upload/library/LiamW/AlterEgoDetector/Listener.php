<?php

class LiamW_AlterEgoDetector_Listener
{
    const AddonNameSpace = 'LiamW_AlterEgoDetector_';

    public static function load_class($class, array &$extend)
    {
        $extend[] = self::AddonNameSpace . $class;
    }
}
