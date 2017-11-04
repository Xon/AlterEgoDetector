<?php

class LiamW_AlterEgoDetector_Option_UserId
{
    public static function verifyOption_AllowGuest(&$option, XenForo_DataWriter $dw, $fieldName)
    {
        if ($option == 0)
        {
            return true;
        }

        return self::verifyOption($option, $dw, $fieldName);
    }

    public static function verifyOption(&$option, XenForo_DataWriter $dw, $fieldName)
    {
        $option = trim($option);
        if ($option == '')
        {
            return true;
        }

        /** @var XenForo_Model_User $userModel */
        $userModel = XenForo_Model::create("XenForo_Model_User");
        $user = $userModel->getUserById($option);

        if (!empty($user))
        {
            return true;
        }

        if ($option == 1)
        {
            $option = '';

            return true;
        }

        $dw->error(new XenForo_Phrase('aed_user_id_not_found', ['UserId' => $option], $fieldName));

        return false;
    }
}
