<?php


class LiamW_AlterEgoDetector_XenForo_ControllerPublic_Logout extends XFCP_LiamW_AlterEgoDetector_XenForo_ControllerPublic_Logout
{
    protected function _assertNotBanned()
    {
        if (XenForo_Application::getOptions()->aed_banned_logout)
        {
            return;
        }
        parent::_assertNotBanned();
    }

    protected function _getRetainedCookies()
    {
        $cookies = parent::_getRetainedCookies();
        if ($cookieName = XenForo_Application::getOptions()->liam_aed_cookiename)
        {
            $cookies[] = $cookieName;
        }
        return $cookies;
    }
}
