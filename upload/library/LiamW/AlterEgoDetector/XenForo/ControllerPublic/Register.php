<?php

class LiamW_AlterEgoDetector_XenForo_ControllerPublic_Register extends XFCP_LiamW_AlterEgoDetector_XenForo_ControllerPublic_Register
{
    protected function _completeRegistration(array $user, array $extraParams = array())
    {
        $spamModel = $this->_getSpamModel();
        $cookie = $spamModel->getCookieValue();
        $options = XenForo_Application::getOptions();
        if($options->aedredeploycookie || empty($cookie))
        {
            $cookie = $user['user_id'];
        }

        $this->_debug('Setting cookie for user:' . $user['user_id'] . ' cookie:'.$cookie);
        $session = XenForo_Application::getSession();
        $session->set('aedOriginalUser', $cookie);
        $spamModel->setCookieValue($cookie, $options->aed_cookie_lifespan * 2592000);

        return parent::_completeRegistration($user, $extraParams);
    }

    protected function _getSpamModel()
    {
        return $this->getModelFromCache('XenForo_Model_SpamPrevention');
    }
    
    protected function _debug($message)
    {
        if (XenForo_Application::getOptions()->aeddebugmessages)
        {
            XenForo_Error::debug($message);
        }
    }
}