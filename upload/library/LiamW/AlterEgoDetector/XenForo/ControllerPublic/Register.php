<?php

class LiamW_AlterEgoDetector_XenForo_ControllerPublic_Register extends XFCP_LiamW_AlterEgoDetector_XenForo_ControllerPublic_Register
{
    protected function _completeRegistration(array $user, array $extraParams = array())
    {
        $response = parent::_completeRegistration($user, $extraParams);

        try
        {
            $spamModel = $this->_getSpamPreventionModel();
            $cookie = $spamModel->getCookieValue();
            $options = XenForo_Application::getOptions();
            if($options->aedredeploycookie || empty($cookie))
            {
                $cookie = $spamModel->userToAlterEgoCookie($user['user_id']);
            }

            $this->_debug('Setting cookie for user:' . $user['user_id'] . ' cookie:'.$cookie);
            $session = XenForo_Application::getSession();
            $session->set('aedOriginalUser', $cookie);
            $spamModel->setCookieValue($cookie, $options->aed_cookie_lifespan * 2592000);

            if ($response instanceof XenForo_ControllerResponse_View)
            {
                $response = $spamModel->PostRegistrationAlterEgoDetection($response, $user, $extraParams);
            }
        }
        catch(Exception $e)
        {
            // do not block login if any sort of error occurs
            XenForo_Error::logException($e, false);
        }
        return $response;
    }

    /**
     * @return LiamW_AlterEgoDetector_XenForo_Model_SpamPrevention|XenForo_Model
     */
    protected function _getSpamPreventionModel()
    {
        return $this->getModelFromCache('XenForo_Model_SpamPrevention');
    }

    protected function _debug($message)
    {
        if (XenForo_Application::getOptions()->aeddebugmessages)
        {
            XenForo_Error::logException(new Exception($message), false);
        }
    }
}
