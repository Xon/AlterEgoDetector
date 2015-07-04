<?php

/**
 * Copyright 2014 Liam Williams
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
class LiamW_AlterEgoDetector_XenForo_ControllerPublic_Login extends XFCP_LiamW_AlterEgoDetector_XenForo_ControllerPublic_Login
{
    public function actionLogin()
    {
        $response = parent::actionLogin();

        $spamModel = $this->_getSpamModel();
        $cookie = $spamModel->getCookieValue();
        $currentUserId = XenForo_Visitor::getInstance()->getUserId();
        if (!$currentUserId)
        {
            /* @var $session XenForo_Session */
            $session = XenForo_Application::getSession();
            $session->set('aedOriginalUser', $cookie);
            return $response;
        }

        $currentUser = $this->_getUserModel()->getUserById($currentUserId, array(
            'join' => XenForo_Model_User::FETCH_USER_PERMISSIONS
        ));
        $currentUser['permissions'] = XenForo_Permission::unserializePermissions($currentUser['global_permission_cache']);

        $detect_methods = $spamModel->detectAlterEgo($currentUser, $cookie);
        if ($detect_methods)
        {
            $spamModel->processAlterEgoDetection($currentUser, $detect_methods);
        }
        return $response;
    }

    protected function _getSpamModel()
    {
        return $this->getModelFromCache('XenForo_Model_SpamPrevention');
    }
}
