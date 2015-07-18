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
class LiamW_AlterEgoDetector_XenForo_Model_SpamPrevention extends XFCP_LiamW_AlterEgoDetector_XenForo_Model_SpamPrevention
{
    public function aed_getLangaugeForUser($userId)
    {
        if (empty($userId))
        {
            $language = XenForo_Visitor::getInstance()->getLanguage();
            return $language['language_id'];
        }
        return $this->_getDb()->fetchOne('
            SELECT language_id
            FROM xf_user
            WHERE user_id = ?
        ', $userId);
    }

    public function aed_setLangauge($newLanguageId)
    {
        $visitor = XenForo_Visitor::getInstance();
        $language = $visitor->getLanguage();

        if ($newLanguageId == $language['language_id'])
        {
            return $language['language_id'];
        }

        $visitor->setVisitorLanguage($newLanguageId);
        XenForo_Phrase::reset();
        $_phraseCache = array();

        return $language['language_id'];
    }

    protected static $_phraseCache = array();
    public function aed_mapDetectionMethod($method)
    {
        if (empty($phraseCache[$method]))
        {
            $phraseCache[$method] = '' . new XenForo_Phrase($method);
        }
        return $phraseCache[$method];
    }

    public function aed_logScore($phrase, $score, $data = array())
    {
        $data['reason'] = $phrase;

        if (is_numeric($score))
        {
            $data['score'] = sprintf('%+d', $score);
        }
        else
        {
            $data['score'] = '+' . $score;
        }

        $method = empty($data['detection_method'])
                  ? LiamW_AlterEgoDetector_Globals::DETECT_METHOD_COOKIE
                  : $data['detection_method'];
        $data['method'] = $this->aed_mapDetectionMethod($method);

        $this->_resultDetails[] = array(
            'phrase' => $phrase,
            'data' => $data
        );
    }

    public function _updateRegAction(&$action, $newAction)
    {
        switch($action)
        {
            case XenForo_Model_SpamPrevention::RESULT_DENIED:
                break;
            case XenForo_Model_SpamPrevention::RESULT_MODERATED:
                if ($newAction != XenForo_Model_SpamPrevention::RESULT_DENIED)
                {
                    break;
                }
            default:
                $action = $newAction;
                break;
        }
    }

    public function allowRegistration(array $user, Zend_Controller_Request_Http $request)
    {
        $result = parent::allowRegistration($user, $request);

        $userModel = $this->_getUserModel();

        $cookie = $this->getCookieValue();
        $this->_debug('inituser (start): ' . $cookie);
        $options = XenForo_Application::getOptions();
        $registration_mode = $options->aedregistrationmode;
        // $user['user_id'] && $visitor->getUserId(); are current empty at this stage

        // try fetch the cookie out of the session if it has been associated with the session before
        $session = XenForo_Application::getSession();
        if (empty($cookie))
        {
            $cookie = $session->get('aedOriginalUser');
            $this->_debug('inituser (in if): ' . $cookie);
        }

        $action = XenForo_Model_SpamPrevention::RESULT_ALLOWED;
        $this->detect_methods = $this->detectAlterEgo($user, $cookie);
        if ($this->detect_methods)
        {
            $oldlanguage_id = $this->aed_setLangauge($this->aed_getLangaugeForUser($options->aeduserid));
            $this->_debug('Potential Alter Ego Detected.');
            foreach($this->detect_methods as $detect_method)
            {
                $ae_action = $registration_mode;
                if ($detect_method['suppress'])
                {
                    continue;
                }
                $alter_ego_info = array
                (
                    'detection_method' => $detect_method['method'],
                    'username' => $detect_method['user']['username'],
                    'user_id' => $detect_method['user']['user_id'],
                );
                switch ($ae_action)
                {
                    case 0:
                        $this->_debug('Action register ae detected case 0');
                        $this->aed_logScore('aed_detectspamreg_accept', 0, $alter_ego_info);
                        break;
                    case 1:
                        $this->_debug('Action register ae detected case 1');
                        $this->aed_logScore('aed_detectspamreg_moderate', 0, $alter_ego_info);
                        $this->_updateRegAction($action, XenForo_Model_SpamPrevention::RESULT_MODERATED);
                        break;
                    case 2:
                        $this->_debug('Action register ae detected case 2');
                        $this->aed_logScore('aed_detectspamreg_reject', 0, $alter_ego_info);
                        $this->_updateRegAction($action, XenForo_Model_SpamPrevention::RESULT_DENIED);
                        break;
                }
            }

            $this->aed_setLangauge($oldlanguage_id);
        }

        $this->_updateRegAction($result, $action);
        $this->_lastResult = $result;
        return $result;
    }

    var $detect_methods = null;

    public function PostRegistrationAlterEgoDetection(XenForo_ControllerResponse_View $response, array $user, array $extraParams = array())
    {
        if (empty($this->detect_methods))
        {
            return $response;
        }
        $detect_methods = $this->detect_methods;
        $this->detect_methods = null;

        if (XenForo_Application::getOptions()->aed_ReportOnRegister)
        {
            $this->processAlterEgoDetection($user, $detect_methods);
        }

        return $response;
    }


    public function alterEgoCookieToUser($cookie)
    {
        return $cookie;
    }

    public function userToAlterEgoCookie($userId)
    {
        return $userId;
    }

    public function detectAlterEgo($currentUser, $cookie)
    {
        $this->_debug('Detecting alter-egos');
        $detect_methods = array();
        $options = XenForo_Application::getOptions();

        // $user['user_id'] && $visitor->getUserId(); may be empty at this stage
        $currentUserId = empty($currentUser['user_id'])
                        ? 0
                        : $currentUser['user_id'];
        $bypassChecks = empty($currentUser['permissions'])
                        ? false
                        : XenForo_Permission::hasPermission($currentUser['permissions'], 'general', 'aedbypass');

        $currentUserCookie = $this->userToAlterEgoCookie($currentUserId);
        $this->_debug('Resolving user_id:'. $currentUserId .' to cookie:' .$currentUserCookie);

        // skip all alter-ego checks depending on options
        $checkBanned = $options->aedcheckbanned;
        if (!$checkBanned && !empty($currentUser['is_banned']))
        {
            $bypassChecks = true;
        }

        $userModel = $this->_getUserModel();
        $this->_debug('Checking Cookie');
        if ($cookie && $cookie != $currentUserCookie)
        {
            $cookie_user_id = $this->alterEgoCookieToUser($cookie);
            $this->_debug('Resolving cookie:'. $cookie .' to user_id:' .$cookie_user_id);
            // AE DETECTED
            $originalUser = $userModel->getUserById($cookie_user_id, array(
                'join' => XenForo_Model_User::FETCH_USER_PERMISSIONS
            ));
            if ($originalUser && isset($originalUser['user_id']))
            {
                $permissions = XenForo_Permission::unserializePermissions($originalUser['global_permission_cache']);
                $bypassCheck_cookie = XenForo_Permission::hasPermission($permissions, 'general', 'aedbypass');
                $detect_methods[] = array
                (
                    'suppress' => $bypassChecks || (!$checkBanned && $originalUser['is_banned']) || $bypassCheck_cookie,
                    'method' => LiamW_AlterEgoDetector_Globals::DETECT_METHOD_COOKIE,
                    'user' => $originalUser,
                );
                $this->_debug('Cookie detection method triggered for: '. $originalUser['username']);
            }
            else
            {
                // trigger setting a new cookie as the old account was deleted
                $cookie = null;
            }
        }

        $ipOption = $options->aedcheckips;
        if ($ipOption['checkIp'])
        {
            $this->_debug('Checking IP');
            $users = $userModel->getUsersByIp($_SERVER['REMOTE_ADDR'], array(
                'join' => XenForo_Model_User::FETCH_USER_PERMISSIONS
            ));
            $this->_debug(count($users) .' users with IP '.$_SERVER['REMOTE_ADDR'].', Checking for freshness...');
            foreach ($users as &$originalUser)
            {
                if ($currentUserId && $originalUser['user_id'] == $currentUserId)
                {
                    continue;
                }

                if ($originalUser['log_date'] < XenForo_Application::$time - $ipOption['minTime'] * 60)
                {
                    continue;
                }

                $permissions = XenForo_Permission::unserializePermissions($originalUser['global_permission_cache']);
                $bypassCheck_ip = XenForo_Permission::hasPermission($permissions, 'general', 'aedbypass');
                $detect_methods[] = array
                (
                    'suppress' => $bypassChecks || (!$checkBanned && $originalUser['is_banned']) || $bypassCheck_ip,
                    'method' => LiamW_AlterEgoDetector_Globals::DETECT_METHOD_IP,
                    'user' => $originalUser,
                );
                $this->_debug('IP detection method triggered for: '. $originalUser['username']);
            }
        }

        if ($currentUserCookie)
        {
            if (empty($cookie))
            {
                $this->_debug('first time cookie deployment');
                $this->setCookieValue($currentUserCookie, $options->aed_cookie_lifespan * 2592000);
            }
            else if ($options->aedredeploycookie && $cookie != $currentUserCookie )
            {
                $this->_debug('Redeploying cookie');
                $this->setCookieValue($currentUserCookie, $options->aed_cookie_lifespan * 2592000);
            }
        }

        return $detect_methods;
    }

    public function buildUserDetectionReport(array $user, array $detection_methods = null)
    {
        if (empty($detection_methods))
        {
            return '';
        }

        $methods = '';
        foreach($detection_methods as $detect_method)
        {
            if ($detect_method['suppress'])
            {
                continue;
            }
            $methods .= " - " .$this->aed_mapDetectionMethod($detect_method['method']) . "\n";
        }

        if (empty($methods))
        {
            return '';
        }

        return new XenForo_Phrase('aed_thread_message_user', array(
                'username' => $user['username'],
                'userLink' => XenForo_Link::buildPublicLink('full:members', $user)
            )) .
            new XenForo_Phrase('aed_triggered_detection_methods') . "\n" .
            $methods . "\n";
    }

    public function buildUserDetectionReportBody(array $alterEgoUser, array $users)
    {
        // build the message body
        $message = new XenForo_Phrase('aed_thread_message', array(
            'username' => $alterEgoUser['username'],
            'userLink' => XenForo_Link::buildPublicLink('full:members', $alterEgoUser)
        )) . "\n\n";
        foreach($users as $user)
        {
            $message .= $this->buildUserDetectionReport($user, $user['detection_methods']);
        }

        return $message;
    }

    public function processAlterEgoDetection($alterEgoUser, array $detect_methods)
    {
        $this->_debug('Reporting alter-egos');

        $userModel = $this->_getUserModel();
        $options = XenForo_Application::getOptions();

        // if the user doesn't exist, skip checking altogether and delete cookie.
        if (!$alterEgoUser || !isset($alterEgoUser['user_id']))
        {
            $this->setCookieValue(false);

            return;
        }

        if (empty($detect_methods))
        {
            return;
        }

        unset($alterEgoUser['permissions']);
        unset($alterEgoUser['global_permission_cache']);
        $reportedUser = $alterEgoUser;
        $reportedUserId = $reportedUser['user_id'];
        $users = array();
        // ensure consistent ordering by picking a user as 'first'
        foreach($detect_methods as $detect_method)
        {
            if ($detect_method['suppress'])
            {
                continue;
            }

            $userId = $detect_method['user']['user_id'];
            if (empty($users[$userId]))
            {
                $users[$userId] = $detect_method['user'];
                if ($userId < $reportedUserId)
                {
                    $reportedUserId = $userId;
                }
            }
            $user = $users[$userId];

            $arr = array();
            if (!empty($user['detection_methods']))
            {
                $arr = $user['detection_methods'];
            }
            unset($detect_method['user']);
            $arr[] = $detect_method;
            $user['detection_methods'] = $arr;
            unset($user['permissions']);
            unset($user['global_permission_cache']);
            $users[$userId] = $user;
        }

        if (isset($users[$reportedUserId]))
        {
            $reportedUser = $users[$reportedUserId];
        }

        // only report if detection methods are unsupressed
        $AE_count = count($users);
        if ($AE_count == 0)
        {
            return;
        }

        $userId = $options->aeduserid;
        $username = $options->aedusername;
        if (empty($userId))
        {
            $userId = 1;
            XenForo_Error::logException(new Exception("Alter Ego Detector - UserId not set, defaulting to 1"), false);
        }
        if (empty($username))
        {
            $username = $this->_getDb()->fetchOne('
                SELECT username
                FROM xf_user
                WHERE user_id = ?
            ', $userId);
        }
        $oldlanguage_id = $this->aed_setLangauge($this->aed_getLangaugeForUser($userId));
        try
        {
            $originalUsername = $reportedUser['username'];
            $user = reset($users);
            $alterEgoUsername = $reportedUser['user_id'] != $alterEgoUser['user_id']
                                ? $alterEgoUser['username']
                                : $user['username'];
            // build the title
            if ($AE_count == 1)
            {
                $title = new XenForo_Phrase('aed_thread_subject', array(
                    'username1' => $originalUsername,
                    'username2' => $alterEgoUsername,
                ));
            }
            else
            {
                $title = new XenForo_Phrase('aed_thread_subject_count', array(
                    'username' => $reportedUser['username'],
                    'count' => $AE_count,
                ));
            }

            $message = $this->buildUserDetectionReportBody($alterEgoUser, $users);

            if ($options->aedcreatethread)
            {
                try
                {
                    $forumId = $options->aedforumid;

                    $forum = $this->_getForumModel()->getForumById($forumId);
                    if (empty($forumId) || empty($userId) || empty($username) || empty($forum))
                    {
                        throw new Exception("Alter Ego Detector - Create Thread is not properly configured when reporting $alterEgoUsername is an alter ego of $originalUsername");
                    }
                    $default_prefix_id = $forum['default_prefix_id'];

                    $this->_debug('Initialised Thread DataWriter');
                    /* @var $threadDw XenForo_DataWriter_Discussion_Thread */
                    $threadDw = XenForo_DataWriter::create('XenForo_DataWriter_Discussion_Thread');
                    $threadDw->bulkSet(array(
                        'user_id' => $userId,
                        'node_id' => $forumId,
                        'title' => $title,
                        'username' => $username,
                        'prefix_id' => $default_prefix_id,
                    ));

                    $firstPostDw = $threadDw->getFirstMessageDw();
                    $firstPostDw->setOption(XenForo_DataWriter_DiscussionMessage::OPTION_IS_AUTOMATED, true);
                    $firstPostDw->set('message', $message);

                    $this->_debug('Line before thread datawriter save');
                    $threadDw->save();
                    $this->_debug('Thread datawriter saved');
                }
                catch(\Exception $e)
                {
                    XenForo_Error::logException($e, false);
                }
            }

            if ($options->aedsendpm)
            {
                try
                {
                    $conversationRecipientsOption = str_replace(array(
                        "/r",
                        "/r/n"
                    ), "/n", $options->aedpmrecipients);
                    $conversationRecipients = array_filter(explode("/n", $conversationRecipientsOption));

                    $starterArray = $userModel->getFullUserById($userId, array(
                        'join' => XenForo_Model_User::FETCH_USER_FULL | XenForo_Model_User::FETCH_USER_PERMISSIONS
                    ));
                    if (empty($starterArray) || empty($username) || empty($conversationRecipients))
                    {
                        throw new Exception("Alter Ego Detector - Start PM is not properly configured when reporting $alterEgoUsername is an alter ego of $originalUsername");
                    }
                    $starterArray['permissions'] = XenForo_Permission::unserializePermissions($starterArray['global_permission_cache']);


                    /* @var $conversationDw XenForo_DataWriter_ConversationMaster */
                    $this->_debug('Conversation datawriter initialised.');
                    $conversationDw = XenForo_DataWriter::create('XenForo_DataWriter_ConversationMaster');
                    $conversationDw->setExtraData(XenForo_DataWriter_ConversationMaster::DATA_ACTION_USER, $starterArray);
                    $conversationDw->set('user_id', $userId);
                    $conversationDw->set('username', $username);
                    $conversationDw->set('title', $title);
                    $conversationDw->set('open_invite', 1);
                    $conversationDw->set('conversation_open', 1);
                    $conversationDw->addRecipientUserNames($conversationRecipients);

                    $firstMessageDw = $conversationDw->getFirstMessageDw();
                    $firstMessageDw->setOption(XenForo_DataWriter_ConversationMessage::OPTION_SET_IP_ADDRESS, true);
                    $firstMessageDw->set('message', $message);

                    $this->_debug('Line before conversation save');
                    $conversationDw->save();
                    $this->_debug('Line after conversation save');
                }
                catch(\Exception $e)
                {
                    XenForo_Error::logException($e, false);
                }
            }

            if ($options->aedreport)
            {
                try
                {
                    $this->_debug('reporting initialised.');

                    if (empty($userId))
                    {
                        throw new Exception("Alter Ego Detector - Start Report is not properly configured when reporting $alterEgoUsername is an alter ego of $originalUsername");
                    }

                    /* @var $reportModel XenForo_Model_Report */
                    $reportModel = XenForo_Model::create('XenForo_Model_Report');

                    $users[$reportedUser['user_id']] = $reportedUser;
                    $users[$alterEgoUser['user_id']] = $alterEgoUser;
                    $userIds = array_keys($users);
                    $reportContent = array();
                    $reportContent[] = $reportedUser;
                    foreach($users as $user)
                    {
                        if ($reportedUser['user_id'] == $user['user_id'])
                        {
                            continue;
                        }
                        $reportContent[] = $user;
                    }

                    // ensure alter-ego detection doesn't nag
                    $makeReport = true;
                    $report = false;
                    $newAlterEgos = array();
                    // do not allow reporting of the alter ego reporter id
                    if ($userId != $reportedUser['user_id'] && $userId != $alterEgoUser['user_id'])
                    {
                        $report = $reportModel->getReportByContent('alterego', $reportedUser['user_id']);
                    }

                    if ($report)
                    {
                        // update the report to add more users.
                        $content_info = @unserialize($report['content_info']);
                        if (empty($content_info['0']))
                        {
                            $content_info['0'] = $reportContent;
                        }

                        // update exiting users
                        foreach($content_info['0'] as $key => $user)
                        {
                            $_userid = $user['user_id'];
                            if (empty($users[$_userid]))
                            {
                                continue;
                            }
                            $this->_debug('updating alter ego report content for ' .$_userid .'- ' . $users[$_userid]['username']);
                            $content_info['0'][$key] = $users[$_userid];
                        }

                        // determine if there are any new users to add
                        $userIdsReported = XenForo_Application::arrayColumn($content_info['0'], 'user_id');
                        $userIds = array_diff($userIds, $userIdsReported);
                        if ($userIds)
                        {
                            foreach($userIds as $_userid)
                            {
                                if (empty($users[$_userid]))
                                {
                                    $this->_debug('Can not find ' .$_userid );
                                    continue;
                                }
                                $this->_debug('Adding alter ego report content for ' .$_userid .'- ' . $users[$_userid]['username']);
                                $content_info['0'][] = $users[$_userid];
                            }
                            $reportContent = $content_info['0'];
                        }
                        $sendDuplicate = $options->aedreport_senddupe;

                        if (isset($sendDuplicate[$report['report_state']]))
                        {
                            $makeReport = $sendDuplicate[$report['report_state']];
                            // update user content
                            $reportDw = XenForo_DataWriter::create('XenForo_DataWriter_Report');
                            $reportDw->setExistingData($report, true);
                            $reportDw->set('content_info', $content_info);
                            $reportDw->save();
                        }
                        else
                        {
                            $makeReport = false;
                        }

                        $this->_debug('Report State:' . $report['report_state']);
                    }

                    if ($makeReport)
                    {
                        $this->_debug('Make report: ' . $makeReport . ' for '. $originalUsername. ' to report AE: '. $alterEgoUsername);
                        $message = XenForo_Helper_String::bbCodeStrip($message);
                        $reportModel->reportContent('alterego', $reportContent, $message, $userModel->getFullUserById($userId));
                    }
                    else
                    {
                        $this->_debug('Suppressing duplicate report.');
                    }
                }
                catch(\Exception $e)
                {
                    XenForo_Error::logException($e, false);
                }
            }
        }
        catch(\Exception $e)
        {
            $this->aed_setLangauge($oldlanguage_id);
            throw $e;
        }
        $this->aed_setLangauge($oldlanguage_id);
    }

    /**
     * Gets the cookie value, or null if the cookie isn't set.
     *
     * @return string|null
     */
    public function getCookieValue()
    {
        $cookieName = XenForo_Application::getOptions()->liam_aed_cookiename;

        if (isset($_COOKIE[$cookieName]))
        {
            return $_COOKIE[$cookieName];
        }
        else
        {
            return null;
        }
    }

    /**
     * Sets the AED cookie value.
     *
     * @param     $value string|boolean The cookie false. False to remove cookie.
     * @param int $time  int How long the cookie is valid for, in seconds.
     */
    public function setCookieValue($value, $time = 31536000)
    {
        $cookieName = XenForo_Application::getOptions()->liam_aed_cookiename;

        if ($value === false)
        {
            setcookie($cookieName, false, XenForo_Application::$time - 3600);
        }
        else
        {
            setcookie($cookieName, $value, XenForo_Application::$time + $time);
        }
    }

    protected function _getForumModel()
    {
        return $this->getModelFromCache('XenForo_Model_Forum');
    }

    protected function _getUserModel()
    {
        return $this->getModelFromCache('XenForo_Model_User');
    }

    protected function _debug($message)
    {
        if (XenForo_Application::getOptions()->aeddebugmessages)
        {
            XenForo_Error::debug($message);
        }
    }
}
