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

        $this->_resultDetails[] = array(
            'phrase' => $phrase,
            'data' => $data
        );
    }

    public function allowRegistration(array $user, Zend_Controller_Request_Http $request)
    {
        $result = parent::allowRegistration($user, $request);

        $userModel = $this->_getUserModel();

        $cookie = $this->getCookieValue();
        $this->_debug('$inituser (start): ' . $cookie);
        $type = XenForo_Application::getOptions()->aedregistrationmode;
        // $user['user_id'] && $visitor->getUserId(); are current empty at this stage

        $session = XenForo_Application::getSession();
        if ($cookie = $session->get('aedOriginalUser'))
        {
            $this->_debug('$inituser (in if): ' . $cookie);
        }

        $action = XenForo_Model_SpamPrevention::RESULT_ALLOWED;
        if ($cookie)
        {
            $this->_debug('Cookie true');

            $originalUserId = $cookie;
            $originalUser = $userModel->getUserById($originalUserId, array(
                'join' => XenForo_Model_User::FETCH_USER_PERMISSIONS
            ));
            // cookie exists but the user doesn't
            if (is_array($originalUser) && isset($originalUser['username']))
            {
                $originalUser['permissions'] = XenForo_Permission::unserializePermissions($originalUser['global_permission_cache']);
                $originalUsername = $originalUser['username'];

                $bypassCheck = XenForo_Permission::hasPermission($originalUser['permissions'], 'general', 'aedbypass');
                if ($bypassCheck)
                {
                    $type = 0;
                }
                $this->_debug('Action register ae detected.');
                switch ($type)
                {
                    case 0:
                        $this->_debug('Action register ae detected case 0');
                        $this->aed_logScore('aed_detectspamreg_accept', 0, array(
                            'username' => $originalUsername,
                            'user_id' => $originalUserId
                        ));
                        break;
                    case 1:
                        $this->_debug('Action register ae detected case 1');
                        $this->aed_logScore('aed_detectspamreg_moderate', 0, array(
                            'username' => $originalUsername,
                            'user_id' => $originalUserId
                        ));
                        $action = XenForo_Model_SpamPrevention::RESULT_MODERATED;
                        break;
                    case 2:
                        $this->_debug('Action register ae detected case 2');
                        $this->aed_logScore('aed_detectspamreg_reject', 0, array(
                            'username' => $originalUsername,
                            'user_id' => $originalUserId
                        ));
                        $action = XenForo_Model_SpamPrevention::RESULT_DENIED;
                        break;
                }
            }
        }


        if ($action == XenForo_Model_SpamPrevention::RESULT_DENIED)
        {
            $result = XenForo_Model_SpamPrevention::RESULT_DENIED;
        }
        elseif (($result == XenForo_Model_SpamPrevention::RESULT_ALLOWED) && ($action == XenForo_Model_SpamPrevention::RESULT_MODERATED))
        {
            $result = XenForo_Model_SpamPrevention::RESULT_MODERATED;
        }

        $this->_lastResult = $result;

        return $result;
    }

    public function processAlterEgoDetection($originalUser, $alterEgoUser)
    {
        $userModel = $this->_getUserModel();
        $options = XenForo_Application::getOptions();

        if (!$originalUser || !$alterEgoUser || !isset($originalUser['user_id']) || !isset($alterEgoUser['user_id'])) // if any of the users don't exist, skip checking altogether and delete cookie.
        {
            $this->setCookieValue(false);

            return;
        }

        if ($alterEgoUser['user_id'] == $originalUser['user_id'])
        {
            return;
        }

        $newUserId = $alterEgoUser['user_id'];
        // ensure consistent ordering
        if ($alterEgoUser['user_id'] < $originalUser['user_id'])
        {
            $tmp = $originalUser;
            $originalUser = $alterEgoUser;
            $alterEgoUser = $tmp;
        }

        $originalUsername = $originalUser['username'];
        $alterEgoUsername = $alterEgoUser['username'];

        $userLink1 = XenForo_Link::buildPublicLink('full:members', $originalUser);
        $userLink2 = XenForo_Link::buildPublicLink('full:members', $alterEgoUser);

        $title = new XenForo_Phrase('aed_thread_subject', array(
            'username1' => $originalUsername,
            'username2' => $alterEgoUsername,
        ));
        $message = new XenForo_Phrase('aed_thread_message', array(
            'username1' => $originalUsername,
            'username2' => $alterEgoUsername,
            'userLink1' => $userLink1,
            'userLink2' => $userLink2
        ));

        if ($options->aedcreatethread)
        {
            try
            {
                $forumId = $options->aedforumid;
                $userId = $options->aeduserid;
                $username = $options->aedusername;
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
                $conversationStarterId = $options->aedpmsenderid;
                $conversationStarterUsername = $options->aedpmusername;
                $conversationRecipientsOption = str_replace(array(
                    "/r",
                    "/r/n"
                ), "/n", $options->aedpmrecipients);
                $conversationRecipients = array_filter(explode("/n", $conversationRecipientsOption));

                $starterArray = $userModel->getFullUserById($conversationStarterId, array(
                    'join' => XenForo_Model_User::FETCH_USER_FULL | XenForo_Model_User::FETCH_USER_PERMISSIONS
                ));
                if (empty($starterArray) || empty($conversationStarterUsername) || empty($conversationRecipients))
                {
                    throw new Exception("Alter Ego Detector - Start PM is not properly configured when reporting $alterEgoUsername is an alter ego of $originalUsername");
                }
                $starterArray['permissions'] = XenForo_Permission::unserializePermissions($starterArray['global_permission_cache']);


                /* @var $conversationDw XenForo_DataWriter_ConversationMaster */
                $this->_debug('Conversation datawriter initialised.');
                $conversationDw = XenForo_DataWriter::create('XenForo_DataWriter_ConversationMaster');                
                $conversationDw->setExtraData(XenForo_DataWriter_ConversationMaster::DATA_ACTION_USER, $starterArray);
                $conversationDw->set('user_id', $conversationStarterId);
                $conversationDw->set('username', $conversationStarterUsername);
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

                $reporterId = $options->liam_aed_reporter;

                if (empty($reporterId))
                {
                    throw new Exception("Alter Ego Detector - Start Report is not properly configured when reporting $alterEgoUsername is an alter ego of $originalUsername");
                }

                /* @var $reportModel XenForo_Model_Report */
                $reportModel = XenForo_Model::create('XenForo_Model_Report');

                $reportContent = array
                (
                    $originalUser,
                    $alterEgoUser
                );
                // ensure alter-ego detection doesn't nag
                $makeReport = true;
                $report = false;
                $newAlterEgo = true;
                // do not allow reporting of the alter ego reporter id
                if ($reporterId != $originalUser['user_id'] && $reporterId != $alterEgoUser['user_id'])
                {
                    $report = $reportModel->getReportByContent('alterego', $originalUser['user_id']);
                }

                if ($report)
                {
                    // update the report to add more users.
                    $content_info = @unserialize($report['content_info']);
                    if (empty($content_info['0']))
                    {
                        $content_info['0'] = $reportContent;
                    }
                    foreach($content_info['0'] as $user)
                    {
                        if ($user['user_id'] == $alterEgoUser['user_id'])
                        {
                            $newAlterEgo = false;
                            break;
                        }
                    }
                    if ($newAlterEgo)
                    {
                        $this->_debug('Adding alter ago '. $alterEgoUsername. ' to known report for '. $originalUsername);
                        $content_info['0'][] = $alterEgoUser;
                        $reportContent = $content_info['0'];


                        $reportDw = XenForo_DataWriter::create('XenForo_DataWriter_Report');
                        $reportDw->setExistingData($report, true);
                        $reportDw->set('content_info', $content_info);
                        $reportDw->save();
                    }
                    else
                    {
                        $sendDuplicate = $options->aedreport_senddupe;

                        if (isset($sendDuplicate[$report['report_state']]))
                        {
                            $makeReport = $sendDuplicate[$report['report_state']];
                        }
                        else
                        {
                            $makeReport = false;
                        }

                        $this->_debug('Report State:' . $report['report_state']);
                    }
                }

                if ($makeReport)
                {
                    $this->_debug('Make report: ' . $makeReport . ' for '. $originalUsername. ' to report AE: '. $alterEgoUsername);
                    $message = XenForo_Helper_String::bbCodeStrip($message);
                    $reportModel->reportContent('alterego', $reportContent, $message, $userModel->getFullUserById($reporterId));
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

        if ($options->aedredeploycookie)
        {
            $this->setCookieValue($newUserId, $options->aed_cookie_lifespan * 2592000);
        }
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

    private function _getUserModel()
    {
        return $this->getModelFromCache('XenForo_Model_User');
    }

    private function _debug($message)
    {
        if (XenForo_Application::getOptions()->aeddebugmessages)
        {
            XenForo_Error::debug($message);
        }
    }
}