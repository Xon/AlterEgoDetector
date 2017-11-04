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
    /**
     * @param int $userId
     * @return int
     */
    public function aed_getLangaugeForUser($userId)
    {
        if (empty($userId))
        {
            $language = XenForo_Visitor::getInstance()->getLanguage();

            return $language['language_id'];
        }

        return $this->_getDb()->fetchOne(
            '
            SELECT language_id
            FROM xf_user
            WHERE user_id = ?
        ', $userId
        );
    }

    /**
     * @param int $newLanguageId
     * @return int
     */
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

        return $language['language_id'];
    }

    /**
     * @param string     $phrase
     * @param string|int $score
     * @param array      $data
     */
    public function aed_logScore($phrase, $score, $data = [])
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

        $data['method'] = empty($data['detection_method'])
            ? new XenForo_Phrase(LiamW_AlterEgoDetector_Globals::DETECT_METHOD_COOKIE)
            : $data['detection_method'];

        $this->_resultDetails[] = [
            'phrase' => $phrase,
            'data'   => $data
        ];
    }

    /**
     * @param string $action
     * @param string $newAction
     */
    public function _updateRegAction(&$action, $newAction)
    {
        switch ($action)
        {
            case XenForo_Model_SpamPrevention::RESULT_DENIED:
                break;
            /** @noinspection PhpMissingBreakStatementInspection */
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

    /**
     * @param array                        $user
     * @param Zend_Controller_Request_Http $request
     * @return string
     */
    public function allowRegistration(array $user, Zend_Controller_Request_Http $request)
    {
        $result = parent::allowRegistration($user, $request);
        try
        {
            $userModel = $this->_getUserModel();

            $cookie = $this->getCookieValue();
            $this->_debug('inituser (start): ' . $cookie);
            $options = XenForo_Application::getOptions();
            $aeduserid = $options->aeduserid;
            if (empty($aeduserid))
            {
                return $result;
            }
            $registration_mode = $options->aedregistrationmode;
            $registration_mode_group = $options->aedregistrationmode_group;
            $special_group_ids = $options->aedregistrationmode_group_ids;
            if ($special_group_ids)
            {
                $special_group_ids = explode(",", $special_group_ids);
            }
            else
            {
                $special_group_ids = [];
            }

            // $user['user_id'] && $visitor->getUserId(); are current empty at this stage

            // try fetch the cookie out of the session if it has been associated with the session before
            $session = XenForo_Application::getSession();
            if (empty($cookie))
            {
                $cookie = $session->get('aedOriginalUser');
                $this->_debug('inituser (in if): ' . $cookie);
            }

            $action = XenForo_Model_SpamPrevention::RESULT_ALLOWED;
            $oldlanguage_id = $this->aed_setLangauge($this->aed_getLangaugeForUser($aeduserid));
            $this->detect_methods = $this->detectAlterEgo($user, $cookie);
            if ($this->detect_methods)
            {
                $this->_debug('Potential Alter Ego Detected.');
                foreach ($this->detect_methods as $detect_method)
                {
                    $ae_action = $registration_mode;
                    if ($detect_method['suppress'])
                    {
                        continue;
                    }
                    $alter_ego_info = [
                        'detection_method' => $detect_method['method'],
                        'username'         => $detect_method['user']['username'],
                        'user_id'          => $detect_method['user']['user_id'],
                    ];

                    $is_banned = $detect_method['user']['is_banned'];
                    if ($is_banned)
                    {
                        $ae_action = $registration_mode_group;
                        $this->_debug('forcing ae action - ae is banned');
                        $this->aed_logScore('aed_detectspamreg_is_banned', 0, $alter_ego_info);
                    }
                    if ($registration_mode_group)
                    {
                        $groups = $detect_method['user']['secondary_group_ids'] ? explode(
                            ',', $detect_method['user']['secondary_group_ids']
                        ) : [];
                        $groups[] = $detect_method['user']['user_group_id'];
                        $intersect = array_intersect($groups, $special_group_ids);
                        if ($intersect)
                        {
                            $ae_action = $registration_mode_group;
                            $this->_debug('forcing ae action - group intersect');

                            $group_list = $this->_getHelper()->prepareField(
                                [
                                    'old_value' => '',
                                    'new_value' => join(',', $intersect),
                                    'field'     => 'secondary_group_ids',
                                ]
                            );

                            $alter_ego_info['groups'] = $group_list['new_value'];
                            $this->aed_logScore('aed_detectspamreg_group_membership', 0, $alter_ego_info);
                        }
                    }
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
            }
            $this->aed_setLangauge($oldlanguage_id);
            $this->_updateRegAction($result, $action);
            $this->_lastResult = $result;
        }
        catch (Exception $e)
        {
            // do not block login if any sort of error occurs
            XenForo_Error::logException($e, false);
        }

        return $result;
    }

    var $detect_methods = null;

    /**
     * @param XenForo_ControllerResponse_View $response
     * @param array                           $user
     * @param array                           $extraParams
     * @return XenForo_ControllerResponse_View
     */
    public function PostRegistrationAlterEgoDetection(XenForo_ControllerResponse_View $response, array $user, array $extraParams = [])
    {
        if (empty($this->detect_methods))
        {
            return $response;
        }
        $detect_methods = $this->detect_methods;
        $this->detect_methods = null;

        if (XenForo_Application::getOptions()->aed_ReportOnRegister)
        {
            $this->processAlterEgoDetection($user, $detect_methods, new XenForo_Phrase('aed_detectiontype_register'));
        }

        return $response;
    }

    /**
     * @param string|int $cookie
     * @return string|int
     */
    public function alterEgoCookieToUser($cookie)
    {
        return $cookie;
    }

    /**
     * @param string|int $userId
     * @return string|int
     */
    public function userToAlterEgoCookie($userId)
    {
        return $userId;
    }

    /**
     * @param XenForo_Session|null $session
     * @return array
     */
    protected function aed_getLoginAsUserIds(XenForo_Session $session = null)
    {
        $loginAsUserIds = [];
        if ($session)
        {
            // https://xenforo.com/community/resources/login-as-user.2493/
            if ($session->isRegistered('loginAsUser_originalId') && $session->get('loginAsUser_originalId'))
            {
                $loginAsUserIds[] = $session->get('loginAsUser_originalId');
            }
            // https://xenforo.com/community/resources/login-as-user-by-waindigo.1131/
            if ($session->isRegistered('loggedInAs') && $session->get('loggedInAs'))
            {
                $loginAsUserIds[] = $session->get('loggedInAs');
            }
        }

        return $loginAsUserIds;
    }

    /**
     * @param string $ip
     * @return array
     * @throws XenForo_Exception
     */
    protected function _getIpRecord($ip)
    {
        $results = XenForo_Helper_Ip::parseIpRangeString($ip);
        if (!$results)
        {
            throw new XenForo_Exception(new XenForo_Phrase('please_enter_valid_ip_or_ip_range'), true);
        }

        return [
            $results['printable'],
            $results['binary'][0],
            $results['startRange'],
            $results['endRange']
        ];
    }

    /**
     * @return bool
     */
    protected function aed_ipWhiteListed()
    {
        $this->_debug('Checking IP whitelist');
        $raw = XenForo_Application::getOptions()->aed_ip_whitelist;
        if (empty($raw))
        {
            return false;
        }
        $whitelistedIPs = array_filter(array_map('trim', explode(',', preg_replace('/\s+/s', ',', $raw))));
        if (empty($whitelistedIPs))
        {
            return false;
        }
        $this->_debug('ranges to check: ' . var_export($whitelistedIPs, true));
        $binaryIp = XenForo_Helper_Ip::getBinaryIp();
        foreach ($whitelistedIPs as $ip)
        {
            list($niceIp, $firstByte, $startRange, $endRange) = $this->_getIpRecord($ip);
            if (XenForo_Helper_Ip::ipMatchesRange($binaryIp, $startRange, $endRange))
            {
                $this->_debug('Whitelisted IP, matches:' . $niceIp);

                return true;
            }
        }
        $this->_debug('Not whitelisted');

        return false;
    }

    /**
     * @param string $ip
     * @param int    $timeLimit
     * @return array
     */
    public function _getUsersByIp($ip, $timeLimit)
    {
        if (!$ip)
        {
            return [];
        }

        $ip = XenForo_Helper_Ip::convertIpStringToBinary($ip);
        if (!$ip)
        {
            return [];
        }

        return $this->fetchAllKeyed(
            '
            SELECT user.*, a.ip, a.log_date, permission_combination.cache_value AS global_permission_cache
            FROM (
                SELECT user_id, ip, max(log_date) AS log_date
                FROM xf_ip AS ip
                WHERE ip.ip = ? AND log_date >= ?
                GROUP BY ip.user_id
            ) a
            INNER JOIN xf_user AS user ON (user.user_id = a.user_id)
            LEFT JOIN xf_permission_combination AS permission_combination ON (permission_combination.permission_combination_id = user.permission_combination_id)
            ORDER BY user.user_id
        ', 'user_id', [$ip, XenForo_Application::$time - $timeLimit * 60]
        );
    }


    /**
     * @param array  $currentUser
     * @param string $cookie
     * @return array
     */
    public function detectAlterEgo($currentUser, $cookie)
    {
        // Disable alter-ego checking if Login As User is detected.
        $session = XenForo_Application::isRegistered('session') ? XenForo_Application::getSession() : false;
        $loginAsUserIds = $this->aed_getLoginAsUserIds($session);
        if ($loginAsUserIds)
        {
            $this->_debug(
                'Detected Login-as-user. Disabling alter-ego checking. Original User IDs:' . var_export(
                    $loginAsUserIds, true
                )
            );

            return [];
        }

        $this->_debug('Detecting alter-egos');
        $detect_methods = [];
        $options = XenForo_Application::getOptions();
        $matching_mode = $options->aed_matching_mode;

        // $user['user_id'] && $visitor->getUserId(); may be empty at this stage
        $currentUserId = empty($currentUser['user_id'])
            ? 0
            : $currentUser['user_id'];
        $bypassChecks = empty($currentUser['permissions'])
            ? false
            : XenForo_Permission::hasPermission($currentUser['permissions'], 'general', 'aedbypass');

        $currentUserCookie = $this->userToAlterEgoCookie($currentUserId);
        $this->_debug('Resolving user_id:' . $currentUserId . ' to cookie:' . $currentUserCookie);

        // skip all alter-ego checks depending on options
        $checkBanned = $options->aedcheckbanned;
        if (!$checkBanned && !empty($currentUser['is_banned']))
        {
            $bypassChecks = true;
        }

        $userModel = $this->_getUserModel();
        $cookie_user_id = null;
        $this->_debug('Checking Cookie');
        if ($cookie && $cookie != $currentUserCookie)
        {
            $cookie_user_id = $this->alterEgoCookieToUser($cookie);
            $this->_debug('Resolving cookie:' . $cookie . ' to user_id:' . $cookie_user_id);
            // AE DETECTED
            $originalUser = $userModel->getUserById(
                $cookie_user_id, [
                                   'join' => XenForo_Model_User::FETCH_USER_PERMISSIONS
                               ]
            );
            if ($originalUser && isset($originalUser['user_id']))
            {
                $permissions = XenForo_Permission::unserializePermissions($originalUser['global_permission_cache']);
                $bypassCheck_cookie = XenForo_Permission::hasPermission($permissions, 'general', 'aedbypass');
                $detect_methods[] = [
                    'suppress' => $bypassChecks || (!$checkBanned && $originalUser['is_banned']) || $bypassCheck_cookie,
                    'method'   => new XenForo_Phrase(LiamW_AlterEgoDetector_Globals::DETECT_METHOD_COOKIE),
                    'user'     => $originalUser,
                ];
                $this->_debug('Cookie detection method triggered for: ' . $originalUser['username']);
            }
            else
            {
                // trigger setting a new cookie as the old account was deleted
                $cookie = null;
            }
        }

        $ipOption = $options->aedcheckips;
        if ($ipOption['checkIp'] && !$this->aed_ipWhiteListed())
        {
            $this->_debug('Checking IP');
            $users = $this->_getUsersByIp($_SERVER['REMOTE_ADDR'], $ipOption['minTime']);
            $ipPhrase = new XenForo_Phrase(
                LiamW_AlterEgoDetector_Globals::DETECT_METHOD_IP, ['ip' => $_SERVER['REMOTE_ADDR']]
            );
            $this->_debug(count($users) . ' users with IP ' . $_SERVER['REMOTE_ADDR'] . ', Checking for freshness...');
            foreach ($users as &$originalUser)
            {
                if ($currentUserId && $originalUser['user_id'] == $currentUserId)
                {
                    continue;
                }

                if ($matching_mode == 2 && $cookie_user_id != $originalUser['user_id'])
                {
                    continue;
                }

                $permissions = XenForo_Permission::unserializePermissions($originalUser['global_permission_cache']);
                $bypassCheck_ip = XenForo_Permission::hasPermission($permissions, 'general', 'aedbypass');
                $detect_methods[] = [
                    'suppress' => $bypassChecks || (!$checkBanned && $originalUser['is_banned']) || $bypassCheck_ip,
                    'method'   => $ipPhrase,
                    'user'     => $originalUser,
                ];
                $this->_debug('IP detection method triggered for: ' . $originalUser['username']);
            }
        }

        if ($currentUserCookie)
        {
            if (empty($cookie))
            {
                $this->_debug('first time cookie deployment');
                $this->setCookieValue($currentUserCookie, $options->aed_cookie_lifespan * 2592000);
            }
            else if ($options->aedredeploycookie && $cookie != $currentUserCookie)
            {
                $this->_debug('Redeploying cookie');
                $this->setCookieValue($currentUserCookie, $options->aed_cookie_lifespan * 2592000);
            }
        }

        // resolve any phrases
        foreach ($detect_methods as &$detect_method)
        {
            $detect_method['method'] = (string)$detect_method['method'];
        }

        if ($detect_methods &&
            $matching_mode == 1)
        {
            $detectionMethods = 1;
            if ($ipOption['checkIp'])
            {
                $detectionMethods += 1;
            }
            if ($detectionMethods > 1)
            {
                $uniqueMethods = [];
                foreach ($detect_methods as $detect_method)
                {
                    if ($detect_method['suppress'] || empty($detect_method['method']))
                    {
                        continue;
                    }
                    if (!isset($uniqueMethods[$detect_method['method']]))
                    {
                        $uniqueMethods[$detect_method['method']] = true;
                    }
                }
                if (count($uniqueMethods) != $detectionMethods)
                {
                    $this->_debug('AND matching method, skipping only match 1 reporting method');
                    $detect_methods = [];
                }
            }
        }

        return $detect_methods;
    }

    /**
     * @param array      $user
     * @param array|null $detection_methods
     * @param string     $ReportDetectionMethod
     * @param bool       $isSingle
     * @return string|XenForo_Phrase
     */
    public function buildUserDetectionReport(array $user, array $detection_methods = null, $ReportDetectionMethod, $isSingle)
    {
        if (empty($detection_methods))
        {
            return '';
        }

        $methods = '';
        foreach ($detection_methods as $detect_method)
        {
            $methods .= "- " . $detect_method['method'] . "\n";
        }

        if (empty($methods))
        {
            return '';
        }

        $phrase = $ReportDetectionMethod
            ? 'aed_thread_message_user_detection'
            : 'aed_thread_message_user';

        return new XenForo_Phrase(
            $phrase, [
            'username' => $user['username'],
            'userLink' => XenForo_Link::buildPublicLink('full:members', $user),
            'methods'  => $methods,
        ], false
        );
    }

    /**
     * @param array       $alterEgoUser
     * @param array       $users
     * @param string|null $detectionType
     * @return string|XenForo_Phrase
     */
    public function buildUserDetectionReportBody(array $alterEgoUser, array $users, $detectionType = null)
    {
        $ReportDetectionMethod = XenForo_Application::getOptions()->aedshowdetectionmethods;

        // build the message body
        $isSingle = count($users) == 1;
        if ($isSingle)
        {
            $otherUser = reset($users);
            $message = new XenForo_Phrase(
                'aed_thread_message_single', [
                'username1'     => $alterEgoUser['username'],
                'userLink1'     => XenForo_Link::buildPublicLink('full:members', $alterEgoUser),
                'username2'     => $otherUser['username'],
                'userLink2'     => XenForo_Link::buildPublicLink('full:members', $otherUser),
                'detectionType' => $detectionType,
            ], false
            );
        }
        else
        {
            $message = new XenForo_Phrase(
                'aed_thread_message', [
                'username'      => $alterEgoUser['username'],
                'userLink'      => XenForo_Link::buildPublicLink('full:members', $alterEgoUser),
                'detectionType' => $detectionType,
            ], false
            );
        }
        $message .= "\n\n";
        foreach ($users as $user)
        {
            $detection_methods = [];
            if (isset($user['detection_methods']))
            {
                $detection_methods = $user['detection_methods'];
            }
            if (empty($detection_methods) && isset($alterEgoUser['detection_methods']))
            {
                $detection_methods = $alterEgoUser['detection_methods'];
            }
            $message .= $this->buildUserDetectionReport($user, $detection_methods, $ReportDetectionMethod, $isSingle);
        }

        return $message;
    }

    /**
     * @param array $alterEgoUser
     * @param array $detect_methods
     * @param null  $detectionType
     * @throws Exception
     */
    public function processAlterEgoDetection($alterEgoUser, array $detect_methods, $detectionType = null)
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
        // assume login
        if ($detectionType === null)
        {
            $detectionType = new XenForo_Phrase('aed_detectiontype_login');
        }

        unset($alterEgoUser['permissions']);
        unset($alterEgoUser['global_permission_cache']);
        $reportedUser = $alterEgoUser;
        $reportedUserId = $reportedUser['user_id'];
        $users = [];
        // ensure consistent ordering by picking a user as 'first'
        foreach ($detect_methods as $detect_method)
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

            $arr = [];
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
            XenForo_Error::logException(
                new Exception("Alter Ego Detector - UserId not set. Aborting reporting alter egos"), false
            );

            return;
        }
        if (empty($username))
        {
            $username = $this->_getDb()->fetchOne(
                '
                SELECT username
                FROM xf_user
                WHERE user_id = ?
            ', $userId
            );
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
                $title = new XenForo_Phrase(
                    'aed_thread_subject', [
                    'username1'     => $originalUsername,
                    'username2'     => $alterEgoUsername,
                    'detectionType' => $detectionType,
                ], false
                );
            }
            else
            {
                $title = new XenForo_Phrase(
                    'aed_thread_subject_count', [
                    'username'      => $reportedUser['username'],
                    'count'         => $AE_count,
                    'detectionType' => $detectionType,
                ], false
                );
            }

            $message = $this->buildUserDetectionReportBody($alterEgoUser, $users, $detectionType);

            if ($options->aedcreatethread)
            {
                try
                {
                    $forumId = $options->aedforumid;

                    $forum = $this->_getForumModel()->getForumById($forumId);
                    if (empty($forumId) || empty($userId) || empty($username) || empty($forum))
                    {
                        throw new Exception(
                            "Alter Ego Detector - Create Thread is not properly configured when reporting $alterEgoUsername is an alter ego of $originalUsername"
                        );
                    }
                    $default_prefix_id = $forum['default_prefix_id'];

                    $this->_debug('Initialised Thread DataWriter');
                    /* @var $threadDw XenForo_DataWriter_Discussion_Thread */
                    $threadDw = XenForo_DataWriter::create('XenForo_DataWriter_Discussion_Thread');
                    $threadDw->bulkSet(
                        [
                            'user_id'   => $userId,
                            'node_id'   => $forumId,
                            'title'     => $title,
                            'username'  => $username,
                            'prefix_id' => $default_prefix_id,
                        ]
                    );

                    $firstPostDw = $threadDw->getFirstMessageDw();
                    $firstPostDw->setOption(XenForo_DataWriter_DiscussionMessage::OPTION_IS_AUTOMATED, true);
                    $firstPostDw->set('message', $message);

                    $this->_debug('Line before thread datawriter save');
                    $threadDw->save();
                    $this->_debug('Thread datawriter saved');
                }
                catch (\Exception $e)
                {
                    XenForo_Error::logException($e, false);
                }
            }

            if ($options->aedsendpm)
            {
                try
                {
                    $conversationRecipientsOption = str_replace(
                        [
                            "\r",
                            "\r\n"
                        ], "\n", $options->aedpmrecipients
                    );
                    $conversationRecipients = array_filter(explode("\n", $conversationRecipientsOption));

                    $starterArray = $userModel->getFullUserById(
                        $userId, [
                                   'join' => XenForo_Model_User::FETCH_USER_FULL | XenForo_Model_User::FETCH_USER_PERMISSIONS
                               ]
                    );
                    if (empty($starterArray) || empty($username) || empty($conversationRecipients))
                    {
                        throw new Exception(
                            "Alter Ego Detector - Start PM is not properly configured when reporting $alterEgoUsername is an alter ego of $originalUsername"
                        );
                    }
                    $starterArray['permissions'] = XenForo_Permission::unserializePermissions(
                        $starterArray['global_permission_cache']
                    );


                    /* @var $conversationDw XenForo_DataWriter_ConversationMaster */
                    $this->_debug('Conversation datawriter initialised.');
                    $conversationDw = XenForo_DataWriter::create('XenForo_DataWriter_ConversationMaster');
                    $conversationDw->setExtraData(
                        XenForo_DataWriter_ConversationMaster::DATA_ACTION_USER, $starterArray
                    );
                    $conversationDw->set('user_id', $userId);
                    $conversationDw->set('username', $username);
                    $conversationDw->set('title', $title);
                    $conversationDw->set('open_invite', 1);
                    $conversationDw->set('conversation_open', 1);
                    $conversationDw->addRecipientUserNames($conversationRecipients);

                    $firstMessageDw = $conversationDw->getFirstMessageDw();
                    $firstMessageDw->setOption(XenForo_DataWriter_ConversationMessage::OPTION_SET_IP_ADDRESS, false);
                    $firstMessageDw->set('message', $message);

                    $this->_debug('Line before conversation save');
                    $conversationDw->save();
                    $this->_debug('Line after conversation save');
                }
                catch (\Exception $e)
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
                        throw new Exception(
                            "Alter Ego Detector - Start Report is not properly configured when reporting $alterEgoUsername is an alter ego of $originalUsername"
                        );
                    }

                    /* @var $reportModel XenForo_Model_Report */
                    $reportModel = XenForo_Model::create('XenForo_Model_Report');

                    $users[$reportedUser['user_id']] = $reportedUser;
                    $users[$alterEgoUser['user_id']] = $alterEgoUser;
                    $userIds = array_keys($users);
                    $reportContent = [];
                    $reportContent[] = $reportedUser;
                    foreach ($users as $user)
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
                    $newAlterEgos = [];
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
                        foreach ($content_info['0'] as $key => $user)
                        {
                            $_userid = $user['user_id'];
                            if (empty($users[$_userid]))
                            {
                                continue;
                            }
                            $this->_debug(
                                'updating alter ego report content for ' . $_userid . '- ' . $users[$_userid]['username']
                            );
                            $content_info['0'][$key] = $users[$_userid];
                        }

                        // determine if there are any new users to add
                        $userIdsReported = XenForo_Application::arrayColumn($content_info['0'], 'user_id');
                        $userIds = array_diff($userIds, $userIdsReported);
                        $forceReport = false;
                        if ($userIds)
                        {
                            foreach ($userIds as $_userid)
                            {
                                if (empty($users[$_userid]))
                                {
                                    $this->_debug('Can not find ' . $_userid);
                                    continue;
                                }
                                $this->_debug(
                                    'Adding alter ego report content for ' . $_userid . '- ' . $users[$_userid]['username']
                                );
                                $content_info['0'][] = $users[$_userid];
                                $forceReport = true;
                            }
                            $reportContent = $content_info['0'];
                        }
                        $sendDuplicate = $options->aedreport_senddupe;

                        if ($forceReport || isset($sendDuplicate[$report['report_state']]))
                        {
                            $content_info[0][0]['detectionType'] = (string)$detectionType;
                            $makeReport = $forceReport || $sendDuplicate[$report['report_state']];
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
                        $reportContent[0]['detectionType'] = (string)$detectionType;
                        $this->_debug(
                            'Make report: ' . $makeReport . ' for ' . $originalUsername . ' to report AE: ' . $alterEgoUsername
                        );
                        $message = XenForo_Helper_String::bbCodeStrip($message);
                        $reportModel->reportContent(
                            'alterego', $reportContent, $message, $userModel->getFullUserById($userId)
                        );
                    }
                    else
                    {
                        $this->_debug('Suppressing duplicate report.');
                    }
                }
                catch (\Exception $e)
                {
                    XenForo_Error::logException($e, false);
                }
            }
        }
        catch (\Exception $e)
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
     * @param string|boolean $value The cookie false. False to remove cookie.
     * @param int            $time  int How long the cookie is valid for, in seconds.
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

    /**
     * @return XenForo_Model_Forum|XenForo_Model
     */
    protected function _getForumModel()
    {
        return $this->getModelFromCache('XenForo_Model_Forum');
    }

    /**
     * @return XenForo_Model_User|XenForo_Model
     */
    protected function _getUserModel()
    {
        return $this->getModelFromCache('XenForo_Model_User');
    }

    protected function _debug($message)
    {
        if (XenForo_Application::getOptions()->aeddebugmessages)
        {
            XenForo_Error::logException(new Exception($message), false);
        }
    }

    /**
     * @return XenForo_Helper_UserChangeLog
     */
    protected function _getHelper()
    {
        return $this->getModelFromCache('XenForo_Helper_UserChangeLog');
    }
}
