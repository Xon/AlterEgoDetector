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
class LiamW_AlterEgoDetector_ReportHandler_AlterEgo extends XenForo_ReportHandler_Abstract
{

    public function getReportDetailsFromContent(array $content)
    {
        $user_id1 = isset($content[0]['user_id']) ? $content[0]['user_id'] : 0;
        //$user_id2 = isset($content[1]['user_id']) ? $content[1]['user_id'] : 0;

        return array(
            $user_id1,
            $user_id1,
            array(
                $content
            )
        );
    }

    public function getVisibleReportsForUser(array $reports, array $viewingUser)
    {
        foreach ($reports AS $reportId => $report)
        {
            if (!XenForo_Permission::hasPermission($viewingUser['permissions'], 'general', 'aedviewreport'))
            {
                unset($reports[$reportId]);
            }
        }

        return $reports;
    }

    public function getContentLink(array $report, array $contentInfo)
    {
        return null;
    }

    public function getContentTitle(array $report, array $contentInfo)
    {
        $AE_count = count($report['extraContent'][0]) - 1;
        $username1 = @$report['extraContent'][0][0]['username'];
        if ($AE_count <= 1)
        {
            $username2 = @$report['extraContent'][0][1]['username'];
            return new XenForo_Phrase('aed_thread_subject', array(
                'username1' => $username1,
                'username2' => $username2,
            ));
        }
        else
            return new XenForo_Phrase('aed_thread_subject_count', array(
                'username' => $username1,
                'count' => $AE_count,
            ));
    }

}