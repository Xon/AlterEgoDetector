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
abstract class LiamW_AlterEgoDetector_Addon
{
    const AddonNameSpace = 'LiamW_AlterEgoDetector';

    public static function install($installedAddon)
    {
        if (XenForo_Application::$versionId < 1030070)
        {
            throw new XenForo_Exception("Please upgrade XenForo. 1.3+ is required.", true);
        }

        $versionId = is_array($installedAddon) ? $installedAddon['version_id'] : 0;

        $db = XenForo_Application::getDb();

        $db->query("
            INSERT IGNORE INTO xf_content_type
                (content_type, addon_id, fields)
            VALUES
                ('alterego', 'liam_ae_detector', '')
        ");

        $db->query("
            INSERT IGNORE INTO xf_content_type_field
                (content_type, field_name, field_value)
            VALUES
                ('alterego', 'report_handler_class', 'LiamW_AlterEgoDetector_ReportHandler_AlterEgo')
        ");

        if ($versionId <= 10405)
        {
            // make sure the model is loaded before accessing the static properties
            XenForo_Model::create("XenForo_Model_User");
            $db->query("insert ignore into xf_permission_entry (user_group_id, user_id, permission_group_id, permission_id, permission_value, permission_value_int) values
                (?, 0, 'general', 'aedviewreport', 'allow', '0'),
                (?, 0, 'general', 'aedviewreport', 'allow', '0')
            ", array(XenForo_Model_User::$defaultModeratorGroupId, XenForo_Model_User::$defaultAdminGroupId));
        }

        XenForo_Model::create('XenForo_Model_ContentType')->rebuildContentTypeCache();
    }

    public static function uninstall()
    {
        $db = XenForo_Application::getDb();

        $db->query("
            DELETE FROM xf_content_type
            WHERE xf_content_type.addon_id = 'liam_ae_detector'
        ");

        $db->query("
            DELETE FROM xf_content_type_field
            WHERE xf_content_type_field.field_value = 'LiamW_AlterEgoDetector_ReportHandler_AlterEgo'
        ");

        $db->delete('xf_permission_entry', "permission_id = 'aedbypass'");
        $db->delete('xf_permission_entry', "permission_id = 'aedviewreport'");

        // update cache
        XenForo_Model::create('XenForo_Model_ContentType')->rebuildContentTypeCache();
    }

    public static function extendClass($class, array &$extend)
    {
        $extend[] = self::AddonNameSpace . '_' . $class;
    }

    // This is a stub to allow the upgrade to go smoothly
    public static function initDependencies(XenForo_Dependencies_Abstract $dependencies, array $data){}
    public static function extendLoginController($class, array &$extend){}
    public static function extendRegisterController($class, array &$extend){}
    public static function extendUserDataWriter($class, array &$extend){}
}
