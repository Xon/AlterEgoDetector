<?php

class LiamW_AlterEgoDetector_Installer
{
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
}
