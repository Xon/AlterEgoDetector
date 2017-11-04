<?php

class LiamW_AlterEgoDetector_Option_Recipients
{
    public static function verifyOption(&$option, XenForo_DataWriter $dw, $fieldName)
    {
        $conversationRecipientsOption = str_replace(
            [
                "\r",
                "\r\n"
            ], "\n", $option
        );
        $usernames = array_filter(explode("\n", $conversationRecipientsOption));
        /** @var XenForo_Model_User $userModel */
        $userModel = XenForo_Model::create("XenForo_Model_User");
        $users = $userModel->getUsersByNames($usernames, [], $notFound);

        if (empty($notFound))
        {
            $usernames = XenForo_Application::arrayColumn($users, 'username');
            $option = implode("\n", $usernames);

            return true;
        }


        $dw->error(
            new XenForo_Phrase('the_following_recipients_could_not_be_found_x', ['names' => implode(', ', $notFound)]),
            $fieldName
        );

        return false;
    }
}
