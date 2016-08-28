<?php

class LiamW_AlterEgoDetector_XenForo_Model_UserConfirmation extends XFCP_LiamW_AlterEgoDetector_XenForo_Model_UserConfirmation
{
    public function processUserModeration(array $user, $action, $notify = true, $rejectionReason = '')
    {
        if ($user['user_state'] != 'moderated')
        {
            return false;
        }

        if ($action == 'aed_email_confirm')
        {
            $dw = XenForo_DataWriter::create('XenForo_DataWriter_User');
            $dw->setExistingData($user);
            $dw->set('user_state', 'email_confirm');
            $dw->save();

            $this->sendEmailConfirmation($dw->getMergedData());

            return true;
        }

        return parent::processUserModeration($user, $action, $notify, $rejectionReason);
    }
}
