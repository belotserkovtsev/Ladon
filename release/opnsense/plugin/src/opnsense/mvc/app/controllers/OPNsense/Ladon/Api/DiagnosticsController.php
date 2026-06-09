<?php

namespace OPNsense\Ladon\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class DiagnosticsController extends ApiControllerBase
{
    public function doctorAction()
    {
        return ['response' => json_decode((new Backend())->configdRun('ladon doctor'))];
    }

    public function hotAction()
    {
        return ['response' => json_decode((new Backend())->configdRun('ladon hot'))];
    }

    public function recentAction()
    {
        return ['response' => json_decode((new Backend())->configdRun('ladon recent'))];
    }

    public function whyAction()
    {
        $domain = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$this->request->get('domain', null, ''));
        if ($domain === '') {
            return ['response' => ''];
        }
        // configd escapes '>' etc. in captured output; undo it for the <pre> view.
        return ['response' => html_entity_decode((new Backend())->configdpRun('ladon why', [$domain]))];
    }
}
