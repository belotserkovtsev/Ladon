#!/usr/local/bin/php
<?php

// Ensure the three Ladon pf tables are declared as External (advanced) firewall
// aliases, so OPNsense persists them and operators can reference them in rules.
// Idempotent: only creates what's missing, never touches operator edits.

require_once('legacy_bindings.inc');

use OPNsense\Core\Config;
use OPNsense\Core\Backend;
use OPNsense\Firewall\Alias;

$wanted = [
    'ladon_engine' => 'Ladon: probe-discovered blocks (engine-managed)',
    'ladon_manual' => 'Ladon: manual allow-list + extensions',
    'ladon_cidr'   => 'Ladon: CIDR blocks from extensions',
];

Config::getInstance()->lock();
$changed = false;
try {
    $mdl = new Alias();
    foreach ($wanted as $name => $descr) {
        if ($mdl->getByName($name, true) !== null) {
            continue; // already declared — leave it alone
        }
        $node = $mdl->aliases->alias->Add();
        $node->enabled = '1';
        $node->name = $name;
        $node->type = 'external'; // daemon-populated; content stays empty
        $node->proto = '';
        $node->description = $descr;
        $changed = true;
    }
    if ($changed) {
        $errors = [];
        foreach ($mdl->performValidation() as $msg) {
            $errors[] = $msg->getField() . ': ' . $msg->getMessage();
        }
        if (!empty($errors)) {
            Config::getInstance()->unlock();
            fwrite(STDERR, "ladon: alias validation failed:\n" . implode("\n", $errors) . "\n");
            exit(1);
        }
        $mdl->serializeToConfig(false, true);
        Config::getInstance()->save();
    }
} catch (\Throwable $e) {
    Config::getInstance()->unlock();
    fwrite(STDERR, "ladon: ensure_aliases error: " . $e->getMessage() . "\n");
    exit(1);
}
Config::getInstance()->unlock();

if ($changed) {
    $be = new Backend();
    $be->configdRun('template reload OPNsense/Filter');
    $be->configdRun('filter reload skip_alias');
    $be->configdRun('filter refresh_aliases');
    echo "ladon: created firewall aliases\n";
} else {
    echo "ladon: firewall aliases already present\n";
}
