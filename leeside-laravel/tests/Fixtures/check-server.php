<?php

// Test helper: single-shot check-protocol responder.
// Usage: php check-server.php <socket path> <mode> [arg]
// Modes: verdict <json> | badjson | close | slow <ms>

[$script, $path, $mode, $arg] = $argv + [null, null, 'verdict', '{}'];

@unlink($path);
$server = stream_socket_server('unix://'.$path, $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "bind failed: $errstr\n");
    exit(1);
}

$client = @stream_socket_accept($server, 10);
if ($client === false) {
    exit(2);
}

fgets($client);

switch ($mode) {
    case 'slow':
        usleep(max((int) $arg, 0) * 1000);
        @fwrite($client, "{\"action\":\"block\",\"mode\":\"enforce\"}\n");
        break;
    case 'badjson':
        fwrite($client, "not json\n");
        break;
    case 'close':
        break;
    default:
        fwrite($client, rtrim($arg)."\n");
        break;
}

fclose($client);
fclose($server);
