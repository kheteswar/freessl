<?php
/**
 * FreeSSL Analytics Viewer
 * Simple analytics dashboard for tracking page visits and certificate orders
 * 
 * SECURITY: Password protect this file in production!
 */

// Simple password protection (CHANGE THIS PASSWORD!)
$ANALYTICS_PASSWORD = 'your_secure_password_here';

// Check authentication
session_start();
$authenticated = isset($_SESSION['analytics_auth']) && $_SESSION['analytics_auth'] === true;

if (isset($_POST['password'])) {
    if ($_POST['password'] === $ANALYTICS_PASSWORD) {
        $_SESSION['analytics_auth'] = true;
        $authenticated = true;
    } else {
        $error = "Invalid password";
    }
}

if (isset($_GET['logout'])) {
    unset($_SESSION['analytics_auth']);
    header('Location: analytics.php');
    exit;
}

// Load analytics functions
define('ANALYTICS_DIR', __DIR__ . '/analytics');
define('VISITS_FILE', ANALYTICS_DIR . '/visits.txt');
define('ORDERS_FILE', ANALYTICS_DIR . '/orders.txt');

function getDetailedStats() {
    $stats = [
        'total_visits' => 0,
        'total_orders' => 0,
        'production_orders' => 0,
        'staging_orders' => 0,
        'last_visit' => null,
        'last_order' => null,
        'recent_visits' => [],
        'recent_orders' => [],
        'conversion_rate' => 0
    ];
    
    // Get visits
    if (file_exists(VISITS_FILE)) {
        $content = file_get_contents(VISITS_FILE);
        $lines = array_filter(explode("\n", $content));
        
        if (!empty($lines)) {
            $lastLine = end($lines);
            list($time, $count) = explode('|', $lastLine);
            $stats['total_visits'] = intval($count);
            $stats['last_visit'] = date('Y-m-d H:i:s', $time);
            
            // Get last 10 visits
            $recentLines = array_slice($lines, -10);
            foreach ($recentLines as $line) {
                list($time, $count) = explode('|', $line);
                $stats['recent_visits'][] = [
                    'time' => date('Y-m-d H:i:s', $time),
                    'count' => $count
                ];
            }
        }
    }
    
    // Get orders
    if (file_exists(ORDERS_FILE)) {
        $content = file_get_contents(ORDERS_FILE);
        $lines = array_filter(explode("\n", $content));
        
        if (!empty($lines)) {
            $productionCount = 0;
            $stagingCount = 0;
            
            foreach ($lines as $line) {
                $parts = explode('|', $line);
                if (count($parts) >= 3) {
                    if ($parts[2] == 0) {
                        $productionCount++;
                    } else {
                        $stagingCount++;
                    }
                }
            }
            
            $lastLine = end($lines);
            $parts = explode('|', $lastLine);
            $stats['total_orders'] = intval($parts[1]);
            $stats['production_orders'] = $productionCount;
            $stats['staging_orders'] = $stagingCount;
            $stats['last_order'] = date('Y-m-d H:i:s', $parts[0]);
            
            // Get last 10 orders
            $recentLines = array_slice($lines, -10);
            foreach ($recentLines as $line) {
                $parts = explode('|', $line);
                if (count($parts) >= 3) {
                    $stats['recent_orders'][] = [
                        'time' => date('Y-m-d H:i:s', $parts[0]),
                        'count' => $parts[1],
                        'type' => $parts[2] == 0 ? 'Production' : 'Staging'
                    ];
                }
            }
        }
    }
    
    // Calculate conversion rate
    if ($stats['total_visits'] > 0) {
        $stats['conversion_rate'] = round(($stats['total_orders'] / $stats['total_visits']) * 100, 2);
    }
    
    return $stats;
}

if (!$authenticated) {
    // Show login form
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FreeSSL Analytics - Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-100 min-h-screen flex items-center justify-center">
        <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
            <h1 class="text-2xl font-bold text-gray-900 mb-6">FreeSSL Analytics</h1>
            <?php if (isset($error)): ?>
                <div class="bg-red-50 text-red-800 p-3 rounded mb-4">
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            <form method="POST">
                <div class="mb-4">
                    <label class="block text-gray-700 font-semibold mb-2">Password:</label>
                    <input type="password" name="password" class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
                </div>
                <button type="submit" class="w-full bg-indigo-600 text-white py-2 rounded font-semibold hover:bg-indigo-700">
                    Login
                </button>
            </form>
            <p class="text-sm text-gray-600 mt-4">
                <strong>Security Note:</strong> Change the password in analytics.php!
            </p>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Get stats
$stats = getDetailedStats();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FreeSSL Analytics Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <!-- Header -->
        <div class="flex justify-between items-center mb-8">
            <div>
                <h1 class="text-3xl font-bold text-gray-900">FreeSSL Analytics</h1>
                <p class="text-gray-600">Real-time statistics and insights</p>
            </div>
            <div class="flex items-center space-x-4">
                <button onclick="location.reload()" class="bg-gray-200 text-gray-700 px-4 py-2 rounded hover:bg-gray-300">
                    <i class="fas fa-sync-alt mr-2"></i>Refresh
                </button>
                <a href="?logout" class="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600">
                    <i class="fas fa-sign-out-alt mr-2"></i>Logout
                </a>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Total Visits -->
            <div class="bg-white p-6 rounded-lg shadow">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-600 text-sm font-semibold uppercase">Total Visits</p>
                        <p class="text-3xl font-bold text-gray-900 mt-2"><?php echo number_format($stats['total_visits']); ?></p>
                        <?php if ($stats['last_visit']): ?>
                            <p class="text-xs text-gray-500 mt-1">Last: <?php echo $stats['last_visit']; ?></p>
                        <?php endif; ?>
                    </div>
                    <div class="bg-blue-100 p-3 rounded-full">
                        <i class="fas fa-eye text-blue-600 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Total Orders -->
            <div class="bg-white p-6 rounded-lg shadow">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-600 text-sm font-semibold uppercase">Total Orders</p>
                        <p class="text-3xl font-bold text-gray-900 mt-2"><?php echo number_format($stats['total_orders']); ?></p>
                        <?php if ($stats['last_order']): ?>
                            <p class="text-xs text-gray-500 mt-1">Last: <?php echo $stats['last_order']; ?></p>
                        <?php endif; ?>
                    </div>
                    <div class="bg-green-100 p-3 rounded-full">
                        <i class="fas fa-certificate text-green-600 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Production Orders -->
            <div class="bg-white p-6 rounded-lg shadow">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-600 text-sm font-semibold uppercase">Production</p>
                        <p class="text-3xl font-bold text-gray-900 mt-2"><?php echo number_format($stats['production_orders']); ?></p>
                        <p class="text-xs text-gray-500 mt-1">Real certificates</p>
                    </div>
                    <div class="bg-indigo-100 p-3 rounded-full">
                        <i class="fas fa-star text-indigo-600 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Conversion Rate -->
            <div class="bg-white p-6 rounded-lg shadow">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-600 text-sm font-semibold uppercase">Conversion Rate</p>
                        <p class="text-3xl font-bold text-gray-900 mt-2"><?php echo $stats['conversion_rate']; ?>%</p>
                        <p class="text-xs text-gray-500 mt-1">Orders / Visits</p>
                    </div>
                    <div class="bg-purple-100 p-3 rounded-full">
                        <i class="fas fa-chart-line text-purple-600 text-2xl"></i>
                    </div>
                </div>
            </div>
        </div>

        <!-- Breakdown Row -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <!-- Order Type Breakdown -->
            <div class="bg-white p-6 rounded-lg shadow">
                <h2 class="text-xl font-bold text-gray-900 mb-4">
                    <i class="fas fa-chart-pie text-indigo-600 mr-2"></i>
                    Order Type Breakdown
                </h2>
                <div class="space-y-4">
                    <div>
                        <div class="flex justify-between items-center mb-2">
                            <span class="text-gray-700 font-semibold">Production Certificates</span>
                            <span class="text-gray-900 font-bold"><?php echo $stats['production_orders']; ?></span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-3">
                            <?php 
                            $prodPercent = $stats['total_orders'] > 0 ? ($stats['production_orders'] / $stats['total_orders']) * 100 : 0;
                            ?>
                            <div class="bg-indigo-600 h-3 rounded-full" style="width: <?php echo $prodPercent; ?>%"></div>
                        </div>
                        <p class="text-sm text-gray-500 mt-1"><?php echo round($prodPercent, 1); ?>% of total</p>
                    </div>
                    <div>
                        <div class="flex justify-between items-center mb-2">
                            <span class="text-gray-700 font-semibold">Staging/Test Certificates</span>
                            <span class="text-gray-900 font-bold"><?php echo $stats['staging_orders']; ?></span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-3">
                            <?php 
                            $stagingPercent = $stats['total_orders'] > 0 ? ($stats['staging_orders'] / $stats['total_orders']) * 100 : 0;
                            ?>
                            <div class="bg-yellow-500 h-3 rounded-full" style="width: <?php echo $stagingPercent; ?>%"></div>
                        </div>
                        <p class="text-sm text-gray-500 mt-1"><?php echo round($stagingPercent, 1); ?>% of total</p>
                    </div>
                </div>
            </div>

            <!-- Quick Stats -->
            <div class="bg-white p-6 rounded-lg shadow">
                <h2 class="text-xl font-bold text-gray-900 mb-4">
                    <i class="fas fa-info-circle text-blue-600 mr-2"></i>
                    Quick Statistics
                </h2>
                <div class="space-y-3">
                    <div class="flex justify-between items-center border-b border-gray-200 pb-2">
                        <span class="text-gray-600">Total Page Views:</span>
                        <span class="font-bold text-gray-900"><?php echo number_format($stats['total_visits']); ?></span>
                    </div>
                    <div class="flex justify-between items-center border-b border-gray-200 pb-2">
                        <span class="text-gray-600">Total Certificate Orders:</span>
                        <span class="font-bold text-gray-900"><?php echo number_format($stats['total_orders']); ?></span>
                    </div>
                    <div class="flex justify-between items-center border-b border-gray-200 pb-2">
                        <span class="text-gray-600">Conversion Rate:</span>
                        <span class="font-bold text-gray-900"><?php echo $stats['conversion_rate']; ?>%</span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span class="text-gray-600">Production vs Staging:</span>
                        <span class="font-bold text-gray-900">
                            <?php echo $stats['production_orders']; ?> / <?php echo $stats['staging_orders']; ?>
                        </span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Activity Tables -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Recent Visits -->
            <div class="bg-white p-6 rounded-lg shadow">
                <h2 class="text-xl font-bold text-gray-900 mb-4">
                    <i class="fas fa-history text-blue-600 mr-2"></i>
                    Recent Visits (Last 10)
                </h2>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-2 text-left text-xs font-semibold text-gray-600 uppercase">Time</th>
                                <th class="px-4 py-2 text-right text-xs font-semibold text-gray-600 uppercase">Count</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            <?php foreach (array_reverse($stats['recent_visits']) as $visit): ?>
                            <tr class="hover:bg-gray-50">
                                <td class="px-4 py-3 text-sm text-gray-700"><?php echo $visit['time']; ?></td>
                                <td class="px-4 py-3 text-sm text-gray-900 font-semibold text-right"><?php echo $visit['count']; ?></td>
                            </tr>
                            <?php endforeach; ?>
                            <?php if (empty($stats['recent_visits'])): ?>
                            <tr>
                                <td colspan="2" class="px-4 py-8 text-center text-gray-500">No visits recorded yet</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Recent Orders -->
            <div class="bg-white p-6 rounded-lg shadow">
                <h2 class="text-xl font-bold text-gray-900 mb-4">
                    <i class="fas fa-certificate text-green-600 mr-2"></i>
                    Recent Orders (Last 10)
                </h2>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-2 text-left text-xs font-semibold text-gray-600 uppercase">Time</th>
                                <th class="px-4 py-2 text-center text-xs font-semibold text-gray-600 uppercase">Type</th>
                                <th class="px-4 py-2 text-right text-xs font-semibold text-gray-600 uppercase">Count</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            <?php foreach (array_reverse($stats['recent_orders']) as $order): ?>
                            <tr class="hover:bg-gray-50">
                                <td class="px-4 py-3 text-sm text-gray-700"><?php echo $order['time']; ?></td>
                                <td class="px-4 py-3 text-center">
                                    <?php if ($order['type'] === 'Production'): ?>
                                        <span class="inline-block bg-indigo-100 text-indigo-800 text-xs px-2 py-1 rounded font-semibold">Production</span>
                                    <?php else: ?>
                                        <span class="inline-block bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded font-semibold">Staging</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900 font-semibold text-right"><?php echo $order['count']; ?></td>
                            </tr>
                            <?php endforeach; ?>
                            <?php if (empty($stats['recent_orders'])): ?>
                            <tr>
                                <td colspan="3" class="px-4 py-8 text-center text-gray-500">No orders recorded yet</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Footer Info -->
        <div class="mt-8 bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h3 class="font-bold text-blue-900 mb-2">
                <i class="fas fa-info-circle mr-2"></i>
                About This Analytics
            </h3>
            <ul class="text-sm text-blue-800 space-y-1">
                <li><i class="fas fa-check mr-2"></i>Data stored in simple flat files (analytics/visits.txt and analytics/orders.txt)</li>
                <li><i class="fas fa-check mr-2"></i>Lightweight and fast - no database required</li>
                <li><i class="fas fa-check mr-2"></i>Page visits tracked automatically on each page load</li>
                <li><i class="fas fa-check mr-2"></i>Certificate orders tracked when user creates order (Step 2)</li>
                <li><i class="fas fa-shield-alt mr-2"></i><strong>Security:</strong> Change the password in analytics.php file!</li>
            </ul>
        </div>
    </div>

    <script>
        // Auto-refresh every 60 seconds
        setTimeout(function() {
            location.reload();
        }, 60000);
    </script>
</body>
</html>
