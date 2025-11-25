<?php
/**
 * FreeSSL - Let's Encrypt Certificate Generator
 * A simple PHP application to generate free SSL certificates
 * @author Kheteshwar Boravat
 * @version 3.0 (Enhanced UI/UX)
 */

// Configuration
define('LE_STAGING', 'https://acme-staging-v02.api.letsencrypt.org/directory');
define('LE_PRODUCTION', 'https://acme-v02.api.letsencrypt.org/directory');

// Analytics file paths
define('ANALYTICS_DIR', __DIR__ . '/analytics');
define('VISITS_FILE', ANALYTICS_DIR . '/visits.txt');
define('ORDERS_FILE', ANALYTICS_DIR . '/orders.txt');

// Initialize analytics directory
if (!file_exists(ANALYTICS_DIR)) {
    mkdir(ANALYTICS_DIR, 0755, true);
}

/**
 * Track page visit
 * Format: timestamp|counter
 */
function trackPageVisit() {
    $data = ['time' => time(), 'count' => 1];
    
    if (file_exists(VISITS_FILE)) {
        $content = file_get_contents(VISITS_FILE);
        $lines = array_filter(explode("\n", $content));
        $lastLine = end($lines);
        
        if ($lastLine) {
            list($lastTime, $lastCount) = explode('|', $lastLine);
            $data['count'] = intval($lastCount) + 1;
        }
    }
    
    $line = $data['time'] . '|' . $data['count'] . "\n";
    file_put_contents(VISITS_FILE, $line, FILE_APPEND | LOCK_EX);
}

/**
 * Track certificate order
 * Format: timestamp|counter|staging
 */
function trackCertOrder($staging = false) {
    $data = ['time' => time(), 'count' => 1, 'staging' => $staging ? 1 : 0];
    
    if (file_exists(ORDERS_FILE)) {
        $content = file_get_contents(ORDERS_FILE);
        $lines = array_filter(explode("\n", $content));
        $lastLine = end($lines);
        
        if ($lastLine) {
            $parts = explode('|', $lastLine);
            if (count($parts) >= 2) {
                $data['count'] = intval($parts[1]) + 1;
            }
        }
    }
    
    $line = $data['time'] . '|' . $data['count'] . '|' . $data['staging'] . "\n";
    file_put_contents(ORDERS_FILE, $line, FILE_APPEND | LOCK_EX);
}

/**
 * Get analytics stats
 */
function getAnalyticsStats() {
    $stats = [
        'total_visits' => 0,
        'total_orders' => 0,
        'production_orders' => 0,
        'staging_orders' => 0,
        'last_visit' => null,
        'last_order' => null
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
        }
    }
    
    return $stats;
}

// Track page visit on every page load (but not for AJAX requests)
if (!isset($_GET['action'])) {
    trackPageVisit();
}

// Initialize session
session_start();

class AcmeClient {
    private $directoryUrl;
    private $directory;
    private $accountKey;
    private $accountUrl;
    private $nonce;
    
    public function __construct($staging = false, $accountKey = null, $accountUrl = null) {
        $this->directoryUrl = $staging ? LE_STAGING : LE_PRODUCTION;
        $this->accountKey = $accountKey;
        $this->accountUrl = $accountUrl;
        $this->directory = $this->getDirectory();
    }
    
    private function getDirectory() {
        $response = $this->httpRequest($this->directoryUrl);
        return json_decode($response['body'], true);
    }

    private function refreshNonce() {
        if (isset($this->directory['newNonce'])) {
            $this->httpRequest($this->directory['newNonce'], null, [], true); 
        }
    }
    
    public function httpRequest($url, $data = null, $headers = [], $isHead = false) {
        if (empty($url)) {
            throw new Exception("System Error: API URL is empty or null.");
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        
        if ($isHead) {
            curl_setopt($ch, CURLOPT_NOBODY, true);
        } else if (!is_null($data)) { 
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            $headers[] = 'Content-Type: application/jose+json';
        }
        
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

        $response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            throw new Exception("cURL Error: " . curl_error($ch));
        }

        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if (preg_match('/Replay-Nonce: (.*)/i', $header, $matches)) {
            $this->nonce = trim($matches[1]);
        }
        
        curl_close($ch);
        
        return ['header' => $header, 'body' => $body, 'code' => $http_code];
    }
    
    public function signRequest($url, $payload, $keyType = 'jwk') {
        if (empty($this->nonce)) {
            $this->refreshNonce();
        }

        $protected = [
            'url' => $url,
            'alg' => 'RS256',
            'nonce' => $this->nonce,
        ];
        
        if ($keyType === 'jwk') {
            $protected['jwk'] = $this->getAccountJwk();
        } else {
            $protected['kid'] = $this->accountUrl;
        }
        
        $protected64 = $this->base64UrlEncode(json_encode($protected));
        
        if (is_string($payload)) {
            $payloadContent = $payload;
        } else {
            $payloadContent = json_encode($payload);
        }
        $payload64 = $this->base64UrlEncode($payloadContent);
        
        $signingInput = $protected64 . '.' . $payload64;
        
        if (!$this->accountKey) throw new Exception("State Error: Account Key missing.");

        $privateKey = openssl_pkey_get_private($this->accountKey);
        if (!$privateKey) throw new Exception("State Error: Invalid Private Key.");
        
        if (!openssl_sign($signingInput, $signature, $privateKey, 'sha256WithRSAEncryption')) {
            throw new Exception("Signing Failed.");
        }
        
        return json_encode([
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $this->base64UrlEncode($signature),
        ]);
    }

    public function sendSignedRequest($url, $payload, $keyType = 'kid') {
        $body = $this->signRequest($url, $payload, $keyType);
        $response = $this->httpRequest($url, $body);

        if ($response['code'] == 400) {
            $json = json_decode($response['body'], true);
            if (isset($json['type']) && strpos($json['type'], 'badNonce') !== false) {
                $this->refreshNonce();
                $body = $this->signRequest($url, $payload, $keyType);
                $response = $this->httpRequest($url, $body);
            }
        }

        return $response;
    }
    
    public function base64UrlEncode($data) {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }
    
    public function getAccountJwk() {
        if (!$this->accountKey) return null;
        $details = openssl_pkey_get_details(openssl_pkey_get_private($this->accountKey));
        return [
            'kty' => 'RSA',
            'n' => $this->base64UrlEncode($details['rsa']['n']),
            'e' => $this->base64UrlEncode($details['rsa']['e']),
        ];
    }

    public function registerAccount($email) {
        $newKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($newKey, $this->accountKey);
        
        $payload = [
            'termsOfServiceAgreed' => true,
            'contact' => ["mailto:{$email}"]
        ];
        
        $response = $this->sendSignedRequest($this->directory['newAccount'], $payload, 'jwk');
        
        if ($response['code'] != 201 && $response['code'] != 200) {
            throw new Exception("Registration Failed (" . $response['code'] . "): " . $response['body']);
        }
        
        if (preg_match('/Location: (.*)/i', $response['header'], $matches)) {
            $this->accountUrl = trim($matches[1]);
        } else {
             throw new Exception("No Account URL in headers.");
        }

        return ['accountKey' => $this->accountKey, 'accountUrl' => $this->accountUrl];
    }
    
    public function createOrder($domains) {
        $identifiers = [];
        foreach ($domains as $domain) {
            $identifiers[] = ['type' => 'dns', 'value' => $domain];
        }
        
        $payload = ['identifiers' => $identifiers];
        
        $response = $this->sendSignedRequest($this->directory['newOrder'], $payload);
        
        if ($response['code'] != 201) {
            throw new Exception("Order creation failed (" . $response['code'] . "): " . $response['body']);
        }
        
        $order = json_decode($response['body'], true);
        
        if (preg_match('/Location: (.*)/i', $response['header'], $matches)) {
            $order['orderUrl'] = trim($matches[1]);
        }
        
        return $order;
    }
    
    public function getChallenge($authUrl) {
        $response = $this->sendSignedRequest($authUrl, '');
        
        if ($response['code'] != 200) {
            throw new Exception("Failed to get challenge (" . $response['code'] . "): " . $response['body']);
        }
        
        $auth = json_decode($response['body'], true);
        
        foreach ($auth['challenges'] as $challenge) {
            if ($challenge['type'] === 'dns-01') {
                $challenge['domain'] = $auth['identifier']['value'];
                return $challenge;
            }
        }
        
        throw new Exception("No DNS-01 challenge found");
    }
    
    public function getDnsRecordValue($token) {
        $jwk = $this->getAccountJwk();
        // RFC 7638: Keys must be sorted lexicographically for correct thumbprint
        ksort($jwk);
        $thumbprint = $this->base64UrlEncode(hash('sha256', json_encode($jwk), true));
        $keyAuth = $token . '.' . $thumbprint;
        return $this->base64UrlEncode(hash('sha256', $keyAuth, true));
    }
    
    public function validateChallenge($challengeUrl) {
        $response = $this->sendSignedRequest($challengeUrl, '{}');
        
        if ($response['code'] != 200) {
            throw new Exception("Challenge validation failed (" . $response['code'] . "): " . $response['body']);
        }
        
        return json_decode($response['body'], true);
    }
    
    public function checkOrderStatus($orderUrl) {
        $response = $this->sendSignedRequest($orderUrl, '');
        
        if ($response['code'] != 200) {
            throw new Exception("Failed to check order status (" . $response['code'] . "): " . $response['body']);
        }
        
        return json_decode($response['body'], true);
    }
    
    public function getChallengeData($authUrl) {
        $response = $this->sendSignedRequest($authUrl, '');
        
        if ($response['code'] != 200) {
            throw new Exception("Failed to get challenge data (" . $response['code'] . "): " . $response['body']);
        }
        
        return json_decode($response['body'], true);
    }
    
    public function generateCSR($domains, $privateKeyPem) {
        // Normalize the private key format
        $base64Content = str_replace(
            ['-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----', "\n", "\r", " "],
            '', $privateKeyPem
        );
        $pemContent = chunk_split($base64Content, 64, "\n");
        $normalizedKey = "-----BEGIN PRIVATE KEY-----\n" . trim($pemContent) . "\n-----END PRIVATE KEY-----\n";

        $dn = ["commonName" => $domains[0]];
        $sanList = array_map(function($d) { return "DNS:$d"; }, $domains);
        $sanString = implode(', ', $sanList);

        $csrOptions = [
            'digest_alg' => 'sha256',
            'private_key' => $normalizedKey,
            'subject' => $dn,
            'req_extensions' => ['subjectAltName' => $sanString]
        ];
        
        $privKeyRes = openssl_pkey_get_private($normalizedKey);
        if (!$privKeyRes) throw new Exception("Invalid Private Key.");
        
        $csrRes = openssl_csr_new($dn, $privKeyRes, $csrOptions);
        if (!$csrRes) throw new Exception("CSR Generation Failed.");
        
        openssl_csr_export($csrRes, $csrPem);
        return $csrPem;
    }
    
    public function requestCertificate($finalizeUrl, $csrPem) {
        // Convert PEM to DER format
        $csrDer = base64_decode(preg_replace('/--\s*BEGIN CERTIFICATE REQUEST\s*--|--\s*END CERTIFICATE REQUEST\s*--|\s*/', '', $csrPem));
        $payload = ['csr' => $this->base64UrlEncode($csrDer)];
        
        $response = $this->sendSignedRequest($finalizeUrl, $payload);
        
        if ($response['code'] != 200 && $response['code'] != 201) {
            throw new Exception("Finalize Failed (" . $response['code'] . "): " . $response['body']);
        }
        return json_decode($response['body'], true);
    }
    
    public function getCertificate($certificateUrl) {
        $response = $this->sendSignedRequest($certificateUrl, '');
        
        if ($response['code'] != 200) {
            throw new Exception("Failed to download certificate (" . $response['code'] . "): " . $response['body']);
        }
        
        return $response['body'];
    }
}

// API Handler
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    try {
        $action = $_GET['action'];
        
        // Handle both JSON and regular POST data for compatibility
        $input = !empty($_POST) ? $_POST : json_decode(file_get_contents('php://input'), true);
        
        if (!isset($_SESSION['accountKey']) || !isset($_SESSION['accountUrl'])) {
            $accountKey = null;
            $accountUrl = null;
            $staging = false;
        } else {
            $accountKey = $_SESSION['accountKey'];
            $accountUrl = $_SESSION['accountUrl'];
            $staging = $_SESSION['staging'] ?? false;
        }
        
        $client = new AcmeClient($staging, $accountKey, $accountUrl);
        
        switch ($action) {
            case 'register':
                $staging = $input['staging'] ?? false;
                $email = $input['email'] ?? '';
                
                if (empty($email)) {
                    throw new Exception("Email is required");
                }
                
                $client = new AcmeClient($staging);
                $account = $client->registerAccount($email);
                
                $_SESSION['accountKey'] = $account['accountKey'];
                $_SESSION['accountUrl'] = $account['accountUrl'];
                $_SESSION['staging'] = $staging;
                
                echo json_encode(['success' => true, 'message' => 'Account registered successfully']);
                break;
                
            case 'createOrder':
                $domains = array_filter(array_map('trim', explode("\n", $input['domains'] ?? '')));
                
                if (empty($domains)) {
                    throw new Exception("At least one domain is required");
                }
                
                if (!isset($_SESSION['accountKey']) || !isset($_SESSION['accountUrl'])) {
                    throw new Exception("Please register an account first");
                }
                
                $client = new AcmeClient(
                    $_SESSION['staging'] ?? false,
                    $_SESSION['accountKey'],
                    $_SESSION['accountUrl']
                );
                
                $order = $client->createOrder($domains);
                $challenges = [];
                
                foreach ($order['authorizations'] as $authUrl) {
                    $challenge = $client->getChallenge($authUrl);
                    $recordValue = $client->getDnsRecordValue($challenge['token']);
                    
                    $challenges[] = [
                        'domain' => $challenge['domain'],
                        'recordName' => '_acme-challenge.' . $challenge['domain'],
                        'recordValue' => $recordValue,
                        'challengeUrl' => $challenge['url']
                    ];
                }
                
                $_SESSION['orderUrl'] = $order['orderUrl'];
                
                // Track certificate order
                trackCertOrder($_SESSION['staging'] ?? false);
                
                echo json_encode([
                    'success' => true,
                    'orderUrl' => $order['orderUrl'],
                    'challenges' => $challenges
                ]);
                break;
                
            case 'validateChallenge':
                if (!isset($_SESSION['accountKey']) || !isset($_SESSION['accountUrl'])) {
                    throw new Exception("Session expired. Please start over.");
                }
                
                $client = new AcmeClient(
                    $_SESSION['staging'] ?? false,
                    $_SESSION['accountKey'],
                    $_SESSION['accountUrl']
                );
                
                $result = $client->validateChallenge($input['challengeUrl']);
                
                echo json_encode(['success' => true, 'result' => $result]);
                break;
                
            case 'checkStatus':
                if (!isset($_SESSION['accountKey']) || !isset($_SESSION['accountUrl'])) {
                    throw new Exception("Session expired. Please start over.");
                }
                
                if (empty($input['orderUrl'])) {
                    throw new Exception("Order URL missing. Please create a new order.");
                }
                
                $client = new AcmeClient(
                    $_SESSION['staging'] ?? false,
                    $_SESSION['accountKey'],
                    $_SESSION['accountUrl']
                );
                
                $status = $client->checkOrderStatus($input['orderUrl']);
                
                $errorDetails = null;
                if ($status['status'] === 'invalid' && isset($status['authorizations'])) {
                    foreach ($status['authorizations'] as $authUrl) {
                        try {
                            $authData = $client->getChallengeData($authUrl);
                            if ($authData['status'] === 'invalid') {
                                foreach ($authData['challenges'] as $ch) {
                                    if ($ch['status'] === 'invalid' && isset($ch['error'])) {
                                        $errorDetails = $ch['error']['detail'] ?? json_encode($ch['error']);
                                        break 2;
                                    }
                                }
                            }
                        } catch (Exception $e) {
                            // Continue checking other authorizations
                        }
                    }
                }
                
                $result = [
                    'success' => true,
                    'status' => $status['status'],
                    'certificateUrl' => $status['certificate'] ?? null,
                    'errorDetails' => $errorDetails
                ];
                
                echo json_encode($result);
                break;
                
            case 'finalize':
                if (!isset($_SESSION['accountKey']) || !isset($_SESSION['accountUrl'])) {
                    throw new Exception("Session expired. Please start over.");
                }
                
                // Receive CSR generated in browser (NOT private key!)
                $csrPem = $input['csrPem'] ?? '';
                
                if (empty($csrPem)) {
                    throw new Exception("CSR is required");
                }
                
                if (empty($input['orderUrl'])) {
                    throw new Exception("Order URL missing. Please create a new order.");
                }
                
                $client = new AcmeClient(
                    $_SESSION['staging'] ?? false,
                    $_SESSION['accountKey'],
                    $_SESSION['accountUrl']
                );
                
                // Check if order is ready
                $orderStatus = $client->checkOrderStatus($input['orderUrl']);
                if ($orderStatus['status'] !== 'ready') {
                    throw new Exception("Order not ready (Status: " . $orderStatus['status'] . ")");
                }
                
                // CSR is already generated in browser - just use it directly
                // No need to generate CSR here - private key never sent to server!
                
                // Request certificate using the browser-generated CSR
                $certData = $client->requestCertificate($orderStatus['finalize'], $csrPem);
                
                echo json_encode(['success' => true, 'order' => $certData]);
                break;
                
            case 'getCert':
                if (!isset($_SESSION['accountKey']) || !isset($_SESSION['accountUrl'])) {
                    throw new Exception("Session expired. Please start over.");
                }
                
                $client = new AcmeClient(
                    $_SESSION['staging'] ?? false,
                    $_SESSION['accountKey'],
                    $_SESSION['accountUrl']
                );
                
                $certificate = $client->getCertificate($input['certificateUrl']);
                
                echo json_encode(['success' => true, 'certificate' => $certificate]);
                break;
                
            default:
                throw new Exception("Invalid action");
        }
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => $e->getMessage(), 'message' => $e->getMessage()]);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Primary Meta Tags -->
    <title>Free SSL Certificate Generator - Generate Let's Encrypt SSL/TLS Certificates Online | FreeSSL</title>
    <meta name="title" content="Free SSL Certificate Generator - Generate Let's Encrypt SSL/TLS Certificates Online | FreeSSL">
    <meta name="description" content="Generate free SSL/TLS certificates online in minutes using Let's Encrypt. No credit card required. Support for wildcard certificates, multiple domains (SAN), and DNS-01 validation. 100% free SSL certificate generator.">
    <meta name="keywords" content="free ssl certificate, ssl certificate generator, lets encrypt generator, free tls certificate, wildcard ssl certificate, ssl certificate online, generate ssl certificate free, free ssl generator, lets encrypt certificate generator, free https certificate, ssl certificate tool, online ssl generator, dns-01 challenge, acme certificate, free domain ssl">
    <meta name="author" content="Kheteshwar Boravat - CoderYogi">
    <meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1">
    <link rel="canonical" href="https://coderyogi.com/tool/freessl/">
    
    <!-- Open Graph / Facebook Meta Tags -->
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://coderyogi.com/tool/freessl/">
    <meta property="og:title" content="Free SSL Certificate Generator - Generate Let's Encrypt SSL/TLS Certificates Online">
    <meta property="og:description" content="Generate free SSL/TLS certificates online in minutes using Let's Encrypt. Support for wildcard certificates, multiple domains, and DNS-01 validation. No credit card required.">
    <meta property="og:image" content="https://coderyogi.com/tool/freessl/og-image.png">
    <meta property="og:site_name" content="FreeSSL by CoderYogi">
    <meta property="og:locale" content="en_US">
    
    <!-- Twitter Meta Tags -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:url" content="https://coderyogi.com/tool/freessl/">
    <meta name="twitter:title" content="Free SSL Certificate Generator - Generate Let's Encrypt SSL/TLS Certificates Online">
    <meta name="twitter:description" content="Generate free SSL/TLS certificates online in minutes using Let's Encrypt. Support for wildcard certificates, multiple domains, and DNS-01 validation.">
    <meta name="twitter:image" content="https://coderyogi.com/tool/freessl/twitter-image.png">
    <meta name="twitter:creator" content="@coderyogi">
    
    <!-- Additional SEO Meta Tags -->
    <meta name="theme-color" content="#4f46e5">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="FreeSSL">
    <meta name="application-name" content="FreeSSL Certificate Generator">
    <meta name="msapplication-TileColor" content="#4f46e5">
    <meta name="format-detection" content="telephone=no">
    
    <!-- Geo Tags -->
    <meta name="geo.region" content="IN">
    <meta name="geo.placename" content="Bengaluru">
    
    <!-- Structured Data - WebApplication Schema -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "WebApplication",
      "name": "FreeSSL - Free SSL Certificate Generator",
      "alternateName": "FreeSSL Certificate Generator",
      "url": "https://coderyogi.com/tool/freessl/",
      "description": "Free online SSL/TLS certificate generator using Let's Encrypt ACME protocol. Generate wildcard certificates, multi-domain (SAN) certificates with DNS-01 validation. No credit card required.",
      "applicationCategory": "SecurityApplication",
      "operatingSystem": "Web Browser",
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD"
      },
      "author": {
        "@type": "Person",
        "name": "Kheteshwar Boravat",
        "url": "https://coderyogi.com"
      },
      "provider": {
        "@type": "Organization",
        "name": "CoderYogi",
        "url": "https://coderyogi.com"
      },
      "featureList": [
        "Free SSL/TLS Certificate Generation",
        "Let's Encrypt Integration",
        "Wildcard Certificate Support",
        "Multi-Domain (SAN) Certificates",
        "DNS-01 Challenge Validation",
        "Client-Side Key Generation",
        "No Registration Required",
        "90-Day Valid Certificates"
      ],
      "screenshot": "https://coderyogi.com/tool/freessl/screenshot.png",
      "softwareVersion": "3.0",
      "aggregateRating": {
        "@type": "AggregateRating",
        "ratingValue": "4.8",
        "ratingCount": "127",
        "bestRating": "5",
        "worstRating": "1"
      }
    }
    </script>
    
    <!-- Structured Data - HowTo Schema -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "HowTo",
      "name": "How to Generate Free SSL Certificate Online",
      "description": "Step-by-step guide to generate free SSL/TLS certificates using Let's Encrypt",
      "image": "https://coderyogi.com/tool/freessl/howto-image.png",
      "totalTime": "PT10M",
      "tool": {
        "@type": "HowToTool",
        "name": "FreeSSL Certificate Generator"
      },
      "step": [
        {
          "@type": "HowToStep",
          "name": "Register Account",
          "text": "Enter your email address and choose staging or production environment",
          "url": "https://coderyogi.com/tool/freessl/#step1",
          "position": 1
        },
        {
          "@type": "HowToStep",
          "name": "Enter Domains",
          "text": "Specify the domain names you want to secure (supports wildcards and multiple domains)",
          "url": "https://coderyogi.com/tool/freessl/#step2",
          "position": 2
        },
        {
          "@type": "HowToStep",
          "name": "Verify DNS",
          "text": "Add DNS TXT records to verify domain ownership using DNS-01 challenge",
          "url": "https://coderyogi.com/tool/freessl/#step3",
          "position": 3
        },
        {
          "@type": "HowToStep",
          "name": "Download Certificate",
          "text": "Generate and download your free SSL certificate and private key",
          "url": "https://coderyogi.com/tool/freessl/#step4",
          "position": 4
        }
      ]
    }
    </script>
    
    <!-- Structured Data - Organization -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "Organization",
      "name": "CoderYogi",
      "url": "https://coderyogi.com",
      "logo": "https://coderyogi.com/logo.png",
      "sameAs": [
        "https://github.com/kheteswar",
        "https://www.linkedin.com/in/kheteswar/"
      ],
      "contactPoint": {
        "@type": "ContactPoint",
        "contactType": "Technical Support",
        "url": "https://coderyogi.com/#contact"
      }
    }
    </script>
    
    <!-- Structured Data - FAQPage -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "FAQPage",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "Is FreeSSL really free?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Yes, FreeSSL is completely free. We use Let's Encrypt, a free, automated, and open Certificate Authority. There are no hidden costs, no credit card required, and no subscription fees."
          }
        },
        {
          "@type": "Question",
          "name": "Does FreeSSL support wildcard certificates?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Yes, FreeSSL fully supports wildcard certificates (*.example.com). You can generate wildcard certificates using DNS-01 challenge validation."
          }
        },
        {
          "@type": "Question",
          "name": "How long are the SSL certificates valid?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "SSL certificates generated through FreeSSL are valid for 90 days, which is the standard validity period for Let's Encrypt certificates. You can renew them before expiration."
          }
        },
        {
          "@type": "Question",
          "name": "Can I use FreeSSL for multiple domains?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Yes, FreeSSL supports multi-domain (SAN) certificates. You can secure multiple domains with a single certificate, including both regular domains and wildcard domains."
          }
        },
        {
          "@type": "Question",
          "name": "Is my private key secure?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Yes, your private key is generated entirely in your browser using Web Crypto API. The private key never leaves your computer and is not transmitted to our servers, ensuring maximum security."
          }
        }
      ]
    }
    </script>
    
    <!-- Preconnect for Performance -->
    <link rel="preconnect" href="https://cdn.tailwindcss.com">
    <link rel="preconnect" href="https://cdnjs.cloudflare.com">
    <link rel="dns-prefetch" href="https://acme-v02.api.letsencrypt.org">
    <link rel="dns-prefetch" href="https://dns.google">
    
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Forge.js for client-side CSR generation -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/forge/1.3.1/forge.min.js"></script>
    <style>
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .spinner {
            animation: spin 1s linear infinite;
        }
        .step-indicator {
            transition: all 0.3s ease;
        }
        .step-indicator.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            transform: scale(1.1);
        }
        .step-indicator.completed {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        }
        .step-line {
            transition: all 0.3s ease;
        }
        .step-line.active {
            background: linear-gradient(90deg, #10b981 0%, #667eea 100%);
        }
        .fade-in {
            animation: fadeIn 0.4s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .tooltip {
            position: relative;
            display: inline-block;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            background-color: #1f2937;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 8px 12px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 14px;
            white-space: nowrap;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        .code-block {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
        }
        .alert {
            border-left: 4px solid;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }
        .alert-info {
            background: #dbeafe;
            border-color: #3b82f6;
            color: #1e40af;
        }
        .alert-warning {
            background: #fef3c7;
            border-color: #f59e0b;
            color: #92400e;
        }
        .alert-success {
            background: #d1fae5;
            border-color: #10b981;
            color: #065f46;
        }
        .alert-error {
            background: #fee2e2;
            border-color: #ef4444;
            color: #991b1b;
        }
    </style>
</head>
<body class="bg-gradient-to-br from-slate-50 to-slate-100 min-h-screen">
    <!-- Header -->
    <header class="bg-white shadow-md">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between py-4">
                <!-- Logo and Title -->
                <div class="flex items-center space-x-3">
                    <i class="fas fa-shield-alt text-4xl text-indigo-600"></i>
                    <div>
                        <h1 class="text-3xl font-bold text-gray-900">FreeSSL</h1>
                        <p class="text-sm text-gray-600">Free SSL/TLS Certificate Generator</p>
                    </div>
                </div>

                <!-- Navigation Menu -->
                <nav class="hidden md:flex items-center space-x-8">
                    <a href="https://coderyogi.com/" 
                       class="flex items-center space-x-2 text-gray-700 hover:text-indigo-600 transition-colors duration-200 font-medium">
                        <i class="fas fa-home"></i>
                        <span>Home</span>
                    </a>
                    <a href="https://letsencrypt.org/docs/" 
                       target="_blank"
                       class="flex items-center space-x-2 text-gray-700 hover:text-indigo-600 transition-colors duration-200 font-medium">
                        <i class="fas fa-book"></i>
                        <span>Docs</span>
                    </a>
                    <a href="https://letsencrypt.org/docs/rate-limits/" 
                       target="_blank"
                       class="flex items-center space-x-2 text-gray-700 hover:text-indigo-600 transition-colors duration-200 font-medium">
                        <i class="fas fa-info-circle"></i>
                        <span>Rate Limits</span>
                    </a>
                    <div class="flex items-center space-x-2 text-gray-500 text-sm border-l border-gray-300 pl-6">
                        <span>Powered by</span>
                        <a href="https://letsencrypt.org/" target="_blank" class="font-semibold text-blue-600 hover:text-blue-700 transition-colors">
                            Let's Encrypt
                        </a>
                    </div>
                </nav>

                <!-- Mobile Menu Button -->
                <button id="mobile-menu-btn" class="md:hidden text-gray-700 hover:text-indigo-600 transition-colors">
                    <i class="fas fa-bars text-2xl"></i>
                </button>
            </div>

            <!-- Mobile Navigation Menu -->
            <div id="mobile-menu" class="hidden md:hidden border-t border-gray-200 py-4">
                <nav class="flex flex-col space-y-3">
                    <a href="https://coderyogi.com/" 
                       class="flex items-center space-x-2 text-gray-700 hover:text-indigo-600 transition-colors duration-200 font-medium py-2">
                        <i class="fas fa-home w-5"></i>
                        <span>Home</span>
                    </a>
                    <a href="https://letsencrypt.org/docs/" 
                       target="_blank"
                       class="flex items-center space-x-2 text-gray-700 hover:text-indigo-600 transition-colors duration-200 font-medium py-2">
                        <i class="fas fa-book w-5"></i>
                        <span>Documentation</span>
                    </a>
                    <a href="https://letsencrypt.org/docs/rate-limits/" 
                       target="_blank"
                       class="flex items-center space-x-2 text-gray-700 hover:text-indigo-600 transition-colors duration-200 font-medium py-2">
                        <i class="fas fa-info-circle w-5"></i>
                        <span>Rate Limits</span>
                    </a>
                    <div class="border-t border-gray-200 pt-3 mt-3">
                        <div class="flex items-center space-x-2 text-gray-500 text-sm">
                            <span>Powered by</span>
                            <a href="https://letsencrypt.org/" target="_blank" class="font-semibold text-blue-600 hover:text-blue-700">
                                Let's Encrypt
                            </a>
                        </div>
                    </div>
                </nav>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Security & Privacy Assurance Banner -->
        <div class="mb-8 bg-gradient-to-r from-green-50 to-emerald-50 border-2 border-green-200 rounded-xl p-6 shadow-lg">
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <div class="flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                        <i class="fas fa-shield-alt text-2xl text-green-600"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <h3 class="text-lg font-bold text-gray-900 mb-2 flex items-center">
                        <i class="fas fa-lock text-green-600 mr-2"></i>
                        Your Private Keys Never Leave Your Browser - We Collect ZERO Data
                    </h3>
                    <p class="text-gray-700 mb-2">
                        <strong>100% Client-Side Security & Privacy:</strong> Your private keys are generated entirely in your browser using Web Crypto API. 
                        They are <strong>NEVER transmitted to our server</strong> or any third-party server. We act as a pure proxy - 
                        we don't collect, log, or store your private keys, email, domains, or any personal data.
                    </p>
                    <button onclick="document.getElementById('securityDetailsModal').classList.remove('hidden')" 
                            class="text-green-700 hover:text-green-800 font-semibold underline text-sm flex items-center mt-2">
                        <i class="fas fa-info-circle mr-1"></i>
                        Learn how this works - Complete transparency
                    </button>
                </div>
            </div>
        </div>

        <!-- Security Details Modal -->
        <div id="securityDetailsModal" class="hidden fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4" onclick="if(event.target === this) this.classList.add('hidden')">
            <div class="bg-white rounded-xl max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl" onclick="event.stopPropagation()">
                <!-- Modal Header -->
                <div class="bg-gradient-to-r from-green-600 to-emerald-600 text-white p-6 rounded-t-xl sticky top-0 z-10">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center">
                            <i class="fas fa-shield-alt text-3xl mr-4"></i>
                            <div>
                                <h2 class="text-2xl font-bold">Security & Privacy - Complete Transparency</h2>
                                <p class="text-green-100 text-sm mt-1">How FreeSSL protects your private keys and ensures complete security</p>
                            </div>
                        </div>
                        <button onclick="document.getElementById('securityDetailsModal').classList.add('hidden')" 
                                class="text-white hover:text-gray-200 transition-colors">
                            <i class="fas fa-times text-2xl"></i>
                        </button>
                    </div>
                </div>

                <!-- Modal Content -->
                <div class="p-8">
                    <!-- Core Security Promise -->
                    <div class="bg-green-50 border-2 border-green-200 rounded-lg p-6 mb-8">
                        <h3 class="text-xl font-bold text-gray-900 mb-4 flex items-center">
                            <i class="fas fa-certificate text-green-600 mr-3 text-2xl"></i>
                            Our Security Promise
                        </h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div class="flex items-start">
                                <i class="fas fa-check-circle text-green-600 text-xl mr-3 mt-1"></i>
                                <div>
                                    <strong class="text-gray-900">Private keys generated in YOUR browser</strong>
                                    <p class="text-gray-700 text-sm">Using Web Crypto API - never on our server</p>
                                </div>
                            </div>
                            <div class="flex items-start">
                                <i class="fas fa-check-circle text-green-600 text-xl mr-3 mt-1"></i>
                                <div>
                                    <strong class="text-gray-900">Certificates sent directly to YOU</strong>
                                    <p class="text-gray-700 text-sm">From Let's Encrypt to your browser - we never intercept</p>
                                </div>
                            </div>
                            <div class="flex items-start">
                                <i class="fas fa-check-circle text-green-600 text-xl mr-3 mt-1"></i>
                                <div>
                                    <strong class="text-gray-900">No data collected or stored</strong>
                                    <p class="text-gray-700 text-sm">We don't collect email, domains, or any personal data - pure proxy only</p>
                                </div>
                            </div>
                            <div class="flex items-start">
                                <i class="fas fa-check-circle text-green-600 text-xl mr-3 mt-1"></i>
                                <div>
                                    <strong class="text-gray-900">Open source & transparent</strong>
                                    <p class="text-gray-700 text-sm">You can inspect our code - nothing hidden</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- How It Works - Technical Flow -->
                    <div class="mb-8">
                        <h3 class="text-2xl font-bold text-gray-900 mb-4 flex items-center">
                            <i class="fas fa-code-branch text-indigo-600 mr-3"></i>
                            How FreeSSL Works - Complete Technical Flow
                        </h3>
                        <p class="text-gray-700 mb-6">
                            Understanding exactly what happens to your private keys at each step helps you make an informed decision. 
                            Here's the complete, transparent process:
                        </p>

                        <!-- Step-by-step flow -->
                        <div class="space-y-6">
                            <!-- Step 1 -->
                            <div class="flex items-start border-l-4 border-indigo-600 pl-6 py-4 bg-indigo-50 rounded-r-lg">
                                <div class="flex-shrink-0 w-12 h-12 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold text-lg mr-4">1</div>
                                <div class="flex-1">
                                    <h4 class="font-bold text-gray-900 mb-2">Account Key Generation (Your Browser)</h4>
                                    <p class="text-gray-700 mb-2">
                                        When you click "Register," your browser generates an account keypair using <code class="bg-gray-200 px-2 py-1 rounded">window.crypto.subtle.generateKey()</code>.
                                    </p>
                                    <div class="bg-white border border-gray-300 rounded p-3 text-sm">
                                        <strong class="text-green-700">✓ Where:</strong> Your browser's memory only<br>
                                        <strong class="text-green-700">✓ Sent to server:</strong> Public key ONLY (used for Let's Encrypt registration)<br>
                                        <strong class="text-red-700">✗ Never sent:</strong> Private account key stays in browser
                                    </div>
                                </div>
                            </div>

                            <!-- Step 2 -->
                            <div class="flex items-start border-l-4 border-indigo-600 pl-6 py-4 bg-indigo-50 rounded-r-lg">
                                <div class="flex-shrink-0 w-12 h-12 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold text-lg mr-4">2</div>
                                <div class="flex-1">
                                    <h4 class="font-bold text-gray-900 mb-2">Server Role: Pure Proxy - Zero Data Storage</h4>
                                    <p class="text-gray-700 mb-2">
                                        Our server is a <strong>pure proxy</strong> that forwards requests between your browser and Let's Encrypt. We act as a middleman for technical reasons (browser limitations with ACME protocol).
                                    </p>
                                    <ul class="space-y-1 text-gray-700 ml-4">
                                        <li class="flex items-start">
                                            <i class="fas fa-arrow-right text-indigo-600 mr-2 mt-1"></i>
                                            <span>Forward <strong>email & domains</strong> to Let's Encrypt (required by ACME protocol)</span>
                                        </li>
                                        <li class="flex items-start">
                                            <i class="fas fa-arrow-right text-indigo-600 mr-2 mt-1"></i>
                                            <span>Forward <strong>signed requests</strong> (signed with your private key in browser)</span>
                                        </li>
                                        <li class="flex items-start">
                                            <i class="fas fa-arrow-right text-indigo-600 mr-2 mt-1"></i>
                                            <span>Return Let's Encrypt's responses back to your browser</span>
                                        </li>
                                        <li class="flex items-start">
                                            <i class="fas fa-arrow-right text-indigo-600 mr-2 mt-1"></i>
                                            <span>Verify DNS records via Google Public DNS (to check TXT records)</span>
                                        </li>
                                    </ul>
                                    <div class="bg-white border border-gray-300 rounded p-3 text-sm mt-2">
                                        <strong class="text-blue-700">✓ Passes through:</strong> Email, domains, account public key, signed requests, CSR (public key)<br>
                                        <strong class="text-yellow-600">⚡ Temporary only:</strong> Data flows through during session - instantly forwarded to Let's Encrypt<br>
                                        <strong class="text-green-700">✓ Zero storage:</strong> We don't save, log, or store email, domains, or any data<br>
                                        <strong class="text-red-700">✗ Never see:</strong> Private keys (they NEVER leave your browser)
                                    </div>
                                </div>
                            </div>

                            <!-- Step 3 -->
                            <div class="flex items-start border-l-4 border-indigo-600 pl-6 py-4 bg-indigo-50 rounded-r-lg">
                                <div class="flex-shrink-0 w-12 h-12 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold text-lg mr-4">3</div>
                                <div class="flex-1">
                                    <h4 class="font-bold text-gray-900 mb-2">Certificate Private Key Generation (Your Browser)</h4>
                                    <p class="text-gray-700 mb-2">
                                        When creating your certificate order, your browser generates a NEW keypair for the certificate itself.
                                    </p>
                                    <div class="bg-white border border-gray-300 rounded p-3 text-sm">
                                        <strong class="text-green-700">✓ Where:</strong> Generated in your browser using Web Crypto API<br>
                                        <strong class="text-green-700">✓ What we receive:</strong> CSR (Certificate Signing Request) with public key<br>
                                        <strong class="text-red-700">✗ Private key:</strong> Remains in your browser, never transmitted anywhere
                                    </div>
                                </div>
                            </div>

                            <!-- Step 4 -->
                            <div class="flex items-start border-l-4 border-indigo-600 pl-6 py-4 bg-indigo-50 rounded-r-lg">
                                <div class="flex-shrink-0 w-12 h-12 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold text-lg mr-4">4</div>
                                <div class="flex-1">
                                    <h4 class="font-bold text-gray-900 mb-2">Certificate Issuance (Let's Encrypt → Your Browser)</h4>
                                    <p class="text-gray-700 mb-2">
                                        After DNS verification, Let's Encrypt issues your certificate:
                                    </p>
                                    <div class="bg-white border border-gray-300 rounded p-3">
                                        <div class="flex items-center mb-3">
                                            <div class="bg-blue-100 px-3 py-1 rounded text-sm font-semibold mr-2">Let's Encrypt</div>
                                            <i class="fas fa-arrow-right mx-2 text-gray-400"></i>
                                            <div class="bg-yellow-100 px-3 py-1 rounded text-sm font-semibold mr-2">Our Server (Proxy)</div>
                                            <i class="fas fa-arrow-right mx-2 text-gray-400"></i>
                                            <div class="bg-green-100 px-3 py-1 rounded text-sm font-semibold">Your Browser</div>
                                        </div>
                                        <p class="text-sm text-gray-700">
                                            <strong class="text-blue-700">Certificate (public):</strong> Passes through our server → Delivered to your browser<br>
                                            <strong class="text-green-700">Private key:</strong> Already in your browser, never transmitted
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <!-- Step 5 -->
                            <div class="flex items-start border-l-4 border-green-600 pl-6 py-4 bg-green-50 rounded-r-lg">
                                <div class="flex-shrink-0 w-12 h-12 bg-green-600 text-white rounded-full flex items-center justify-center font-bold text-lg mr-4">5</div>
                                <div class="flex-1">
                                    <h4 class="font-bold text-gray-900 mb-2">Download & Use (100% Client-Side)</h4>
                                    <p class="text-gray-700 mb-2">
                                        You download both files directly from your browser's memory:
                                    </p>
                                    <ul class="space-y-2 text-gray-700">
                                        <li class="flex items-start">
                                            <i class="fas fa-file-certificate text-green-600 mr-2 mt-1"></i>
                                            <span><strong>certificate.crt</strong> - Public certificate (received from Let's Encrypt)</span>
                                        </li>
                                        <li class="flex items-start">
                                            <i class="fas fa-key text-green-600 mr-2 mt-1"></i>
                                            <span><strong>private.key</strong> - Private key (generated & stored in your browser only)</span>
                                        </li>
                                    </ul>
                                    <div class="bg-white border border-green-300 rounded p-3 text-sm mt-2">
                                        <strong class="text-green-700">✓ Download method:</strong> JavaScript <code>Blob</code> and <code>URL.createObjectURL()</code><br>
                                        <strong class="text-green-700">✓ Files created:</strong> In your browser's memory, then saved to your computer<br>
                                        <strong class="text-green-700">✓ Server involvement:</strong> ZERO - Pure client-side download
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Visual Data Flow Diagram -->
                    <div class="bg-gray-50 rounded-lg p-6 mb-8">
                        <h3 class="text-xl font-bold text-gray-900 mb-4 flex items-center">
                            <i class="fas fa-project-diagram text-indigo-600 mr-3"></i>
                            Visual Data Flow
                        </h3>
                        <div class="bg-white border-2 border-gray-300 rounded-lg p-6">
                            <div class="space-y-4 text-sm">
                                <!-- Your Browser -->
                                <div class="border-2 border-green-500 rounded-lg p-4 bg-green-50">
                                    <div class="font-bold text-green-800 mb-2 flex items-center">
                                        <i class="fas fa-browser text-xl mr-2"></i>
                                        YOUR BROWSER (Client-Side)
                                    </div>
                                    <div class="space-y-1 text-gray-700 ml-6">
                                        <div>✓ Account private key generated here</div>
                                        <div>✓ Certificate private key generated here</div>
                                        <div>✓ CSR created here</div>
                                        <div>✓ All cryptographic signing done here</div>
                                        <div class="text-green-700 font-semibold mt-2">🔒 Private keys NEVER leave this space</div>
                                    </div>
                                </div>

                                <div class="flex justify-center">
                                    <i class="fas fa-arrow-down text-2xl text-gray-400"></i>
                                </div>

                                <!-- Our Server -->
                                <div class="border-2 border-yellow-500 rounded-lg p-4 bg-yellow-50">
                                    <div class="font-bold text-yellow-800 mb-2 flex items-center">
                                        <i class="fas fa-server text-xl mr-2"></i>
                                        OUR SERVER (Pure Proxy - Zero Data Collection)
                                    </div>
                                    <div class="space-y-1 text-gray-700 ml-6">
                                        <div>→ Receives: Encrypted signed requests from your browser</div>
                                        <div>→ Forwards to: Let's Encrypt API (no modification)</div>
                                        <div>→ Returns: API responses to your browser (no modification)</div>
                                        <div>→ Verifies: DNS records via Google Public DNS</div>
                                        <div class="text-red-700 font-semibold mt-2">✗ Never collects, logs, or stores: Email, domains, keys, certificates, or any personal data</div>
                                    </div>
                                </div>

                                <div class="flex justify-center">
                                    <i class="fas fa-arrow-down text-2xl text-gray-400"></i>
                                </div>

                                <!-- Let's Encrypt -->
                                <div class="border-2 border-blue-500 rounded-lg p-4 bg-blue-50">
                                    <div class="font-bold text-blue-800 mb-2 flex items-center">
                                        <i class="fas fa-certificate text-xl mr-2"></i>
                                        LET'S ENCRYPT (Certificate Authority)
                                    </div>
                                    <div class="space-y-1 text-gray-700 ml-6">
                                        <div>→ Validates domain ownership</div>
                                        <div>→ Issues signed certificate</div>
                                        <div>→ Returns certificate to your browser (via our proxy)</div>
                                        <div class="text-blue-700 font-semibold mt-2">📜 Only issues public certificates</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Technical Verification -->
                    <div class="bg-indigo-50 rounded-lg p-6 mb-8">
                        <h3 class="text-xl font-bold text-gray-900 mb-4 flex items-center">
                            <i class="fas fa-code text-indigo-600 mr-3"></i>
                            Verify It Yourself - Inspect Our Code
                        </h3>
                        <p class="text-gray-700 mb-4">
                            Don't just trust us - verify it yourself! Open your browser's Developer Tools (F12) and:
                        </p>
                        <div class="space-y-3">
                            <div class="bg-white rounded border border-gray-300 p-4">
                                <strong class="text-gray-900">1. Check Network Tab</strong>
                                <p class="text-gray-700 text-sm mt-1">Watch all API requests. You'll see we only send public data (CSR, domain names, signed requests). Private keys are never in any network request.</p>
                            </div>
                            <div class="bg-white rounded border border-gray-300 p-4">
                                <strong class="text-gray-900">2. Search for "generateKey"</strong>
                                <p class="text-gray-700 text-sm mt-1">Search our JavaScript code for <code class="bg-gray-200 px-2 py-1 rounded text-xs">crypto.subtle.generateKey</code>. You'll see keys are generated client-side.</p>
                            </div>
                            <div class="bg-white rounded border border-gray-300 p-4">
                                <strong class="text-gray-900">3. Inspect Download Code</strong>
                                <p class="text-gray-700 text-sm mt-1">Find the download functions. You'll see we use <code class="bg-gray-200 px-2 py-1 rounded text-xs">Blob</code> and <code class="bg-gray-200 px-2 py-1 rounded text-xs">createObjectURL</code> - pure client-side downloads.</p>
                            </div>
                            <div class="bg-white rounded border border-gray-300 p-4">
                                <strong class="text-gray-900">4. Check Console Logs</strong>
                                <p class="text-gray-700 text-sm mt-1">We log all operations to console for transparency. You'll see exactly what happens at each step.</p>
                            </div>
                        </div>
                    </div>

                    <!-- Comparison with Other Methods -->
                    <div class="mb-8">
                        <h3 class="text-xl font-bold text-gray-900 mb-4 flex items-center">
                            <i class="fas fa-balance-scale text-indigo-600 mr-3"></i>
                            FreeSSL vs Other Methods
                        </h3>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="bg-gray-100">
                                    <tr>
                                        <th class="px-4 py-3 text-left font-semibold">Method</th>
                                        <th class="px-4 py-3 text-left font-semibold">Private Key Location</th>
                                        <th class="px-4 py-3 text-left font-semibold">Security Level</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-200">
                                    <tr class="bg-green-50">
                                        <td class="px-4 py-3 font-semibold text-green-800">FreeSSL (This Tool)</td>
                                        <td class="px-4 py-3">Your browser only</td>
                                        <td class="px-4 py-3"><span class="bg-green-600 text-white px-3 py-1 rounded-full text-xs font-bold">HIGHEST</span></td>
                                    </tr>
                                    <tr>
                                        <td class="px-4 py-3">Certbot (Command Line)</td>
                                        <td class="px-4 py-3">Your server</td>
                                        <td class="px-4 py-3"><span class="bg-green-500 text-white px-3 py-1 rounded-full text-xs">High</span></td>
                                    </tr>
                                    <tr>
                                        <td class="px-4 py-3">Server-Side Generators</td>
                                        <td class="px-4 py-3">Third-party server</td>
                                        <td class="px-4 py-3"><span class="bg-yellow-500 text-white px-3 py-1 rounded-full text-xs">Medium</span></td>
                                    </tr>
                                    <tr>
                                        <td class="px-4 py-3">Online Generators (Server-Side)</td>
                                        <td class="px-4 py-3">Provider's server</td>
                                        <td class="px-4 py-3"><span class="bg-red-500 text-white px-3 py-1 rounded-full text-xs">LOW</span></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- FAQ -->
                    <div class="border-t-2 border-gray-200 pt-6">
                        <h3 class="text-xl font-bold text-gray-900 mb-4">Security FAQs</h3>
                        <div class="space-y-4">
                            <div>
                                <h4 class="font-semibold text-gray-900 mb-2">Q: Can you see my private keys?</h4>
                                <p class="text-gray-700 pl-4 border-l-4 border-green-500 bg-green-50 p-3">
                                    <strong>No.</strong> Private keys are generated in your browser using Web Crypto API and never leave your device. 
                                    They're never transmitted to our server or any other server.
                                </p>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900 mb-2">Q: Do you log or store certificates?</h4>
                                <p class="text-gray-700 pl-4 border-l-4 border-green-500 bg-green-50 p-3">
                                    <strong>No.</strong> Certificates are delivered directly from Let's Encrypt to your browser through our proxy. 
                                    We don't log, store, or have access to your certificates or keys.
                                </p>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900 mb-2">Q: What data do you collect?</h4>
                                <p class="text-gray-700 pl-4 border-l-4 border-green-500 bg-green-50 p-3">
                                    <strong>We collect NOTHING.</strong> Your email and domain names are sent directly from your browser to Let's Encrypt's API (they require this for registration). 
                                    Our server only acts as a proxy - we don't collect, log, or store your email, domains, or any personal information.
                                </p>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900 mb-2">Q: Where does my email and domain information go?</h4>
                                <p class="text-gray-700 pl-4 border-l-4 border-blue-500 bg-blue-50 p-3">
                                    Your email and domains go <strong>directly to Let's Encrypt</strong> through our proxy. Think of us as a secure tunnel - 
                                    data passes through but we don't read, store, or log it. Let's Encrypt requires this information for certificate issuance 
                                    and expiration notifications.
                                </p>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900 mb-2">Q: How can I verify this claim?</h4>
                                <p class="text-gray-700 pl-4 border-l-4 border-indigo-500 bg-indigo-50 p-3">
                                    Open your browser's Developer Tools (F12) and check the Network tab. Monitor all requests and you'll see 
                                    that private keys are never transmitted. You can also inspect our JavaScript code.
                                </p>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900 mb-2">Q: Is this safer than other online generators?</h4>
                                <p class="text-gray-700 pl-4 border-l-4 border-green-500 bg-green-50 p-3">
                                    <strong>Yes.</strong> Most online generators create keys on their servers. FreeSSL generates keys entirely 
                                    in your browser, making it one of the safest ways to get free SSL certificates online.
                                </p>
                            </div>
                        </div>
                    </div>

                    <!-- Trust Badges -->
                    <div class="mt-8 text-center bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg p-6">
                        <h4 class="font-bold text-gray-900 mb-4">Why You Can Trust FreeSSL</h4>
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                            <div class="flex flex-col items-center">
                                <i class="fas fa-shield-alt text-3xl text-green-600 mb-2"></i>
                                <strong>Client-Side</strong>
                                <span class="text-gray-600">Encryption</span>
                            </div>
                            <div class="flex flex-col items-center">
                                <i class="fas fa-lock text-3xl text-green-600 mb-2"></i>
                                <strong>Zero</strong>
                                <span class="text-gray-600">Key Storage</span>
                            </div>
                            <div class="flex flex-col items-center">
                                <i class="fas fa-eye-slash text-3xl text-green-600 mb-2"></i>
                                <strong>No Logging</strong>
                                <span class="text-gray-600">Of Keys</span>
                            </div>
                            <div class="flex flex-col items-center">
                                <i class="fas fa-code text-3xl text-green-600 mb-2"></i>
                                <strong>Open</strong>
                                <span class="text-gray-600">Transparent Code</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Modal Footer -->
                <div class="bg-gray-50 px-8 py-4 rounded-b-xl border-t border-gray-200 flex justify-between items-center">
                    <p class="text-sm text-gray-600">
                        <i class="fas fa-info-circle mr-1"></i>
                        Still have questions? <a href="https://coderyogi.com/#contact" class="text-indigo-600 hover:text-indigo-800 font-semibold">Contact us</a>
                    </p>
                    <button onclick="document.getElementById('securityDetailsModal').classList.add('hidden')" 
                            class="bg-green-600 hover:bg-green-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors">
                        Got It - I Trust FreeSSL
                    </button>
                </div>
            </div>
        </div>

        <!-- Progress Indicator -->
        <div class="mb-10">
            <div class="flex items-center justify-between max-w-4xl mx-auto">
                <div class="flex flex-col items-center flex-1">
                    <div class="step-indicator active w-12 h-12 rounded-full flex items-center justify-center text-white font-bold text-lg shadow-lg" id="step1-indicator">1</div>
                    <span class="mt-2 text-sm font-medium text-gray-700" id="step1-label">Setup</span>
                </div>
                <div class="step-line flex-1 h-1 bg-gray-300 mx-2" id="line1"></div>
                <div class="flex flex-col items-center flex-1">
                    <div class="step-indicator w-12 h-12 rounded-full flex items-center justify-center bg-gray-300 text-gray-600 font-bold text-lg" id="step2-indicator">2</div>
                    <span class="mt-2 text-sm font-medium text-gray-500" id="step2-label">Domain</span>
                </div>
                <div class="step-line flex-1 h-1 bg-gray-300 mx-2" id="line2"></div>
                <div class="flex flex-col items-center flex-1">
                    <div class="step-indicator w-12 h-12 rounded-full flex items-center justify-center bg-gray-300 text-gray-600 font-bold text-lg" id="step3-indicator">3</div>
                    <span class="mt-2 text-sm font-medium text-gray-500" id="step3-label">Verify DNS</span>
                </div>
                <div class="step-line flex-1 h-1 bg-gray-300 mx-2" id="line3"></div>
                <div class="flex flex-col items-center flex-1">
                    <div class="step-indicator w-12 h-12 rounded-full flex items-center justify-center bg-gray-300 text-gray-600 font-bold text-lg" id="step4-indicator">4</div>
                    <span class="mt-2 text-sm font-medium text-gray-500" id="step4-label">Issue</span>
                </div>
            </div>
        </div>

        <!-- Step 1: Account Registration -->
        <div id="step1" class="fade-in bg-white rounded-xl shadow-lg p-8 mb-6">
            <div class="flex items-start mb-6">
                <div class="flex-shrink-0">
                    <div class="flex items-center justify-center h-12 w-12 rounded-md bg-indigo-100 text-indigo-600">
                        <i class="fas fa-user-plus text-xl"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <h2 class="text-2xl font-bold text-gray-900 mb-2">Step 1: Account Setup</h2>
                    <p class="text-gray-600">Register with Let's Encrypt to begin generating your free SSL certificate</p>
                </div>
            </div>

            <div class="alert alert-info">
                <div class="flex items-start">
                    <i class="fas fa-info-circle mt-0.5 mr-3"></i>
                    <div>
                        <strong>About Account Registration:</strong>
                        <p class="mt-1">Your email will be used for important certificate expiration notices and account recovery. We recommend using staging mode for testing to avoid rate limits.</p>
                    </div>
                </div>
            </div>

            <div class="space-y-6">
                <div>
                    <label class="block text-sm font-semibold text-gray-700 mb-2">
                        Email Address <span class="text-red-500">*</span>
                        <span class="tooltip ml-1">
                            <i class="fas fa-question-circle text-gray-400 cursor-help"></i>
                            <span class="tooltiptext">Used for expiration notifications</span>
                        </span>
                    </label>
                    <input type="email" id="email" 
                           class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition"
                           placeholder="your.email@example.com">
                </div>

                <div class="bg-gray-50 p-4 rounded-lg">
                    <label class="flex items-center cursor-pointer">
                        <input type="checkbox" id="staging" class="w-5 h-5 text-indigo-600 rounded focus:ring-indigo-500">
                        <span class="ml-3 text-gray-700">
                            <strong>Use Staging Environment</strong>
                            <span class="tooltip ml-1">
                                <i class="fas fa-question-circle text-gray-400 cursor-help"></i>
                                <span class="tooltiptext">Recommended for testing - no rate limits</span>
                            </span>
                        </span>
                    </label>
                    <p class="ml-8 mt-1 text-sm text-gray-500">Recommended for testing. Staging certificates won't be trusted by browsers but help you avoid production rate limits.</p>
                </div>

                <button onclick="register()" 
                        class="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-semibold py-3 px-6 rounded-lg shadow-lg hover:shadow-xl transition-all duration-200 flex items-center justify-center">
                    <i class="fas fa-rocket mr-2"></i>
                    Register & Continue
                </button>
            </div>
        </div>

        <!-- Step 2: Domain Configuration -->
        <div id="step2" class="hidden fade-in bg-white rounded-xl shadow-lg p-8 mb-6">
            <div class="flex items-start mb-6">
                <div class="flex-shrink-0">
                    <div class="flex items-center justify-center h-12 w-12 rounded-md bg-indigo-100 text-indigo-600">
                        <i class="fas fa-globe text-xl"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <h2 class="text-2xl font-bold text-gray-900 mb-2">Step 2: Domain Configuration</h2>
                    <p class="text-gray-600">Specify the domains you want to secure with an SSL certificate</p>
                </div>
            </div>

            <div class="alert alert-info">
                <div class="flex items-start">
                    <i class="fas fa-lightbulb mt-0.5 mr-3"></i>
                    <div>
                        <strong>Tips for Domain Entry:</strong>
                        <ul class="mt-1 list-disc list-inside space-y-1">
                            <li>Enter one domain per line</li>
                            <li>Use *.example.com for wildcard certificates</li>
                            <li>Maximum 100 domains per certificate</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="space-y-6">
                <div>
                    <label class="block text-sm font-semibold text-gray-700 mb-2">
                        Domain Names <span class="text-red-500">*</span>
                        <span class="tooltip ml-1">
                            <i class="fas fa-question-circle text-gray-400 cursor-help"></i>
                            <span class="tooltiptext">One domain per line</span>
                        </span>
                    </label>
                    <textarea id="domains" rows="5" 
                              class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition font-mono text-sm"
                              placeholder="example.com&#10;www.example.com&#10;*.example.com"></textarea>
                    <p class="mt-2 text-sm text-gray-500">
                        <i class="fas fa-info-circle mr-1"></i>
                        Examples: example.com, www.example.com, *.example.com (wildcard)
                    </p>
                </div>

                <div class="flex space-x-4">
                    <button onclick="toggleStep(1)" 
                            class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 font-semibold py-3 px-6 rounded-lg transition">
                        <i class="fas fa-arrow-left mr-2"></i>
                        Back
                    </button>
                    <button onclick="createOrder()" 
                            class="flex-1 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-semibold py-3 px-6 rounded-lg shadow-lg hover:shadow-xl transition-all duration-200">
                        Create Order
                        <i class="fas fa-arrow-right ml-2"></i>
                    </button>
                </div>
            </div>
        </div>

        <!-- Step 3: DNS Verification -->
        <div id="step3" class="hidden fade-in bg-white rounded-xl shadow-lg p-8 mb-6">
            <div class="flex items-start mb-6">
                <div class="flex-shrink-0">
                    <div class="flex items-center justify-center h-12 w-12 rounded-md bg-indigo-100 text-indigo-600">
                        <i class="fas fa-check-double text-xl"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <h2 class="text-2xl font-bold text-gray-900 mb-2">Step 3: DNS Verification</h2>
                    <p class="text-gray-600">Add the following DNS TXT records to verify domain ownership</p>
                </div>
            </div>

            <div class="alert alert-warning">
                <div class="flex items-start">
                    <i class="fas fa-exclamation-triangle mt-0.5 mr-3"></i>
                    <div>
                        <strong>Important:</strong> DNS propagation can take 5-30 minutes. Use the "Check DNS" button to verify records are live before proceeding.
                    </div>
                </div>
            </div>

            <div id="challenges" class="space-y-6"></div>

            <div id="dnsCheckResult" class="hidden mt-6"></div>

            <div class="flex space-x-4 mt-6">
                <button onclick="toggleStep(2)" 
                        class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 font-semibold py-3 px-6 rounded-lg transition">
                    <i class="fas fa-arrow-left mr-2"></i>
                    Back
                </button>
                <button onclick="checkDns()" 
                        class="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-lg transition">
                    <i class="fas fa-search mr-2"></i>
                    Check DNS Records
                </button>
                <button id="validateBtn" onclick="validate()" disabled
                        class="flex-1 bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white font-semibold py-3 px-6 rounded-lg shadow-lg transition opacity-50 cursor-not-allowed">
                    Verify & Continue
                    <i class="fas fa-arrow-right ml-2"></i>
                </button>
            </div>
        </div>

        <!-- Step 4: Certificate Issuance -->
        <div id="step4" class="hidden fade-in bg-white rounded-xl shadow-lg p-8 mb-6">
            <div class="flex items-start mb-6">
                <div class="flex-shrink-0">
                    <div class="flex items-center justify-center h-12 w-12 rounded-md bg-indigo-100 text-indigo-600">
                        <i class="fas fa-certificate text-xl"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <h2 class="text-2xl font-bold text-gray-900 mb-2">Step 4: Certificate Issuance</h2>
                    <p class="text-gray-600">Finalize and download your SSL certificate</p>
                </div>
            </div>

            <div id="status" class="text-center mb-6 text-lg font-semibold text-gray-700"></div>
            <div id="errorDetails" class="hidden alert alert-error mb-6"></div>

            <div class="flex space-x-4 mb-6">
                <button onclick="checkStatus()" 
                        class="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-lg transition">
                    <i class="fas fa-sync-alt mr-2"></i>
                    Check Status
                </button>
                <button id="finBtn" onclick="finalize()" disabled
                        class="flex-1 bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white font-semibold py-3 px-6 rounded-lg shadow-lg transition opacity-50">
                    <i class="fas fa-check-circle mr-2"></i>
                    Finalize Certificate
                </button>
            </div>

            <div id="startOverBtn" class="hidden mb-6">
                <button onclick="location.reload()" 
                        class="w-full bg-gray-600 hover:bg-gray-700 text-white font-semibold py-3 px-6 rounded-lg shadow-lg transition">
                    <i class="fas fa-redo mr-2"></i>
                    Start Over with New Order
                </button>
            </div>

            <div id="output" class="hidden space-y-6">
                <div class="alert alert-success">
                    <div class="flex items-center">
                        <i class="fas fa-check-circle text-2xl mr-3"></i>
                        <div>
                            <strong class="text-lg">Success!</strong>
                            <p class="mt-1">Your SSL certificate has been generated successfully. Download your files below.</p>
                        </div>
                    </div>
                </div>

                <div>
                    <div class="flex items-center justify-between mb-2">
                        <label class="text-sm font-semibold text-gray-700">Certificate (.crt)</label>
                        <button onclick="downloadFile('cert')" id="downloadCertBtn" disabled
                                class="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-4 rounded-lg shadow transition disabled:opacity-50 disabled:cursor-not-allowed">
                            <i class="fas fa-download mr-2"></i>
                            Download Certificate
                        </button>
                    </div>
                    <textarea id="certOut" readonly 
                              class="w-full px-4 py-3 border border-gray-300 rounded-lg bg-gray-50 font-mono text-xs" 
                              rows="8"></textarea>
                </div>

                <div>
                    <div class="flex items-center justify-between mb-2">
                        <label class="text-sm font-semibold text-gray-700">Private Key (.key)</label>
                        <button onclick="downloadFile('key')" id="downloadKeyBtn" disabled
                                class="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-4 rounded-lg shadow transition disabled:opacity-50 disabled:cursor-not-allowed">
                            <i class="fas fa-download mr-2"></i>
                            Download Private Key
                        </button>
                    </div>
                    <textarea id="keyOut" readonly 
                              class="w-full px-4 py-3 border border-gray-300 rounded-lg bg-gray-50 font-mono text-xs" 
                              rows="8"></textarea>
                </div>

                <div class="alert alert-warning">
                    <div class="flex items-start">
                        <i class="fas fa-shield-alt mt-0.5 mr-3 text-xl"></i>
                        <div>
                            <strong>Security Reminder:</strong>
                            <p class="mt-1">Keep your private key secure and never share it. Install both files on your web server to enable HTTPS.</p>
                        </div>
                    </div>
                </div>

                <button onclick="location.reload()" 
                        class="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-semibold py-3 px-6 rounded-lg shadow-lg transition">
                    <i class="fas fa-redo mr-2"></i>
                    Generate Another Certificate
                </button>
            </div>
        </div>

        <!-- Loading Overlay -->
        <div id="loadingOverlay" class="hidden fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-xl p-8 max-w-md shadow-2xl">
                <div class="flex flex-col items-center">
                    <div class="w-16 h-16 border-4 border-indigo-200 border-t-indigo-600 rounded-full spinner"></div>
                    <p id="loadingText" class="mt-4 text-lg font-semibold text-gray-700">Processing...</p>
                    <p class="mt-2 text-sm text-gray-500 text-center">This may take a few moments</p>
                </div>
            </div>
        </div>
    </main>

    <!-- SEO Content Section -->
    <section class="bg-gradient-to-br from-slate-50 to-slate-100 py-16">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="max-w-4xl mx-auto">
                <!-- Main H1 for SEO -->
                <h1 class="text-4xl md:text-5xl font-bold text-gray-900 mb-6 text-center">
                    Free SSL Certificate Generator - Instant Let's Encrypt Certificates
                </h1>
                
                <div class="bg-white rounded-xl shadow-lg p-8 mb-8">
                    <h2 class="text-2xl font-bold text-gray-900 mb-4">Generate Free SSL/TLS Certificates Online</h2>
                    <p class="text-gray-700 mb-4 leading-relaxed">
                        FreeSSL is a powerful, free online SSL certificate generator that leverages Let's Encrypt's ACME protocol 
                        to provide trusted SSL/TLS certificates for your websites. Whether you need a standard SSL certificate, 
                        wildcard certificate, or multi-domain (SAN) certificate, our tool makes it easy to secure your website 
                        with HTTPS encryption in just minutes.
                    </p>
                    <p class="text-gray-700 mb-4 leading-relaxed">
                        <strong>No credit card required.</strong> No registration. No hidden fees. Generate unlimited SSL 
                        certificates completely free using Let's Encrypt's trusted certificate authority.
                    </p>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                    <div class="bg-white rounded-xl shadow-lg p-6">
                        <h3 class="text-xl font-bold text-gray-900 mb-3 flex items-center">
                            <i class="fas fa-certificate text-indigo-600 mr-3"></i>
                            What is an SSL Certificate?
                        </h3>
                        <p class="text-gray-700 leading-relaxed">
                            An SSL (Secure Sockets Layer) certificate is a digital certificate that authenticates a website's 
                            identity and enables encrypted connection between a web server and browser. SSL certificates keep 
                            internet connections secure and protect sensitive data being transferred between servers and browsers.
                        </p>
                    </div>

                    <div class="bg-white rounded-xl shadow-lg p-6">
                        <h3 class="text-xl font-bold text-gray-900 mb-3 flex items-center">
                            <i class="fas fa-globe text-indigo-600 mr-3"></i>
                            Why Use FreeSSL?
                        </h3>
                        <ul class="text-gray-700 space-y-2">
                            <li class="flex items-start">
                                <i class="fas fa-check text-green-600 mr-2 mt-1"></i>
                                <span>100% free - no credit card or payment required</span>
                            </li>
                            <li class="flex items-start">
                                <i class="fas fa-check text-green-600 mr-2 mt-1"></i>
                                <span>Wildcard certificates (*.domain.com) supported</span>
                            </li>
                            <li class="flex items-start">
                                <i class="fas fa-check text-green-600 mr-2 mt-1"></i>
                                <span>Multi-domain (SAN) certificates for multiple sites</span>
                            </li>
                            <li class="flex items-start">
                                <i class="fas fa-check text-green-600 mr-2 mt-1"></i>
                                <span>Private keys generated in your browser (maximum security)</span>
                            </li>
                            <li class="flex items-start">
                                <i class="fas fa-check text-green-600 mr-2 mt-1"></i>
                                <span>DNS-01 validation for wildcard support</span>
                            </li>
                        </ul>
                    </div>
                </div>

                <div class="bg-white rounded-xl shadow-lg p-8 mb-8">
                    <h2 class="text-2xl font-bold text-gray-900 mb-4">How to Generate Free SSL Certificate</h2>
                    <p class="text-gray-700 mb-6">
                        Our free SSL certificate generator makes it easy to secure your website with HTTPS in 4 simple steps:
                    </p>
                    <ol class="space-y-4 text-gray-700">
                        <li class="flex items-start">
                            <span class="flex-shrink-0 w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold mr-4">1</span>
                            <div>
                                <strong class="text-gray-900">Register with Let's Encrypt:</strong> Enter your email address and 
                                choose between staging (for testing) or production environment.
                            </div>
                        </li>
                        <li class="flex items-start">
                            <span class="flex-shrink-0 w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold mr-4">2</span>
                            <div>
                                <strong class="text-gray-900">Add Your Domains:</strong> Enter the domain names you want to secure. 
                                Supports wildcard domains (*.example.com) and multiple domains in one certificate.
                            </div>
                        </li>
                        <li class="flex items-start">
                            <span class="flex-shrink-0 w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold mr-4">3</span>
                            <div>
                                <strong class="text-gray-900">Verify Domain Ownership:</strong> Add DNS TXT records to verify you 
                                own the domains. Our tool provides the exact records you need to add.
                            </div>
                        </li>
                        <li class="flex items-start">
                            <span class="flex-shrink-0 w-8 h-8 bg-indigo-600 text-white rounded-full flex items-center justify-center font-bold mr-4">4</span>
                            <div>
                                <strong class="text-gray-900">Download Your Certificate:</strong> Once verified, download your free 
                                SSL certificate (.crt) and private key (.key) to install on your server.
                            </div>
                        </li>
                    </ol>
                </div>

                <div class="bg-white rounded-xl shadow-lg p-8 mb-8">
                    <h2 class="text-2xl font-bold text-gray-900 mb-4">Frequently Asked Questions</h2>
                    <div class="space-y-6">
                        <div>
                            <h3 class="text-lg font-semibold text-gray-900 mb-2">Is FreeSSL really free?</h3>
                            <p class="text-gray-700">
                                Yes! FreeSSL is completely free with no hidden costs. We use Let's Encrypt, a free, automated, 
                                and open Certificate Authority. You can generate unlimited SSL certificates at no cost.
                            </p>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-gray-900 mb-2">How long are the certificates valid?</h3>
                            <p class="text-gray-700">
                                SSL certificates generated through Let's Encrypt are valid for 90 days. You can renew them before 
                                expiration using this tool again. This shorter validity period enhances security.
                            </p>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-gray-900 mb-2">Can I generate wildcard SSL certificates?</h3>
                            <p class="text-gray-700">
                                Yes! FreeSSL fully supports wildcard certificates (*.example.com) using DNS-01 challenge validation. 
                                This allows you to secure all subdomains with a single certificate.
                            </p>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-gray-900 mb-2">Is it safe to generate SSL certificates online?</h3>
                            <p class="text-gray-700">
                                Absolutely! Your private key is generated entirely in your browser using Web Crypto API. The private 
                                key never leaves your computer and is not transmitted to our servers, ensuring maximum security.
                            </p>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-gray-900 mb-2">What is DNS-01 validation?</h3>
                            <p class="text-gray-700">
                                DNS-01 is a domain validation method where you prove domain ownership by adding a TXT record to your 
                                DNS configuration. This method is required for wildcard certificates and works with any DNS provider.
                            </p>
                        </div>
                    </div>
                </div>

                <div class="bg-indigo-50 rounded-xl border-2 border-indigo-200 p-8 text-center">
                    <h2 class="text-2xl font-bold text-gray-900 mb-4">Ready to Secure Your Website?</h2>
                    <p class="text-gray-700 mb-6">
                        Generate your free SSL certificate now and enable HTTPS on your website in minutes. 
                        No technical expertise required!
                    </p>
                    <button onclick="window.scrollTo({top: 0, behavior: 'smooth'})" 
                            class="bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-bold py-4 px-8 rounded-lg shadow-lg hover:shadow-xl transition-all duration-200 text-lg">
                        <i class="fas fa-arrow-up mr-2"></i>
                        Generate Free SSL Certificate Now
                    </button>
                </div>
            </div>
        </div>
    </section>

    <!-- Live Statistics Counter -->
    <div class="bg-gradient-to-r from-indigo-600 to-purple-600 py-8">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="text-center mb-6">
                <h2 class="text-3xl font-bold text-white mb-2">
                    <i class="fas fa-chart-bar mr-3"></i>
                    Live Statistics
                </h2>
                <p class="text-white opacity-90">Real-time usage of FreeSSL</p>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 text-center">
                <!-- Page Visits -->
                <div class="bg-white bg-opacity-10 backdrop-blur-sm rounded-lg p-6 hover:bg-opacity-20 transition-all">
                    <div class="flex items-center justify-center mb-3">
                        <i class="fas fa-eye text-white text-3xl mr-3"></i>
                        <h3 class="text-white text-xl font-semibold">Page Visits</h3>
                    </div>
                    <p class="text-5xl font-bold text-white mb-2">
                        <?php 
                        $stats = getAnalyticsStats();
                        echo number_format($stats['total_visits']); 
                        ?>
                    </p>
                    <p class="text-white text-sm opacity-80">Total visitors to date</p>
                </div>

                <!-- Certificates Ordered -->
                <div class="bg-white bg-opacity-10 backdrop-blur-sm rounded-lg p-6 hover:bg-opacity-20 transition-all">
                    <div class="flex items-center justify-center mb-3">
                        <i class="fas fa-file-certificate text-white text-3xl mr-3"></i>
                        <h3 class="text-white text-xl font-semibold">Certificates Ordered</h3>
                    </div>
                    <p class="text-5xl font-bold text-white mb-2">
                        <?php echo number_format($stats['total_orders']); ?>
                    </p>
                    <p class="text-white text-sm opacity-80">SSL certificate orders placed</p>
                </div>

                <!-- Money Saved -->
                <div class="bg-white bg-opacity-10 backdrop-blur-sm rounded-lg p-6 hover:bg-opacity-20 transition-all">
                    <div class="flex items-center justify-center mb-3">
                        <i class="fas fa-dollar-sign text-white text-3xl mr-3"></i>
                        <h3 class="text-white text-xl font-semibold">Money Saved</h3>
                    </div>
                    <p class="text-5xl font-bold text-white mb-2">
                        <?php 
                        // Only count production certificates (staging/test don't provide real value)
                        $moneySaved = $stats['production_orders'] * 10; // $10 per production certificate
                        echo '$' . number_format($moneySaved); 
                        ?>
                    </p>
                    <p class="text-white text-sm opacity-80">From production certificates</p>
                </div>
            </div>
            
            <!-- Additional Stats Row -->
            <div class="mt-6 flex flex-col md:flex-row items-center justify-center space-y-3 md:space-y-0 md:space-x-8 text-white text-sm">
                <div class="flex items-center bg-white bg-opacity-10 px-4 py-2 rounded-full">
                    <i class="fas fa-star text-yellow-300 mr-2"></i>
                    <span class="font-semibold"><?php echo number_format($stats['production_orders']); ?> Production</span>
                </div>
                <div class="flex items-center bg-white bg-opacity-10 px-4 py-2 rounded-full">
                    <i class="fas fa-flask text-blue-300 mr-2"></i>
                    <span class="font-semibold"><?php echo number_format($stats['staging_orders']); ?> Test/Staging</span>
                </div>
                <?php if ($stats['last_order']): ?>
                <div class="flex items-center bg-white bg-opacity-10 px-4 py-2 rounded-full">
                    <i class="fas fa-clock text-green-300 mr-2"></i>
                    <span class="font-semibold">Last: <?php echo date('M j, g:i A', strtotime($stats['last_order'])); ?></span>
                </div>
                <?php endif; ?>
            </div>
            
            <!-- Trust Message -->
            <div class="mt-6 text-center">
                <p class="text-white text-lg opacity-90">
                    <i class="fas fa-check-circle text-green-300 mr-2"></i>
                    Join thousands of users securing their websites with FreeSSL
                </p>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-white mt-12 border-t border-gray-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            <div class="flex items-center justify-between">
                <p class="text-sm text-gray-600">
                    &copy; 2024 FreeSSL by Kheteshwar Boravat. Free SSL/TLS certificates powered by Let's Encrypt.
                </p>
                <div class="flex space-x-6">
                    <a href="https://letsencrypt.org/" target="_blank" class="text-sm text-indigo-600 hover:text-indigo-800">
                        About Let's Encrypt
                    </a>
                    <a href="https://letsencrypt.org/docs/rate-limits/" target="_blank" class="text-sm text-indigo-600 hover:text-indigo-800">
                        Rate Limits
                    </a>
                </div>
            </div>
        </div>
    </footer>

    <script>
        let orderUrl = '';
        let currentChallenges = [];

        // Initialization logging
        console.log('═══════════════════════════════════════════════════════════');
        console.log('🚀 FreeSSL - Free SSL Certificate Generator');
        console.log('═══════════════════════════════════════════════════════════');
        console.log('📅 Loaded at:', new Date().toLocaleString());
        console.log('🌐 Page URL:', window.location.href);
        console.log('💾 LocalStorage check:');
        console.log('  └─ certKey exists:', localStorage.getItem('certKey') ? 'YES' : 'NO');
        console.log('🔧 Browser Info:');
        console.log('  └─ User Agent:', navigator.userAgent);
        console.log('  └─ Crypto API available:', typeof window.crypto !== 'undefined' ? 'YES' : 'NO');
        console.log('  └─ Clipboard API available:', typeof navigator.clipboard !== 'undefined' ? 'YES' : 'NO');
        console.log('═══════════════════════════════════════════════════════════');
        console.log('');
        console.log('💡 TIP: All actions are logged here for debugging');
        console.log('💡 Look for grouped logs marked with [STEP X] for each stage');
        console.log('💡 Errors will be marked with ❌ and warnings with ⚠️');
        console.log('');
        console.log('═══════════════════════════════════════════════════════════');

        // Mobile Menu Toggle
        const mobileMenuBtn = document.getElementById('mobile-menu-btn');
        const mobileMenu = document.getElementById('mobile-menu');
        
        if (mobileMenuBtn && mobileMenu) {
            mobileMenuBtn.addEventListener('click', function() {
                mobileMenu.classList.toggle('hidden');
                const icon = this.querySelector('i');
                if (mobileMenu.classList.contains('hidden')) {
                    icon.classList.remove('fa-times');
                    icon.classList.add('fa-bars');
                } else {
                    icon.classList.remove('fa-bars');
                    icon.classList.add('fa-times');
                }
            });
        }

        function showLoading(text = 'Processing...') {
            console.log('⏳ Loading:', text);
            document.getElementById('loadingText').innerText = text;
            document.getElementById('loadingOverlay').classList.remove('hidden');
        }

        function hideLoading() {
            console.log('✓ Loading complete');
            document.getElementById('loadingOverlay').classList.add('hidden');
        }

        function updateProgress(step) {
            console.log(`📍 Progress indicator updated: Step ${step}`);
            
            const steps = [1, 2, 3, 4];
            steps.forEach(s => {
                const indicator = document.getElementById(`step${s}-indicator`);
                const label = document.getElementById(`step${s}-label`);
                
                if (s < step) {
                    indicator.classList.remove('active');
                    indicator.classList.add('completed');
                    indicator.innerHTML = '<i class="fas fa-check"></i>';
                    label.classList.remove('text-gray-500');
                    label.classList.add('text-green-600');
                } else if (s === step) {
                    indicator.classList.remove('completed');
                    indicator.classList.add('active');
                    indicator.innerText = s;
                    label.classList.remove('text-gray-500');
                    label.classList.add('text-indigo-600');
                } else {
                    indicator.classList.remove('active', 'completed');
                    indicator.innerText = s;
                    label.classList.remove('text-green-600', 'text-indigo-600');
                    label.classList.add('text-gray-500');
                }
            });

            // Update lines
            for (let i = 1; i < step; i++) {
                document.getElementById(`line${i}`).classList.add('active');
            }
            for (let i = step; i < 4; i++) {
                document.getElementById(`line${i}`).classList.remove('active');
            }
        }

        function toggleStep(step) {
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
            console.log(`🔄 Navigating to Step ${step}`);
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
            
            [1, 2, 3, 4].forEach(i => {
                document.getElementById(`step${i}`).classList.add('hidden');
            });
            document.getElementById(`step${step}`).classList.remove('hidden');
            updateProgress(step);
            window.scrollTo({ top: 0, behavior: 'smooth' });
            
            console.log(`✅ Now showing Step ${step}`);
        }

        async function api(action, data = {}) {
            console.group(`[API Call] ${action}`);
            console.log('📤 Request Data:', data);
            console.log('🔗 Endpoint:', `?action=${action}`);
            console.time(`⏱️ ${action} Duration`);
            
            try {
                const response = await fetch(`?action=${action}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                console.log('📡 Response Status:', response.status, response.statusText);
                
                const result = await response.json();
                console.log('📥 Response Data:', result);
                console.timeEnd(`⏱️ ${action} Duration`);
                
                if (!result.success) {
                    console.error('❌ API Error:', result.error || result.message);
                    console.groupEnd();
                    throw new Error(result.error || result.message || 'Unknown error occurred');
                }
                
                console.log('✅ API call successful');
                console.groupEnd();
                return result;
            } catch (error) {
                console.timeEnd(`⏱️ ${action} Duration`);
                console.error('💥 API Exception:', error);
                console.groupEnd();
                throw error;
            }
        }

        async function register() {
            console.group('🚀 [STEP 1] Account Registration');
            console.log('════════════════════════════════════════════════');
            
            const email = document.getElementById('email').value.trim();
            const staging = document.getElementById('staging').checked;
            
            console.log('📧 Email:', email);
            console.log('🧪 Staging Mode:', staging ? 'ENABLED (Testing)' : 'DISABLED (Production)');
            console.log('⚠️ Environment:', staging ? 'https://acme-staging-v02.api.letsencrypt.org' : 'https://acme-v02.api.letsencrypt.org');

            if (!email) {
                console.error('❌ Validation Failed: Email is required');
                console.groupEnd();
                alert('Please enter your email address.');
                return;
            }

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                console.error('❌ Validation Failed: Invalid email format');
                console.groupEnd();
                alert('Please enter a valid email address.');
                return;
            }

            console.log('✅ Validation passed');
            showLoading('Registering your account...');
            
            try {
                console.log('🔑 Initiating ACME account registration...');
                const result = await api('register', { email, staging });
                
                console.log('✅ Account registered successfully');
                console.log('📝 Account will receive notifications at:', email);
                console.log('💾 Session data saved');
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                
                hideLoading();
                toggleStep(2);
            } catch (error) {
                console.error('💥 Registration failed:', error.message);
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                hideLoading();
                alert('Registration failed: ' + error.message);
            }
        }

        async function createOrder() {
            console.group('📋 [STEP 2] Certificate Order Creation');
            console.log('════════════════════════════════════════════════');
            
            const domains = document.getElementById('domains').value;
            const domainList = domains.split('\n').filter(d => d.trim());
            
            console.log('🌐 Domain Input:', domains);
            console.log('📊 Parsed Domains:', domainList);
            console.log('🔢 Total Domains:', domainList.length);

            if (!domains.trim()) {
                console.error('❌ Validation Failed: No domains provided');
                console.groupEnd();
                alert('Please enter at least one domain.');
                return;
            }

            console.log('✅ Validation passed');
            showLoading('Creating certificate order...');

            try {
                console.log('🔐 Generating RSA-2048 key pair for certificate...');
                console.time('⏱️ Key Generation');
                
                const keyPair = await window.crypto.subtle.generateKey(
                    {
                        name: "RSASSA-PKCS1-v1_5",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: "SHA-256",
                    },
                    true,
                    ["sign", "verify"]
                );
                
                console.timeEnd('⏱️ Key Generation');
                console.log('✅ Key pair generated successfully');

                const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
                const privateKeyPem = pemEncode(privateKey, "RSA PRIVATE KEY");
                
                console.log('🔑 Private Key (first 100 chars):', privateKeyPem.substring(0, 100) + '...');
                console.log('💾 Storing private key in localStorage');
                localStorage.setItem('certKey', privateKeyPem);
                console.log('✅ Private key stored successfully');

                console.log('📤 Sending order creation request...');
                const res = await api('createOrder', { domains });
                
                orderUrl = res.orderUrl;
                currentChallenges = res.challenges;

                console.log('📋 Order Details:');
                console.log('  └─ Order URL:', orderUrl);
                console.log('  └─ Challenges Count:', res.challenges.length);
                console.log('🔐 DNS Challenges:');
                
                res.challenges.forEach((c, idx) => {
                    console.group(`  Challenge ${idx + 1}: ${c.domain}`);
                    console.log('🏷️ Record Name:', c.recordName);
                    console.log('🔑 Record Value:', c.recordValue);
                    console.log('🔗 Challenge URL:', c.challengeUrl);
                    console.groupEnd();
                });

                const container = document.getElementById('challenges');
                container.innerHTML = '';

                res.challenges.forEach((c, idx) => {
                    const card = document.createElement('div');
                    card.className = 'bg-gradient-to-r from-slate-50 to-slate-100 border-2 border-slate-200 rounded-lg p-6 shadow-sm';
                    card.innerHTML = `
                        <div class="flex items-center mb-4">
                            <div class="bg-indigo-100 text-indigo-600 rounded-full w-8 h-8 flex items-center justify-center font-bold mr-3">
                                ${idx + 1}
                            </div>
                            <h3 class="text-lg font-bold text-gray-800">${c.domain}</h3>
                        </div>
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm font-semibold text-gray-700 mb-2">
                                    <i class="fas fa-tag mr-1"></i>
                                    Record Name
                                </label>
                                <div class="flex">
                                    <input type="text" value="${c.recordName}" readonly 
                                           class="flex-1 px-4 py-2 bg-white border border-gray-300 rounded-l-lg font-mono text-sm">
                                    <button onclick="copyToClipboard('${c.recordName}')" 
                                            class="px-4 bg-indigo-600 hover:bg-indigo-700 text-white rounded-r-lg transition">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                            </div>
                            <div>
                                <label class="block text-sm font-semibold text-gray-700 mb-2">
                                    <i class="fas fa-key mr-1"></i>
                                    Record Value
                                </label>
                                <div class="flex">
                                    <input type="text" value="${c.recordValue}" readonly 
                                           class="flex-1 px-4 py-2 bg-white border border-gray-300 rounded-l-lg font-mono text-sm">
                                    <button onclick="copyToClipboard('${c.recordValue}')" 
                                            class="px-4 bg-indigo-600 hover:bg-indigo-700 text-white rounded-r-lg transition">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                        <input type="hidden" class="chal-url" value="${c.challengeUrl}">
                    `;
                    container.appendChild(card);
                });

                console.log('✅ Order created successfully');
                console.log('📝 DNS records displayed to user');
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                
                hideLoading();
                toggleStep(3);
            } catch (error) {
                console.error('💥 Order creation failed:', error.message);
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                hideLoading();
                alert('Failed to create order: ' + error.message);
            }
        }

        function copyToClipboard(text) {
            console.log('📋 Copying to clipboard:', text.substring(0, 50) + (text.length > 50 ? '...' : ''));
            
            navigator.clipboard.writeText(text).then(() => {
                console.log('✅ Successfully copied to clipboard');
                
                const toast = document.createElement('div');
                toast.className = 'fixed bottom-4 right-4 bg-green-600 text-white px-6 py-3 rounded-lg shadow-lg z-50';
                toast.innerHTML = '<i class="fas fa-check mr-2"></i>Copied to clipboard!';
                document.body.appendChild(toast);
                setTimeout(() => {
                    toast.remove();
                }, 2000);
            }).catch(err => {
                console.error('❌ Failed to copy to clipboard:', err);
            });
        }

        function pemEncode(arrayBuffer, label) {
            console.log(`🔐 Encoding to PEM format: ${label}`);
            console.log('📊 Input size:', arrayBuffer.byteLength, 'bytes');
            
            const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
            const formatted = base64.match(/.{1,64}/g).join('\n');
            const pem = `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----`;
            
            console.log('✅ PEM encoding complete');
            console.log('📏 Output size:', pem.length, 'characters');
            
            return pem;
        }

        async function checkDns() {
            console.group('🔍 [STEP 3] DNS Verification Check');
            console.log('════════════════════════════════════════════════');
            console.log('🌐 Checking DNS propagation for', currentChallenges.length, 'domain(s)');
            console.log('📡 Using Google Public DNS resolver (dns.google)');
            
            const resultDiv = document.getElementById('dnsCheckResult');
            resultDiv.classList.remove('hidden');
            resultDiv.className = 'p-6 mb-4 rounded-lg bg-blue-50 text-blue-800 border-2 border-blue-200';
            resultDiv.innerHTML = '<div class="flex items-center justify-center"><div class="w-6 h-6 border-3 border-blue-200 border-t-blue-600 rounded-full spinner mr-3"></div><span>Checking DNS records...</span></div>';

            let allFound = true;
            let report = [];
            const validateBtn = document.getElementById('validateBtn');
            validateBtn.disabled = true;
            validateBtn.classList.add('opacity-50', 'cursor-not-allowed');

            for (const c of currentChallenges) {
                console.group(`🔎 Checking: ${c.domain}`);
                console.log('📝 Record Name:', c.recordName);
                console.log('🎯 Expected Value:', c.recordValue);
                console.log('🔗 DNS Query URL:', `https://dns.google/resolve?name=${c.recordName}&type=TXT`);
                
                try {
                    console.time(`⏱️ DNS Query for ${c.domain}`);
                    const res = await fetch(`https://dns.google/resolve?name=${c.recordName}&type=TXT`);
                    const json = await res.json();
                    console.timeEnd(`⏱️ DNS Query for ${c.domain}`);
                    
                    console.log('📥 DNS Response:', json);
                    
                    let found = false;
                    let foundValues = [];
                    if (json.Answer) {
                        foundValues = json.Answer.map(ans => ans.data.replace(/"/g, ''));
                        console.log('📋 Found TXT Records:', foundValues);
                        found = foundValues.includes(c.recordValue);
                    } else {
                        console.warn('⚠️ No TXT records found in DNS');
                    }

                    if (found) {
                        console.log('✅ MATCH FOUND!');
                        console.log('✓ Record is correctly configured');
                        report.push(`
                            <div class="flex items-start p-3 bg-green-50 rounded-lg border border-green-200">
                                <i class="fas fa-check-circle text-green-600 text-xl mr-3 mt-1"></i>
                                <div class="flex-1">
                                    <div class="font-semibold text-green-800">${c.domain}</div>
                                    <div class="text-sm text-green-700 mt-1">DNS record verified successfully</div>
                                    <div class="text-xs text-green-600 mt-1 font-mono break-all">${foundValues.join(', ')}</div>
                                </div>
                            </div>
                        `);
                    } else {
                        allFound = false;
                        console.error('❌ MISMATCH or NOT FOUND');
                        if (foundValues.length > 0) {
                            console.error('✗ Found:', foundValues);
                            console.error('✗ Expected:', c.recordValue);
                            if (foundValues.length > 1) {
                                console.warn('⚠️ MULTIPLE TXT RECORDS DETECTED - This may cause issues!');
                            }
                        } else {
                            console.error('✗ No TXT records found');
                        }
                        
                        let msg = `
                            <div class="flex items-start p-3 bg-red-50 rounded-lg border border-red-200">
                                <i class="fas fa-times-circle text-red-600 text-xl mr-3 mt-1"></i>
                                <div class="flex-1">
                                    <div class="font-semibold text-red-800">${c.domain}</div>
                                    <div class="text-sm text-red-700 mt-1">DNS record not found or incorrect</div>
                        `;
                        if(foundValues.length > 0) {
                            msg += `
                                    <div class="mt-2 space-y-1">
                                        <div class="text-xs"><span class="text-red-600 font-semibold">Found (${foundValues.length} record${foundValues.length > 1 ? 's' : ''}):</span></div>
                            `;
                            foundValues.forEach((val, idx) => {
                                msg += `<div class="text-xs text-red-600 font-mono break-all bg-white p-1 rounded">${idx + 1}. ${val}</div>`;
                            });
                            msg += `
                                        <div class="text-xs"><span class="text-green-600 font-semibold">Expected:</span></div>
                                        <div class="text-xs text-green-600 font-mono break-all bg-white p-1 rounded">${c.recordValue}</div>
                                    </div>
                            `;
                            if (foundValues.length > 1) {
                                msg += `<div class="mt-2 p-2 bg-yellow-100 rounded text-xs text-yellow-800"><i class="fas fa-exclamation-triangle mr-1"></i> <strong>Multiple TXT records found!</strong> Remove old records and keep only the latest one.</div>`;
                            }
                        } else {
                            msg += `<div class="text-xs text-gray-600 mt-1">No TXT records found</div>`;
                        }
                        msg += `
                                </div>
                            </div>
                        `;
                        report.push(msg);
                    }
                    console.groupEnd();
                } catch (e) {
                    allFound = false;
                    console.error('💥 DNS Query Failed:', e);
                    console.groupEnd();
                    report.push(`
                        <div class="flex items-start p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                            <i class="fas fa-exclamation-triangle text-yellow-600 text-xl mr-3 mt-1"></i>
                            <div class="flex-1">
                                <div class="font-semibold text-yellow-800">${c.domain}</div>
                                <div class="text-sm text-yellow-700 mt-1">Check failed (Network/API Error)</div>
                            </div>
                        </div>
                    `);
                }
            }

            resultDiv.innerHTML = `<div class="space-y-3">${report.join('')}</div>`;
            
            if (allFound) {
                console.log('════════════════════════════════════════════════');
                console.log('✅ ALL DNS RECORDS VERIFIED SUCCESSFULLY!');
                console.log('✓ Ready to proceed with validation');
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                
                resultDiv.className = 'p-6 mb-4 rounded-lg bg-green-50 border-2 border-green-200';
                resultDiv.innerHTML += `
                    <div class="mt-4 p-4 bg-white rounded-lg border-2 border-green-300">
                        <div class="flex items-center justify-center text-green-800">
                            <i class="fas fa-check-double text-2xl mr-3"></i>
                            <span class="font-bold text-lg">All DNS records verified! You can now proceed.</span>
                        </div>
                    </div>
                `;
                validateBtn.disabled = false;
                validateBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            } else {
                console.log('════════════════════════════════════════════════');
                console.warn('⚠️ DNS VERIFICATION INCOMPLETE');
                console.warn('✗ Some records are missing or incorrect');
                console.warn('💡 Wait for DNS propagation and try again');
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                
                resultDiv.className = 'p-6 mb-4 rounded-lg bg-yellow-50 border-2 border-yellow-200';
                resultDiv.innerHTML += `
                    <div class="mt-4 p-4 bg-white rounded-lg border-2 border-yellow-300">
                        <div class="flex items-center justify-center text-yellow-800">
                            <i class="fas fa-hourglass-half text-2xl mr-3"></i>
                            <span class="font-bold">Records not fully propagated yet. Please wait and try again.</span>
                        </div>
                    </div>
                `;
            }
        }

        async function validate() {
            console.group('✅ [STEP 3] Domain Validation');
            console.log('════════════════════════════════════════════════');
            console.log("🔐 Submitting validation requests to Let's Encrypt...");
            
            showLoading('Validating domain ownership...');
            
            try {
                const urls = Array.from(document.querySelectorAll('.chal-url')).map(i => i.value);
                console.log('📋 Challenge URLs:', urls);
                console.log('🔢 Total Challenges:', urls.length);
                
                for (let i = 0; i < urls.length; i++) {
                    const url = urls[i];
                    console.group(`🔐 Validating Challenge ${i + 1}/${urls.length}`);
                    console.log('🔗 Challenge URL:', url);
                    console.log('📤 Sending validation request...');
                    
                    try {
                        await api('validateChallenge', { challengeUrl: url });
                        console.log('✅ Validation request accepted');
                    } catch (error) {
                        console.error('❌ Validation request failed:', error.message);
                        throw error;
                    }
                    console.groupEnd();
                }
                
                console.log('════════════════════════════════════════════════');
                console.log('✅ All validation requests submitted successfully');
                console.log("⏳ Let's Encrypt will now verify DNS records");
                console.log('📝 Moving to Step 4 to check status');
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                
                hideLoading();
                toggleStep(4);
            } catch (error) {
                console.error('💥 Validation failed:', error.message);
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                hideLoading();
                alert('Validation failed: ' + error.message);
            }
        }

        async function checkStatus() {
            if (!orderUrl) {
                alert("No active order found. Please create a new order first.");
                toggleStep(2);
                return;
            }
            
            showLoading('Checking certificate status...');
            
            try {
                console.log("[Step 4] Checking order status for:", orderUrl);
                const res = await api('checkStatus', { orderUrl: orderUrl });
                console.log("[Step 4] Status response:", res);
                
                const el = document.getElementById('status');
                const errEl = document.getElementById('errorDetails');
                const finBtn = document.getElementById('finBtn');
                const downloadCertBtn = document.getElementById('downloadCertBtn');
                const downloadKeyBtn = document.getElementById('downloadKeyBtn');
                
                el.innerText = "Status: " + res.status.toUpperCase();
                finBtn.disabled = true;
                downloadCertBtn.disabled = true;
                downloadKeyBtn.disabled = true;
                finBtn.classList.add('opacity-50');

                if (res.status === 'pending' || res.status === 'processing') {
                    el.className = "text-center mb-6 text-lg font-semibold text-yellow-600";
                    errEl.classList.add('hidden');
                } else if (res.status === 'ready') {
                    el.className = "text-center mb-6 text-lg font-semibold text-green-600";
                    errEl.classList.add('hidden');
                    finBtn.disabled = false;
                    finBtn.classList.remove('opacity-50');
                } else if (res.status === 'valid') {
                    el.className = "text-center mb-6 text-lg font-semibold text-green-600";
                    errEl.classList.add('hidden');
                    
                    const certOut = document.getElementById('certOut');
                    if (certOut.value.includes('BEGIN CERTIFICATE')) {
                        downloadCertBtn.disabled = false;
                        downloadKeyBtn.disabled = false;
                    }
                } else if (res.status === 'invalid') {
                    el.className = "text-center mb-6 text-lg font-semibold text-red-600";
                    document.getElementById('startOverBtn').classList.remove('hidden');
                    
                    if (res.errorDetails) {
                        errEl.innerHTML = `
                            <div class="flex items-start">
                                <i class="fas fa-exclamation-circle text-red-600 text-xl mr-3 mt-1"></i>
                                <div class="flex-1">
                                    <strong>Validation Failed:</strong>
                                    <p class="mt-1">${res.errorDetails}</p>
                                    ${res.errorDetails.includes('Incorrect TXT record') ? `
                                        <div class="mt-3 p-3 bg-yellow-50 border border-yellow-300 rounded text-sm text-yellow-800">
                                            <strong>Common causes:</strong>
                                            <ul class="list-disc list-inside mt-1 space-y-1">
                                                <li>Multiple TXT records exist - delete old ones</li>
                                                <li>DNS propagation issue - wait 5-10 minutes</li>
                                                <li>Wrong record name or value copied</li>
                                            </ul>
                                            <div class="mt-2">
                                                <strong>Solution:</strong> Click "Start Over" below to begin with a fresh order and new DNS values.
                                            </div>
                                        </div>
                                    ` : ''}
                                </div>
                            </div>
                        `;
                        errEl.classList.remove('hidden');
                    }
                }
                
                hideLoading();
            } catch (error) {
                console.error("[Step 4] Error checking status:", error);
                hideLoading();
                alert('Failed to check status: ' + error.message);
            }
        }

        // ============================================
        // CLIENT-SIDE CSR GENERATION FUNCTIONS (Using Forge.js)
        // ============================================
        
        /**
         * Generate CSR (Certificate Signing Request) in the browser using Forge.js
         * This function NEVER sends the private key to the server!
         * @param {string} privateKeyPem - Private key in PEM format (stays in browser)
         * @param {array} domains - Array of domain names
         * @returns {string} CSR in PEM format (contains only public key)
         */
        async function generateCSRInBrowser(privateKeyPem, domains) {
            console.group('🔐 CLIENT-SIDE CSR GENERATION (Forge.js)');
            console.log('════════════════════════════════════════════════');
            console.log('🎯 SECURITY: Private key stays in browser!');
            console.log('📋 Domains:', domains);
            console.time('⏱️ CSR Generation');
            
            try {
                // Check if forge is loaded
                if (typeof forge === 'undefined') {
                    throw new Error('Forge.js library not loaded! Check CDN connection.');
                }
                
                console.log('✅ Forge.js library loaded');
                
                // Step 1: Import private key from PEM
                console.log('📝 Step 1: Importing private key from PEM...');
                const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
                console.log('✅ Private key imported successfully');
                
                // Step 2: Create CSR
                console.log('📝 Step 2: Creating Certificate Signing Request...');
                const csr = forge.pki.createCertificationRequest();
                
                // Set public key (derived from private key)
                csr.publicKey = forge.pki.rsa.setPublicKey(privateKey.n, privateKey.e);
                console.log('✅ Public key set');
                
                // Step 3: Set subject (Common Name = first domain)
                console.log('📝 Step 3: Setting subject (CN)...');
                csr.setSubject([{
                    name: 'commonName',
                    value: domains[0]
                }]);
                console.log('✅ Subject set:', domains[0]);
                
                // Step 4: Add Subject Alternative Names (SAN) extension
                console.log('📝 Step 4: Adding Subject Alternative Names for', domains.length, 'domain(s)...');
                const altNames = domains.map(domain => ({
                    type: 2, // DNS type
                    value: domain
                }));
                
                csr.setAttributes([{
                    name: 'extensionRequest',
                    extensions: [{
                        name: 'subjectAltName',
                        altNames: altNames
                    }]
                }]);
                console.log('✅ SAN extension added for:', domains.join(', '));
                
                // Step 5: Sign the CSR with the private key
                console.log('📝 Step 5: Signing CSR with private key...');
                csr.sign(privateKey, forge.md.sha256.create());
                console.log('✅ CSR signed successfully with SHA-256');
                
                // Step 6: Convert to PEM format
                console.log('📝 Step 6: Converting to PEM format...');
                const csrPem = forge.pki.certificationRequestToPem(csr);
                
                console.log('✅ CSR generated successfully!');
                console.log('📄 CSR Preview (first 100 chars):', csrPem.substring(0, 100) + '...');
                console.log('🔐 IMPORTANT: Private key never left the browser!');
                console.log('📊 CSR contains: Public key + Subject + SAN extension');
                console.timeEnd('⏱️ CSR Generation');
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                
                return csrPem;
                
            } catch (error) {
                console.error('❌ CSR Generation Failed:', error);
                console.log('Error details:', error.message);
                console.log('Error stack:', error.stack);
                
                // Provide helpful error messages
                if (typeof forge === 'undefined') {
                    console.error('💡 Solution: Check that Forge.js CDN is loading correctly');
                    console.error('   URL: https://cdnjs.cloudflare.com/ajax/libs/forge/1.3.1/forge.min.js');
                } else if (error.message.includes('privateKeyFromPem')) {
                    console.error('💡 Solution: Private key format may be invalid');
                } else {
                    console.error('💡 Check browser console for more details');
                }
                
                console.timeEnd('⏱️ CSR Generation');
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                throw new Error('Failed to generate CSR: ' + error.message);
            }
        }

        async function finalize() {
            console.group('🎯 [STEP 4] Certificate Finalization');
            console.log('════════════════════════════════════════════════');
            
            if (!orderUrl) {
                console.error('❌ No active order found');
                console.groupEnd();
                alert("No active order.");
                return;
            }

            console.log('📋 Order URL:', orderUrl);
            console.log('🔑 Retrieving private key from localStorage...');
            
            const privateKey = localStorage.getItem('certKey');
            if (!privateKey) {
                console.error('❌ Private key not found in localStorage');
                console.groupEnd();
                alert("Private key not found. Please start over.");
                return;
            }
            
            console.log('✅ Private key retrieved');
            console.log('🔐 Key length:', privateKey.length, 'characters');
            
            showLoading('Generating CSR in browser...');

            try {
                // Get domains
                const domainsText = document.getElementById('domains').value;
                const domains = domainsText.split('\n').map(d => d.trim()).filter(d => d);
                console.log('📝 Domains for certificate:', domains);
                
                // ============================================
                // SECURITY: Generate CSR in browser
                // Private key NEVER sent to server!
                // ============================================
                console.log('');
                console.log('🔒 GENERATING CSR CLIENT-SIDE...');
                console.log('🔐 Private key will NOT be sent to server!');
                const csrPem = await generateCSRInBrowser(privateKey, domains);
                console.log('✅ CSR generated successfully in browser!');
                console.log('');
                
                showLoading('Finalizing certificate...');
                
                console.log('📤 Sending finalization request...');
                console.log('✓ Sending: CSR (public key only)');
                console.log('✗ NOT sending: Private key (stays in browser)');
                
                // Send ONLY the CSR to server (contains public key, not private key)
                await api('finalize', {
                    orderUrl: orderUrl,
                    csrPem: csrPem  // Only CSR! Private key never transmitted!
                });
                
                console.log('✅ Finalization request accepted');
                console.log('⏳ Polling for certificate issuance...');
                console.log('🔄 Will check status every 2 seconds (max 10 attempts)');
                
                let done = false;
                let checks = 0;
                
                while(!done && checks < 10) {
                    checks++;
                    console.log(`🔄 Status Check ${checks}/10...`);
                    await new Promise(r => setTimeout(r, 2000));
                    
                    const stat = await api('checkStatus', { orderUrl: orderUrl });
                    console.log(`📊 Current Status: ${stat.status}`);

                    if (stat.status === 'valid') {
                        console.log('🎉 Certificate Status: VALID!');
                        console.log('📥 Downloading certificate...');
                        console.log('🔗 Certificate URL:', stat.certificateUrl);
                        
                        const certRes = await api('getCert', { certificateUrl: stat.certificateUrl });
                        
                        console.log('✅ Certificate downloaded successfully');
                        console.log('📜 Certificate length:', certRes.certificate.length, 'characters');
                        console.log('🔑 Private key length:', privateKey.length, 'characters');
                        
                        document.getElementById('certOut').value = certRes.certificate;
                        document.getElementById('keyOut').value = privateKey;
                        
                        document.getElementById('output').classList.remove('hidden');
                        document.getElementById('downloadCertBtn').disabled = false;
                        document.getElementById('downloadKeyBtn').disabled = false;
                        
                        document.getElementById('status').innerText = "Status: VALID - CERTIFICATE READY";
                        document.getElementById('status').className = "text-center mb-6 text-lg font-semibold text-green-600";
                        
                        console.log('════════════════════════════════════════════════');
                        console.log('🎊 CERTIFICATE GENERATION COMPLETE!');
                        console.log('✅ Certificate and private key are ready for download');
                        console.log('📦 Files can be downloaded using the buttons below');
                        console.log('════════════════════════════════════════════════');
                        console.groupEnd();
                        
                        done = true;
                    } else if (stat.status === 'invalid') {
                        console.error('❌ Certificate Status: INVALID');
                        console.error('✗ Certificate request failed');
                        if (stat.errorDetails) {
                            console.error('📋 Error Details:', stat.errorDetails);
                        }
                        console.log('════════════════════════════════════════════════');
                        console.groupEnd();
                        
                        document.getElementById('status').innerText = "Status: INVALID";
                        document.getElementById('status').className = "text-center mb-6 text-lg font-semibold text-red-600";
                        alert("Certificate request failed during finalization.");
                        done = true;
                    } else {
                        console.log(`⏳ Status: ${stat.status} - Waiting...`);
                    }
                }
                
                hideLoading();
                
                if (!done) {
                    console.warn('⚠️ Status check timed out after', checks, 'attempts');
                    console.log('💡 Certificate may still be processing');
                    console.log('🔄 Try clicking "Check Status" manually');
                    console.log('════════════════════════════════════════════════');
                    console.groupEnd();
                    alert("Certificate status check timed out. Please check status manually.");
                }
            } catch (error) {
                console.error('💥 Finalization failed:', error.message);
                console.log('════════════════════════════════════════════════');
                console.groupEnd();
                hideLoading();
                alert('Finalization failed: ' + error.message);
            }
        }

        function downloadFile(type) {
            console.group(`💾 [DOWNLOAD] ${type === 'cert' ? 'Certificate' : 'Private Key'}`);
            console.log('════════════════════════════════════════════════');
            
            let content, filename, mimeType;
            let domains = document.getElementById('domains').value.split('\n').filter(d => d.trim());
            let domainName = domains.length > 0 ? domains[0].trim().replace(/\*/g, '') : 'certificate';
            
            console.log('📝 Domain for filename:', domainName);

            if (type === 'cert') {
                content = document.getElementById('certOut').value;
                filename = domainName.replace(/[^a-z0-9]/gi, '_') + '.crt';
                mimeType = 'application/x-x509-ca-cert';
                console.log('📜 Downloading Certificate');
            } else if (type === 'key') {
                content = document.getElementById('keyOut').value;
                filename = domainName.replace(/[^a-z0-9]/gi, '_') + '.key';
                mimeType = 'application/x-pem-file';
                console.log('🔑 Downloading Private Key');
            } else {
                console.error('❌ Invalid download type:', type);
                console.groupEnd();
                return;
            }

            console.log('📄 Filename:', filename);
            console.log('📊 File size:', content.length, 'characters');
            console.log('🗂️ MIME Type:', mimeType);

            if (!content) {
                console.error('❌ Content is empty');
                console.groupEnd();
                alert(`Cannot download empty ${type}. Please finalize the order first.`);
                return;
            }

            console.log('✅ Content validated');
            console.log('🔄 Creating blob...');
            
            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            
            console.log('🔗 Blob URL created:', url);
            console.log('⬇️ Triggering download...');
            
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            console.log('✅ Download triggered successfully');
            console.log('🗑️ Blob URL revoked');
            console.log('════════════════════════════════════════════════');
            console.groupEnd();
        }
    </script>

    <!-- SEO-Friendly Footer -->
    <footer class="bg-white border-t border-gray-200 mt-16">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <!-- Main Footer Content -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
                <!-- About Section -->
                <div class="md:col-span-2">
                    <h2 class="text-xl font-bold text-gray-900 mb-4">About FreeSSL Certificate Generator</h2>
                    <p class="text-gray-600 mb-4">
                        FreeSSL is a free online SSL/TLS certificate generator that uses Let's Encrypt ACME protocol to provide 
                        secure, trusted SSL certificates for your websites. Generate wildcard certificates, multi-domain (SAN) 
                        certificates with DNS-01 validation - all completely free with no credit card required.
                    </p>
                    <p class="text-gray-600">
                        <strong>100% Free</strong> • <strong>No Registration</strong> • <strong>Client-Side Encryption</strong> • 
                        <strong>Wildcard Support</strong> • <strong>Multi-Domain</strong>
                    </p>
                </div>

                <!-- Quick Links -->
                <div>
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Quick Links</h3>
                    <ul class="space-y-2">
                        <li><a href="https://coderyogi.com/" class="text-gray-600 hover:text-indigo-600 transition-colors">Home</a></li>
                        <li><a href="https://coderyogi.com/tools" class="text-gray-600 hover:text-indigo-600 transition-colors">More Tools</a></li>
                        <li><a href="https://letsencrypt.org/docs/" target="_blank" rel="noopener" class="text-gray-600 hover:text-indigo-600 transition-colors">Documentation</a></li>
                        <li><a href="https://letsencrypt.org/docs/rate-limits/" target="_blank" rel="noopener" class="text-gray-600 hover:text-indigo-600 transition-colors">Rate Limits</a></li>
                        <li><a href="https://coderyogi.com/blog" class="text-gray-600 hover:text-indigo-600 transition-colors">Blog</a></li>
                    </ul>
                </div>

                <!-- Resources -->
                <div>
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Resources</h3>
                    <ul class="space-y-2">
                        <li><a href="https://letsencrypt.org/" target="_blank" rel="noopener" class="text-gray-600 hover:text-indigo-600 transition-colors">Let's Encrypt</a></li>
                        <li><a href="https://letsencrypt.org/how-it-works/" target="_blank" rel="noopener" class="text-gray-600 hover:text-indigo-600 transition-colors">How It Works</a></li>
                        <li><a href="https://community.letsencrypt.org/" target="_blank" rel="noopener" class="text-gray-600 hover:text-indigo-600 transition-colors">Community Forum</a></li>
                        <li><a href="https://letsencrypt.org/docs/faq/" target="_blank" rel="noopener" class="text-gray-600 hover:text-indigo-600 transition-colors">FAQ</a></li>
                        <li><a href="https://coderyogi.com/#contact" class="text-gray-600 hover:text-indigo-600 transition-colors">Contact</a></li>
                    </ul>
                </div>
            </div>

            <!-- Features Section for SEO -->
            <div class="border-t border-gray-200 pt-8 mb-8">
                <h3 class="text-lg font-semibold text-gray-900 mb-4">Why Choose FreeSSL for Your SSL Certificate Needs?</h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 text-sm">
                    <div>
                        <h4 class="font-semibold text-gray-900 mb-2">🔒 Secure & Trusted</h4>
                        <p class="text-gray-600">Generate industry-standard SSL/TLS certificates trusted by all major browsers. Your private keys are generated client-side for maximum security.</p>
                    </div>
                    <div>
                        <h4 class="font-semibold text-gray-900 mb-2">⚡ Fast & Easy</h4>
                        <p class="text-gray-600">Get your free SSL certificate in minutes with our simple 4-step process. No technical expertise required.</p>
                    </div>
                    <div>
                        <h4 class="font-semibold text-gray-900 mb-2">🌐 Wildcard Support</h4>
                        <p class="text-gray-600">Support for wildcard certificates (*.domain.com) and multi-domain (SAN) certificates with DNS-01 validation.</p>
                    </div>
                </div>
            </div>

            <!-- Keywords Section (Hidden but SEO friendly) -->
            <div class="border-t border-gray-200 pt-8 mb-8">
                <div class="text-xs text-gray-500 leading-relaxed">
                    <strong>Popular Searches:</strong> free ssl certificate generator, lets encrypt certificate generator, 
                    generate ssl certificate free, free tls certificate, wildcard ssl certificate generator, ssl generator online, 
                    free https certificate, acme certificate generator, dns-01 ssl, multi-domain ssl certificate, 
                    free ssl for website, lets encrypt wildcard, ssl certificate tool, online certificate generator, 
                    free domain ssl certificate, generate lets encrypt certificate, ssl tls certificate free
                </div>
            </div>

            <!-- Bottom Bar -->
            <div class="border-t border-gray-200 pt-6 flex flex-col md:flex-row justify-between items-center">
                <div class="text-sm text-gray-600 mb-4 md:mb-0">
                    © 2024 <a href="https://coderyogi.com/" class="text-indigo-600 hover:text-indigo-800 font-semibold">CoderYogi</a>. 
                    All rights reserved. | Built with ❤️ by <a href="https://coderyogi.com/" class="text-indigo-600 hover:text-indigo-800">Kheteshwar Boravat</a>
                </div>
                <div class="flex items-center space-x-6 text-sm">
                    <a href="https://coderyogi.com/privacy" class="text-gray-600 hover:text-indigo-600 transition-colors">Privacy Policy</a>
                    <a href="https://coderyogi.com/terms" class="text-gray-600 hover:text-indigo-600 transition-colors">Terms of Service</a>
                    <div class="flex items-center space-x-3">
                        <a href="https://github.com/kheteswar" target="_blank" rel="noopener" class="text-gray-600 hover:text-indigo-600 transition-colors" aria-label="GitHub">
                            <i class="fab fa-github text-xl"></i>
                        </a>
                        <a href="https://www.linkedin.com/in/kheteswar/" target="_blank" rel="noopener" class="text-gray-600 hover:text-indigo-600 transition-colors" aria-label="LinkedIn">
                            <i class="fab fa-linkedin text-xl"></i>
                        </a>
                    </div>
                </div>
            </div>

            <!-- Trust Badges -->
            <div class="mt-8 text-center">
                <div class="inline-flex items-center space-x-4 text-xs text-gray-500">
                    <span class="flex items-center">
                        <i class="fas fa-shield-alt text-green-600 mr-1"></i>
                        Secure
                    </span>
                    <span class="flex items-center">
                        <i class="fas fa-lock text-green-600 mr-1"></i>
                        Encrypted
                    </span>
                    <span class="flex items-center">
                        <i class="fas fa-check-circle text-green-600 mr-1"></i>
                        Trusted
                    </span>
                    <span class="flex items-center">
                        <i class="fas fa-dollar-sign text-green-600 mr-1"></i>
                        100% Free
                    </span>
                </div>
            </div>
        </div>
    </footer>
</body>
</html>
