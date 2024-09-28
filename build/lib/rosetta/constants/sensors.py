ACTIONS = ["Allow", "Deny", "Drop", "Wait", "Log"]
PROTOCOLS = ["TCP", "UDP", "HTTP", "SSL", "SQL", "SSH", "FTP", "RTP", "RDP"]
TECHNIQUES = [
    {
        "technique": "Injection",
        "indicator": "https://example.com/login.php?username=admin' OR 1=1 --&password=pass",
        "mechanism": "Web-POST"
    },
    {
        "technique": "Broken Authentication and Session Management",
        "indicator": "https://example.com/admin.php?sessionid=12345",
        "mechanism": "Web-POST"
    },
    {
        "technique": "Cross-Site Scripting (XSS)",
        "indicator": "https://example.com/search.php?q=<script>alert('xss')</script>",
        "mechanism": "Web-GET"
    },
    {
        "technique": "Broken Access Control",
        "indicator": "https://example.com/user/profile.php?id=1234' OR 1=1 --&password=pass",
        "mechanism": "Web-GET"
    },
    {
        "technique": "Security Misconfiguration",
        "indicator": "https://example.com/index.php",
        "mechanism": "Web-GET"
    },
    {
        "technique": "Insecure Cryptographic Storage",
        "indicator": "https://example.com/checkout.php?ccnum=1234567890",
        "mechanism": "Web-POST"
    },
    {
        "technique": "Insufficient Transport Layer Protection",
        "indicator": "http://example.com/login.php",
        "mechanism": "Web-GET"
    },
    {
        "technique": "Unvalidated Redirects and Forwards",
        "indicator": "https://example.com/redirect.php?to=http://malicious.com",
        "mechanism": "Web-GET"
    },
    {
        "technique": "Using Components with Known Vulnerabilities",
        "indicator": "https://example.com/assets/jquery-1.11.1.js",
        "mechanism": "Web-GET"
    },
    {
        "technique": "Insufficient Logging and Monitoring",
        "indicator": "https://example.com/login.php?username=admin&password=pass",
        "mechanism": "Web-POST"
    }
]
ERROR_CODE = [200, 403, 404, 500]
