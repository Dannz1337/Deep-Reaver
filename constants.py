# constants.py

COMMON_DIRECTORIES = [
    'admin', 'backup', 'config', 'download', 'logs', 
    'secret', 'uploads', 'wp-admin', 'wp-content'
]

COMMON_FILES = [
    'config.php', '.env', 'wp-config.php', 'robots.txt',
    'backup.zip', 'credentials.txt', 'database.sql'
]

WAF_SIGNATURES = {
    'Cloudflare': 'cloudflare',
    'Akamai': 'akamai',
    'ModSecurity': 'mod_security',
    'Imperva': 'imperva',
    'AWS WAF': 'aws-waf'
}
