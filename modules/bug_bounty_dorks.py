"""
Bug Bounty Dork Templates
Comprehensive Google Dork library specifically for bug bounty hunting
"""

def get_bug_bounty_dorks(domain):
    """
    Returns a comprehensive list of Google Dorks for the target domain.
    These dorks are designed to find sensitive exposures commonly found during bug bounty hunting.
    """
    
    dorks = []
    
    # Admin panels and login pages
    admin_dorks = [
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} inurl:administrator',
        f'site:{domain} inurl:auth',
        f'site:{domain} intitle:"admin panel"',
        f'site:{domain} intitle:"login page"',
        f'site:{domain} inurl:wp-admin',
        f'site:{domain} inurl:controlpanel',
        f'site:{domain} inurl:admincp',
    ]
    
    # Configuration files
    config_dorks = [
        f'site:{domain} ext:env',
        f'site:{domain} ext:ini',
        f'site:{domain} ext:config',
        f'site:{domain} ext:conf',
        f'site:{domain} inurl:config',
        f'site:{domain} intitle:"index of" config',
        f'site:{domain} filetype:env "DB_PASSWORD"',
        f'site:{domain} filetype:ini "password"',
        f'site:{domain} inurl:web.config',
        f'site:{domain} ext:cfg',
    ]
    
    # Database files and backups
    database_dorks = [
        f'site:{domain} ext:sql',
        f'site:{domain} ext:db',
        f'site:{domain} ext:dbf',
        f'site:{domain} ext:mdb',
        f'site:{domain} inurl:backup',
        f'site:{domain} inurl:dump',
        f'site:{domain} filetype:sql "INSERT INTO"',
        f'site:{domain} filetype:sql "CREATE TABLE"',
        f'site:{domain} intitle:"index of" backup',
        f'site:{domain} ext:bak',
        f'site:{domain} ext:backup',
    ]
    
    # Log files
    log_dorks = [
        f'site:{domain} ext:log',
        f'site:{domain} filetype:log',
        f'site:{domain} inurl:log',
        f'site:{domain} intitle:"index of" logs',
        f'site:{domain} filetype:log "password"',
        f'site:{domain} ext:txt inurl:error',
    ]
    
    # Exposed documents
    document_dorks = [
        f'site:{domain} ext:pdf',
        f'site:{domain} ext:doc',
        f'site:{domain} ext:docx',
        f'site:{domain} ext:xls',
        f'site:{domain} ext:xlsx',
        f'site:{domain} ext:ppt',
        f'site:{domain} ext:txt',
        f'site:{domain} filetype:pdf "confidential"',
        f'site:{domain} filetype:doc "internal"',
    ]
    
    # Source code and version control
    source_code_dorks = [
        f'site:{domain} ext:php',
        f'site:{domain} ext:asp',
        f'site:{domain} ext:aspx',
        f'site:{domain} ext:jsp',
        f'site:{domain} ext:java',
        f'site:{domain} ext:py',
        f'site:{domain} inurl:.git',
        f'site:{domain} inurl:.svn',
        f'site:{domain} intitle:"index of" .git',
        f'site:{domain} filetype:php "mysql_connect"',
    ]
    
    # API endpoints and keys
    api_dorks = [
        f'site:{domain} inurl:api',
        f'site:{domain} inurl:/v1/',
        f'site:{domain} inurl:/api/v1',
        f'site:{domain} filetype:json',
        f'site:{domain} "api_key"',
        f'site:{domain} "apikey"',
        f'site:{domain} "api key"',
        f'site:{domain} intext:"api token"',
    ]
    
    # Error pages and debug info
    error_dorks = [
        f'site:{domain} intext:"sql syntax"',
        f'site:{domain} intext:"mysql"',
        f'site:{domain} intext:"syntax error"',
        f'site:{domain} intext:"warning: mysql"',
        f'site:{domain} inurl:error',
        f'site:{domain} intitle:"error"',
        f'site:{domain} "Fatal error"',
        f'site:{domain} "stack trace"',
    ]
    
    # Sensitive directories
    directory_dorks = [
        f'site:{domain} intitle:"index of /"',
        f'site:{domain} intitle:"index of" uploads',
        f'site:{domain} intitle:"index of" files',
        f'site:{domain} intitle:"index of" downloads',
        f'site:{domain} intitle:"index of" images',
        f'site:{domain} intitle:"index of" temp',
        f'site:{domain} intitle:"index of" backup',
    ]
    
    # Subdomains
    subdomain_dorks = [
        f'site:*.{domain}',
        f'site:*.{domain} -www',
    ]
    
    # Email addresses
    email_dorks = [
        f'site:{domain} intext:"@{domain}"',
        f'site:{domain} "email" "@{domain}"',
    ]
    
    # Combine all dorks
    dorks.extend(admin_dorks)
    dorks.extend(config_dorks)
    dorks.extend(database_dorks)
    dorks.extend(log_dorks)
    dorks.extend(document_dorks)
    dorks.extend(source_code_dorks)
    dorks.extend(api_dorks)
    dorks.extend(error_dorks)
    dorks.extend(directory_dorks)
    dorks.extend(subdomain_dorks)
    dorks.extend(email_dorks)
    
    return dorks


def get_dork_categories():
    """
    Returns categories of dorks for organized scanning
    """
    return {
        "admin_panels": "Admin Panels & Login Pages",
        "config_files": "Configuration Files",
        "databases": "Database Files & Backups",
        "logs": "Log Files",
        "documents": "Exposed Documents",
        "source_code": "Source Code & Version Control",
        "api": "API Endpoints & Keys",
        "errors": "Error Pages & Debug Info",
        "directories": "Sensitive Directories",
        "subdomains": "Subdomain Discovery",
        "emails": "Email Addresses"
    }
