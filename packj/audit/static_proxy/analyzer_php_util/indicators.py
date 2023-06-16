#!/usr/bin/python
# -*- coding: utf-8 -*-

# /!\ Detection Format (.*)function($vuln)(.*) matched by payload[0]+regex_indicators
regex_indicators = '\\((.*?)(\\$_GET\\[.*?\\]|\\$_FILES\\[.*?\\]|\\$_POST\\[.*?\\]|\\$_REQUEST\\[.*?\\]|\\$_COOKIES\\[.*?\\]|\\$_SESSION\\[.*?\\]|\\$(?!this|e-)[a-zA-Z0-9_]*)(.*?)\\)'

# Function_Name:String, Vulnerability_Name:String, Protection_Function:Array
payloads = [

    # Remote Command Execution
    ["eval", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["popen", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["popen_ex", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["system", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["passthru", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["exec", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["shell_exec", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["pcntl_exec", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["assert", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["proc_open", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["expect_popen", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["create_function", "SINK_PROCESS_OPERATION", ["escapeshellarg", "escapeshellcmd"]],
    ["call_user_func", "SINK_PROCESS_OPERATION", []],
    ["call_user_func_array", "SINK_PROCESS_OPERATION", []],
    ["preg_replace", "SINK_PROCESS_OPERATION", ["preg_quote"]],
    ["ereg_replace", "SINK_PROCESS_OPERATION", ["preg_quote"]],
    ["eregi_replace", "SINK_PROCESS_OPERATION", ["preg_quote"]],
    ["mb_ereg_replace", "SINK_PROCESS_OPERATION", ["preg_quote"]],
    ["mb_eregi_replace", "SINK_PROCESS_OPERATION", ["preg_quote"]],

    # File Inclusion / Path Traversal
    ["virtual", "SOURCE_FILE", []],
    ["include", "SOURCE_FILE", []],
    ["require", "SOURCE_FILE", []],
    ["include_once", "SOURCE_FILE", []],
    ["require_once", "SOURCE_FILE", []],

    ["readfile", "SOURCE_FILE", []],
    ["file_get_contents", "SOURCE_FILE", []],
    ["file_put_contents", "SINK_FILE", []],
    ["show_source", "SOURCE_FILE", []],
    ["fopen", "SOURCE_FILE", []],
    ["file", "SOURCE_FILE", []],
    ["fpassthru", "SOURCE_FILE", []],
    ["gzopen", "SOURCE_FILE", []],
    ["gzfile", "SOURCE_FILE", []],
    ["gzpassthru", "SOURCE_FILE", []],
    ["readgzfile", "SOURCE_FILE", []],
    
    ["DirectoryIterator", "SOURCE_FILE", []],
    ["stream_get_contents", "SOURCE_FILE", []],
    ["copy", "SINK_FILE", []],

    # MySQL(i) SQL Injection
    ["mysql_query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysqli_multi_query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysqli_send_query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysqli_master_query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysql_unbuffered_query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysql_db_query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysqli::real_query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysqli_real_query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysqli::query", "SINK_NETWORK", ["mysql_real_escape_string"]],
    ["mysqli_query", "SINK_NETWORK", ["mysql_real_escape_string"]],

    # PostgreSQL Injection
    ["pg_query", "SINK_NETWORK", ["pg_escape_string", "pg_pconnect", "pg_connect"]],
    ["pg_send_query", "SINK_NETWORK", ["pg_escape_string", "pg_pconnect", "pg_connect"]],

    # SQLite SQL Injection
    ["sqlite_array_query", "SINK_NETWORK", ["sqlite_escape_string"]],
    ["sqlite_exec", "SINK_NETWORK", ["sqlite_escape_string"]],
    ["sqlite_query", "SINK_NETWORK", ["sqlite_escape_string"]],
    ["sqlite_single_query", "SINK_NETWORK", ["sqlite_escape_string"]],
    ["sqlite_unbuffered_query", "SINK_NETWORK", ["sqlite_escape_string"]],

    # PDO SQL Injection
    ["->arrayQuery", "SINK_NETWORK", ["->prepare"]],
    ["->query", "SINK_NETWORK", ["->prepare"]],
    ["->queryExec", "SINK_NETWORK", ["->prepare"]],
    ["->singleQuery", "SINK_NETWORK", ["->prepare"]],
    ["->querySingle", "SINK_NETWORK", ["->prepare"]],
    ["->exec", "SINK_NETWORK", ["->prepare"]],
    ["->execute", "SINK_NETWORK", ["->prepare"]],
    ["->unbufferedQuery", "SINK_NETWORK", ["->prepare"]],
    ["->real_query", "SINK_NETWORK", ["->prepare"]],
    ["->multi_query", "SINK_NETWORK", ["->prepare"]],
    ["->send_query", "SINK_NETWORK", ["->prepare"]],

    # Cubrid SQL Injection
    ["cubrid_unbuffered_query", "SINK_NETWORK", ["cubrid_real_escape_string"]],
    ["cubrid_query", "SINK_NETWORK", ["cubrid_real_escape_string"]],

    # MSSQL SQL Injection : Warning there is not any real_escape_string
    ["mssql_query", "SINK_NETWORK", ["mssql_escape"]],

    # File Upload
    ["move_uploaded_file", "SINK_NETWORK", []],

    # Cross Site Scripting
    ["echo", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["print", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["printf", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["vprintf", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["trigger_error", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["user_error", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["odbc_result_all", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["ifx_htmltbl_result", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["die", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["exit", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],
    ["var_dump", "SINK_PROCESS_OPERATION", ["htmlentities", "htmlspecialchars"]],

    # XPATH and LDAP
    ["xpath", "SOURCE_NETWORK", []],
    ["ldap_search", "SOURCE_NETWORK", ["Zend_Ldap", "ldap_escape"]],

    # Insecure E-Mail
    ["mail", "SOURCE_SETTINGS", []],

    # PHP Objet Injection
    ["unserialize", "SINK_CODE_GENERATION", []],

    # Header Injection
    ["header", "SINK_CODE_GENERATION", []],
    ["HttpMessage::setHeaders", "SINK_CODE_GENERATION", []],
    ["HttpRequest::setHeaders", "SINK_CODE_GENERATION", []],

    # URL Redirection
    ["http_redirect", "SOURCE_NETWORK", []],
    ["HttpMessage::setResponseCode", "SOURCE_NETWORK", []],

    # Server Side Template Injection
    ["->render", "SOURCE_FILE", []],
    ["->assign", "SINK_UNCLASSIFIED", []],

    # Information Leak
    ["phpinfo", "SOURCE_SETTINGS", []],
    ["debug_print_backtrace", "SOURCE_SETTINGS", []],
    ["show_source", "SOURCE_SETTINGS", []],
    ["highlight_file", "SOURCE_SETTINGS", []],

    # Others
    ["unlink", "SINK_FILE", []],
    ["extract", "SINK_UNCLASSIFIED", []],
    ["setcookie", "SINK_UNCLASSIFIED", []],
    ["chmod", "SOURCE_FILE", []],
    ["mkdir", "SINK_FILE", []],
    
]