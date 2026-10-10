RULES = {
    "CWE-89": {
        "name": "SQL Injection",
        "sources": [
            "request.getParameter", "getParameter",
            "getQueryString", "getHeader"
        ],
        "sinks": [
            "executeQuery", "executeUpdate", "execute",
            "prepareStatement"
        ],
        "sanitizers": ["PreparedStatement", "setString", "setInt"],
        "repair": "Use PreparedStatement with parameter binding instead of string concatenation."
    },
    "CWE-78": {
        "name": "Command Injection",
        "sources": ["request.getParameter", "getParameter", "getHeader"],
        "sinks": ["Runtime.getRuntime().exec", "ProcessBuilder"],
        "sanitizers": [],
        "repair": "Avoid shell command construction from user input; use allowlists and safe argument APIs."
    },
    "CWE-22": {
        "name": "Path Traversal",
        "sources": ["request.getParameter", "getParameter"],
        "sinks": ["FileInputStream", "FileOutputStream", "Paths.get", "new File"],
        "sanitizers": ["normalize"],
        "repair": "Canonicalize paths and enforce an allowlisted base directory."
    }
}
