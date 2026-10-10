"""Servlet request value sources shared by propagation and summary invalidation."""
SERVLET_SOURCES = {
    'ServletRequest': frozenset({'getParameter', 'getParameterValues', 'getParameterMap'}),
    'HttpServletRequest': frozenset({'getParameter', 'getParameterValues', 'getParameterMap',
                                   'getHeader', 'getHeaders', 'getQueryString', 'getCookies'}),
}
SOURCE_METHOD_NAMES = frozenset().union(*SERVLET_SOURCES.values())
